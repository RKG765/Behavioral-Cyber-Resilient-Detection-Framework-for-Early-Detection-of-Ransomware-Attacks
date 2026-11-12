//! AWS Lambda for the Tier-2 API and the SOC console's admin API (plan sections 3.2, 4.1, 6).
//!   POST /v1/score      fallback scorer (via CloudFront): signed request -> signed verdict
//!   POST /v1/register   via the Cloudflare Worker only (origin secret)
//!   POST /v1/report     via the Worker only: a report the user chose to send, signed by the device
//!   POST /internal/log  via the Worker only: one request log event
//!   GET|POST /admin/*   via the console's Pages Function only: Access JWT + Cognito ID token
//!                       (incl. /admin/metrics/{aws,cloudflare}, the Cloud pages, plan 6.3)
//! Env: README.md -> Setup.
// shortcut: secrets come from Lambda env vars (encrypted at rest); move them to SSM in hardening.

use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use aws_sdk_cognitoidentityprovider::types::{AttributeType, DeliveryMediumType};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tier2_scorer::admin::{self, AccessClaims, CognitoClaims, Jwks, Role};
use tier2_scorer::auth::{self, AuthError, Guard, SignedHeaders};
use tier2_scorer::cloud::{self, day};
use tier2_scorer::{score, verdict, FEATURE_DIM};

type Item = HashMap<String, AttributeValue>;
const RETAIN_S: i64 = 90 * 86_400; // request logs, IPs, reports and audit entries
const MAX_LOG_BATCH: usize = 100; // Worker sends at most 50; 100 rows fit well inside the 10 s timeout

struct App {
    db: aws_sdk_dynamodb::Client,
    devices: String,
    licences: String,
    events: String,
    index: String,
    seed: [u8; 32],
    origin_secret: String,
    kv_url: String,
    cf_token: String,
    idp: aws_sdk_cognitoidentityprovider::Client, // console admins (Admins page)
    pool_id: String,
    access_list_url: String, // the Access email list; "" until CF_ACCESS_LIST_ID and CF_ZT_TOKEN are set
    zt_token: String,
    access: Jwks,
    cognito: Jwks,
    http: reqwest::Client,
    guard: Guard,
    rejects: Mutex<HashMap<String, i64>>,
    obs: Observability,
}

/// The Cloud pages' sources (plan 6.3). Optional: empty values turn a panel off, never the scorer.
struct Observability {
    cw: aws_sdk_cloudwatch::Client,
    cw_us_east_1: aws_sdk_cloudwatch::Client,
    logs: aws_sdk_cloudwatchlogs::Client,
    function: String,
    tables: Vec<(String, f64, f64)>,
    distribution: String,
    queue: String,
    cf_graphql_token: String,
    cf_account: String,
    cf_zone: String,
    cf_worker: String,
    cache: cloud::Cache,
}

#[derive(Deserialize)]
struct ScoreRequest {
    features: Vec<f32>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    licence_key: String,
    public_key: String,
    key_kind: String,
}

#[derive(Deserialize)]
struct ReportRequest {
    name: String,
    path: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogEvent {
    device: String,
    ip: String,
    country: String,
    asn: String,
    verified: String,
    verdict: String,
    status: u16,
    reason: String,
    path: String,
    ms: f64,
    source: String,
}

// ───────────────────────── small helpers ─────────────────────────

fn resp(status: u16, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into())
        .expect("static response parts are valid")
}

fn reply(status: u16, body: Value) -> Result<Response<Body>, Error> {
    Ok(resp(status, body))
}

fn signed(app: &App, body: Value) -> Result<Response<Body>, Error> {
    let text = body.to_string();
    Ok(Response::builder()
        .header("content-type", "application/json")
        .header("x-tt-resp-sig", auth::sign_reply(&app.seed, &text))
        .body(text.into())?)
}

fn deny(e: AuthError) -> Response<Body> {
    match e {
        AuthError::Unauthorized => resp(401, json!({ "error": "unauthorized" })),
        AuthError::RateLimited => resp(429, json!({ "error": "rate limited" })),
    }
}

fn header<'a>(req: &'a Request, name: &str) -> &'a str {
    req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn signed_headers(req: &Request) -> SignedHeaders<'_> {
    SignedHeaders {
        device: header(req, "x-tt-device"),
        time: header(req, "x-tt-time"),
        nonce: header(req, "x-tt-nonce"),
        sig: header(req, "x-tt-sig"),
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn n(v: impl ToString) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

/// Device data is attacker-controlled: cap every string before storing it.
fn cap(v: &str, max: usize) -> String {
    v.chars().take(max).collect()
}

fn attr<'a>(item: &'a Item, name: &str) -> &'a str {
    item.get(name).and_then(|v| v.as_s().ok()).map_or("", |s| s.as_str())
}

fn num(item: &Item, name: &str) -> f64 {
    item.get(name).and_then(|v| v.as_n().ok()).and_then(|x| x.parse().ok()).unwrap_or(0.0)
}

fn to_json(v: &AttributeValue) -> Value {
    match v {
        AttributeValue::S(x) => json!(x),
        AttributeValue::N(x) => x.parse::<f64>().map_or(json!(x), |f| json!(f)),
        AttributeValue::Bool(b) => json!(b),
        AttributeValue::L(l) => Value::Array(l.iter().map(to_json).collect()),
        AttributeValue::M(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()),
        _ => Value::Null,
    }
}

fn item_json(item: &Item) -> Value {
    Value::Object(item.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
}

/// Exactly 99 finite numbers in "features", or None.
fn parse_features(body: &[u8]) -> Option<[f32; FEATURE_DIM]> {
    let f = serde_json::from_slice::<ScoreRequest>(body).ok()?.features;
    if f.iter().all(|x| x.is_finite()) { f.try_into().ok() } else { None }
}

// ───────────────────────── storage ─────────────────────────

async fn device(app: &App, id: &str) -> Result<Option<Item>, Error> {
    Ok(app.db.get_item().table_name(&app.devices).key("device_id", s(id)).send().await?.item)
}

/// One event under "<prefix>#<day>": e = request log, r = report, a = admin audit.
async fn put_event(app: &App, prefix: &str, mut item: Item) -> Result<(), Error> {
    let t = now();
    item.insert("pk".into(), s(format!("{prefix}#{}", day(t))));
    item.insert("sk".into(), s(format!("{:013}#{:08x}", now_ms(), rand_u32())));
    item.insert("ts".into(), n(t));
    item.insert("expires".into(), n(t + RETAIN_S));
    app.db.put_item().table_name(&app.events).set_item(Some(item)).send().await?;
    Ok(())
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).unwrap_or_default();
    u32::from_le_bytes(b)
}

/// Request log + device <-> IP index + the device's last IP (SOC console, section 6.1).
async fn log_request(app: &App, ev: &LogEvent) -> Result<(), Error> {
    log_batch(app, std::slice::from_ref(ev)).await
}

/// Verified traffic per device + IP, so a batch updates the index once per pair, not per request.
fn pairs(events: &[LogEvent]) -> HashMap<(String, String), (u32, String)> {
    let mut out: HashMap<(String, String), (u32, String)> = HashMap::new();
    for ev in events.iter().filter(|e| auth::is_id(&e.device) && !e.ip.is_empty() && e.status == 200) {
        let e = out.entry((ev.device.clone(), cap(&ev.ip, 45))).or_default();
        e.0 += 1;
        e.1 = cap(&ev.country, 2); // the latest wins
    }
    out
}

async fn log_batch(app: &App, events: &[LogEvent]) -> Result<(), Error> {
    for ev in events {
        put_event(app, "e", event_item(ev)).await?;
    }
    let t = now();
    for ((device, ip), (hits, country)) in pairs(events) {
        for (pk, sk) in [(format!("d#{device}"), format!("ip#{ip}")), (format!("i#{ip}"), format!("d#{device}"))] {
            app.db
                .update_item()
                .table_name(&app.index)
                .key("pk", s(pk))
                .key("sk", s(sk))
                .update_expression("SET last_seen = :t, country = :c, first_seen = if_not_exists(first_seen, :t) ADD hits :n")
                .expression_attribute_values(":t", n(t))
                .expression_attribute_values(":c", s(&country))
                .expression_attribute_values(":n", n(hits))
                .send()
                .await?;
        }
        let _ = app
            .db
            .update_item()
            .table_name(&app.devices)
            .key("device_id", s(&device))
            .update_expression("SET last_seen = :t, last_ip = :ip")
            .condition_expression("attribute_exists(device_id)")
            .expression_attribute_values(":t", n(t))
            .expression_attribute_values(":ip", s(ip))
            .send()
            .await;
    }
    Ok(())
}

fn event_item(ev: &LogEvent) -> Item {
    let mut item: Item = [
        ("device", cap(&ev.device, 32)),
        ("ip", cap(&ev.ip, 45)),
        ("country", cap(&ev.country, 2)),
        ("asn", cap(&ev.asn, 12)),
        ("verified", cap(&ev.verified, 10)),
        ("verdict", cap(&ev.verdict, 8)),
        ("reason", cap(&ev.reason, 40)),
        ("path", cap(&ev.path, 20)),
        ("source", cap(&ev.source, 4)),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| (k.to_string(), s(v)))
    .collect();
    item.insert("status".into(), n(ev.status));
    item.insert("ms".into(), n(ev.ms.clamp(0.0, 60_000.0)));
    item
}

/// Rejected requests are logged at most once per IP per minute, so junk can't flood the log.
fn sample_reject(app: &App, ip: &str) -> bool {
    let t = now();
    let mut seen = app.rejects.lock().unwrap();
    if seen.len() > 10_000 {
        seen.clear();
    }
    if seen.get(ip).is_some_and(|&last| t - last < 60) {
        return false;
    }
    seen.insert(ip.to_string(), t);
    true
}

async fn publish(app: &App, device_id: &str, pk: &str, status: &str, kind: &str) -> bool {
    let kv = json!({ "pk": pk, "status": status, "kind": kind }).to_string();
    let r = app.http.put(format!("{}/{device_id}", app.kv_url)).bearer_auth(&app.cf_token).body(kv).send().await;
    r.is_ok_and(|r| r.status().is_success())
}

async fn scan(app: &App, table: &str, prefix: Option<&str>) -> Result<Vec<Item>, Error> {
    let mut out = Vec::new();
    let mut start = None;
    loop {
        let mut q = app.db.scan().table_name(table).set_exclusive_start_key(start);
        if let Some(p) = prefix {
            q = q.filter_expression("begins_with(pk, :p)").expression_attribute_values(":p", s(p));
        }
        let page = q.send().await?;
        out.extend(page.items.unwrap_or_default());
        start = page.last_evaluated_key;
        // shortcut: scans stop at 5,000 items; add pagination in the console past beta scale.
        if start.is_none() || out.len() >= 5_000 {
            return Ok(out);
        }
    }
}

async fn query(app: &App, table: &str, pk: String, limit: i32) -> Result<Vec<Item>, Error> {
    let out = app
        .db
        .query()
        .table_name(table)
        .key_condition_expression("pk = :pk")
        .expression_attribute_values(":pk", s(pk))
        .scan_index_forward(false)
        .limit(limit)
        .send()
        .await?;
    Ok(out.items.unwrap_or_default())
}

// ───────────────────────── device routes ─────────────────────────

/// Signed request from an active device. Ok((device_id, nonce, kind)) or the error reply.
async fn verified_device(app: &App, req: &Request, path: &str) -> Result<(String, String, String), Response<Body>> {
    let h = signed_headers(req);
    if !auth::is_id(h.device) {
        return Err(deny(AuthError::Unauthorized));
    }
    let item = match device(app, h.device).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(deny(AuthError::Unauthorized)),
        Err(_) => return Err(resp(503, json!({ "error": "storage unavailable" }))),
    };
    if attr(&item, "status") != "active" {
        return Err(resp(403, json!({ "error": "revoked" })));
    }
    let pk = B64.decode(attr(&item, "pk")).unwrap_or_default();
    app.guard.verify(&h, "POST", path, req.body(), &pk, now()).map_err(deny)?;
    Ok((h.device.to_string(), h.nonce.to_string(), attr(&item, "kind").to_string()))
}

async fn score_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    let started = std::time::Instant::now();
    let ip = header(req, "cloudfront-viewer-address").rsplit_once(':').map_or("", |(ip, _)| ip).to_string();
    let mut ev = LogEvent {
        device: signed_headers(req).device.to_string(),
        ip,
        country: header(req, "cloudfront-viewer-country").to_string(),
        path: "/v1/score".into(),
        source: "aws".into(),
        ..Default::default()
    };
    let (device_id, nonce, kind) = match verified_device(app, req, "/v1/score").await {
        Ok(v) => v,
        Err(r) => {
            ev.status = r.status().as_u16();
            ev.verified = "failed".into();
            if sample_reject(app, &ev.ip) {
                let _ = log_request(app, &ev).await;
            }
            return Ok(r);
        }
    };
    let Some(x) = parse_features(req.body()) else {
        return reply(400, json!({ "error": "body must be {\"features\": [99 finite numbers]}" }));
    };
    let v = verdict(score(&x));
    let request_id = req.lambda_context_ref().map(|c| c.request_id.clone()).unwrap_or_default();
    ev.device = device_id;
    ev.status = 200;
    ev.verified = kind;
    ev.verdict = v.into();
    ev.ms = started.elapsed().as_secs_f64() * 1000.0;
    if let Err(e) = log_request(app, &ev).await {
        eprintln!("log failed: {e}"); // never fail a verdict because logging failed
    }
    signed(app, json!({ "verdict": v, "request_id": request_id, "nonce": nonce }))
}

async fn register_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    let Ok(r) = serde_json::from_slice::<RegisterRequest>(req.body()) else {
        return reply(400, json!({ "error": "body must be {licence_key, public_key, key_kind}" }));
    };
    let pk = B64.decode(&r.public_key).unwrap_or_default();
    let h = signed_headers(req);
    // The signature proves the caller holds the private key for `public_key`.
    if let Err(e) = app.guard.verify(&h, "POST", "/v1/register", req.body(), &pk, now()) {
        return Ok(deny(e));
    }
    let kind = if r.key_kind == "tpm" { "tpm" } else { "software" };

    match device(app, h.device).await? {
        Some(item) if attr(&item, "pk") == r.public_key && attr(&item, "status") == "active" => {} // re-register
        // Signed (the request signature was checked above): the agent stops protecting on it.
        Some(item) if attr(&item, "pk") == r.public_key => {
            return signed(app, json!({ "licence": "revoked", "device_id": h.device, "nonce": h.nonce }));
        }
        Some(_) => return reply(403, json!({ "error": "revoked" })),
        None => {
            let licence = auth::hex(&Sha256::digest(r.licence_key.as_bytes()));
            let seat = app
                .db
                .update_item()
                .table_name(&app.licences)
                .key("licence_hash", s(licence.clone()))
                .update_expression("SET used = used + :one")
                .condition_expression("attribute_exists(licence_hash) AND used < seats")
                .expression_attribute_values(":one", n(1))
                .send()
                .await;
            if let Err(e) = seat {
                if e.as_service_error().is_some_and(|s| s.is_conditional_check_failed_exception()) {
                    let exists = app.db.get_item().table_name(&app.licences).key("licence_hash", s(licence)).send().await?.item.is_some();
                    let why = if exists { "full" } else { "invalid" }; // invalid includes a deleted licence
                    return signed(app, json!({ "licence": why, "device_id": h.device, "nonce": h.nonce }));
                }
                return Err(e.into());
            }
            // shortcut: two simultaneous first registrations of one device can both take a
            // seat; rare, and visible in the console's Licences view.
            let put = app
                .db
                .put_item()
                .table_name(&app.devices)
                .item("device_id", s(h.device))
                .item("pk", s(r.public_key.clone()))
                .item("kind", s(kind))
                .item("status", s("active"))
                .item("licence_hash", s(licence))
                .item("first_ip", s(cap(header(req, "x-tt-client-ip"), 45)))
                .item("created_at", n(now()))
                .condition_expression("attribute_not_exists(device_id)")
                .send()
                .await;
            if let Err(e) = put {
                if !e.as_service_error().is_some_and(|s| s.is_conditional_check_failed_exception()) {
                    return Err(e.into());
                }
            }
        }
    }
    // Publish (again) to the edge; a retry after a failed publish takes the re-register path.
    if !publish(app, h.device, &r.public_key, "active", kind).await {
        return reply(502, json!({ "error": "edge publish failed, retry" }));
    }
    signed(app, json!({ "device_id": h.device, "nonce": h.nonce }))
}

async fn report_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    let (device_id, nonce, _) = match verified_device(app, req, "/v1/report").await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let Ok(r) = serde_json::from_slice::<ReportRequest>(req.body()) else {
        return reply(400, json!({ "error": "body must be {name, path, sha256, reason, reasons}" }));
    };
    let reasons = r.reasons.iter().take(20).map(|x| s(cap(x, 200))).collect();
    let item: Item = HashMap::from([
        ("device".into(), s(device_id)),
        ("name".into(), s(cap(&r.name, 260))),
        ("path".into(), s(cap(&r.path, 1024))),
        ("sha256".into(), s(cap(&r.sha256, 64))),
        ("reason".into(), s(cap(&r.reason, 200))),
        ("reasons".into(), AttributeValue::L(reasons)),
        ("ip".into(), s(cap(header(req, "x-tt-client-ip"), 45))),
    ]);
    put_event(app, "r", item).await?;
    signed(app, json!({ "ok": true, "nonce": nonce }))
}

async fn internal_log_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    // The Worker batches events (worker/src/log.js) so this runs a few times a minute, not per request.
    let Ok(events) = serde_json::from_slice::<Vec<LogEvent>>(req.body()) else {
        return reply(400, json!({ "error": "body must be an array of log events" }));
    };
    if events.len() > MAX_LOG_BATCH {
        return reply(400, json!({ "error": "too many events" }));
    }
    log_batch(app, &events).await?;
    reply(200, json!({ "ok": true, "logged": events.len() }))
}

// ───────────────────────── admin routes ─────────────────────────

/// Both login layers, the same person, the needed role and, for actions, a recent login.
async fn admin_user(app: &App, req: &Request, need: Role, step_up: bool) -> Result<String, Response<Body>> {
    let access: AccessClaims = app
        .access
        .verify(&app.http, header(req, "cf-access-jwt-assertion"))
        .await
        .map_err(|_| resp(401, json!({ "error": "access" })))?;
    let id: CognitoClaims = app
        .cognito
        .verify(&app.http, header(req, "x-tt-admin-token"))
        .await
        .map_err(|_| resp(401, json!({ "error": "login" })))?;
    admin::authorize(&access.email, &id, need, step_up, now())
        .map_err(|e| resp(if e == "forbidden" { 403 } else { 401 }, json!({ "error": e })))?;
    Ok(access.email)
}

async fn audit(app: &App, admin_email: &str, action: &str, target: &str) -> Result<(), Error> {
    let item: Item = HashMap::from([
        ("admin".into(), s(admin_email)),
        ("action".into(), s(action)),
        ("target".into(), s(cap(target, 64))),
    ]);
    put_event(app, "a", item).await
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { 0.0 } else { sorted[((sorted.len() - 1) as f64 * p).round() as usize] }
}

async fn overview(app: &App) -> Result<Response<Body>, Error> {
    let t = now();
    let devices = scan(app, &app.devices, None).await?;
    let today = query(app, &app.events, format!("e#{}", day(t)), 1000).await?;
    let hour: Vec<&Item> = today.iter().filter(|e| num(e, "ts") as i64 > t - 3600).collect();
    let mut ms: Vec<f64> = hour.iter().filter(|e| num(e, "status") == 200.0).map(|e| num(e, "ms")).collect();
    ms.sort_by(f64::total_cmp);
    reply(200, json!({
        "devices": devices.len(),
        "online_24h": devices.iter().filter(|d| num(d, "last_seen") as i64 > t - 86_400).count(),
        "revoked": devices.iter().filter(|d| attr(d, "status") == "revoked").count(),
        "lower_trust": devices.iter().filter(|d| attr(d, "kind") == "software").count(),
        "requests_1h": hour.len(),
        "rejected_1h": hour.iter().filter(|e| num(e, "status") != 200.0).count(),
        "kills_1h": hour.iter().filter(|e| attr(e, "verdict") == "KILL").count(),
        "p50_ms": percentile(&ms, 0.5),
        "p99_ms": percentile(&ms, 0.99),
    }))
}

async fn ips(app: &App) -> Result<Response<Body>, Error> {
    let mut by_ip: HashMap<String, (usize, f64, f64, String)> = HashMap::new();
    for row in scan(app, &app.index, Some("i#")).await? {
        let e = by_ip.entry(attr(&row, "pk")[2..].to_string()).or_default();
        e.0 += 1;
        e.1 += num(&row, "hits");
        e.2 = e.2.max(num(&row, "last_seen"));
        e.3 = attr(&row, "country").to_string();
    }
    let mut out: Vec<Value> = by_ip
        .into_iter()
        .map(|(ip, (devices, hits, last_seen, country))| json!({ "ip": ip, "devices": devices, "hits": hits, "last_seen": last_seen, "country": country }))
        .collect();
    out.sort_by(|a, b| b["devices"].as_u64().cmp(&a["devices"].as_u64()));
    reply(200, Value::Array(out))
}

async fn set_status(app: &App, admin_email: &str, id: &str, action: &str) -> Result<Response<Body>, Error> {
    let Some(item) = device(app, id).await? else { return reply(404, json!({ "error": "no such device" })) };
    let status = if action == "revoke" { "revoked" } else { "active" };
    app.db
        .update_item()
        .table_name(&app.devices)
        .key("device_id", s(id))
        .update_expression("SET #s = :s")
        .expression_attribute_names("#s", "status")
        .expression_attribute_values(":s", s(status))
        .send()
        .await?;
    let edge = publish(app, id, attr(&item, "pk"), status, attr(&item, "kind")).await;
    audit(app, admin_email, action, id).await?;
    reply(if edge { 200 } else { 502 }, json!({ "device": id, "status": status, "edge_updated": edge }))
}

/// "HL-" + four groups of five base32 characters: 100 random bits from the OS.
fn new_licence_key() -> Result<String, getrandom::Error> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // no I, L, O, U: easy to read out
    let mut b = [0u8; 20];
    getrandom::getrandom(&mut b)?;
    let chars: Vec<String> = b.iter().map(|x| (ALPHABET[(x & 31) as usize] as char).to_string()).collect();
    Ok(format!("HL-{}", chars.chunks(5).map(|g| g.concat()).collect::<Vec<_>>().join("-")))
}

/// Admin action: a new licence for `seats` PCs. Only its SHA-256 is stored; the key is returned once.
async fn create_licence(app: &App, admin_email: &str, seats: &str) -> Result<Response<Body>, Error> {
    let Some(seats) = seats.parse::<u32>().ok().filter(|n| (1..=100).contains(n)) else {
        return reply(400, json!({ "error": "seats must be 1 to 100" }));
    };
    let key = new_licence_key()?;
    let hash = auth::hex(&Sha256::digest(key.as_bytes())); // the same hash register_route checks
    app.db
        .put_item()
        .table_name(&app.licences)
        .item("licence_hash", s(&hash))
        .item("seats", n(seats))
        .item("used", n(0))
        .item("created_at", n(now()))
        .item("created_by", s(admin_email))
        .condition_expression("attribute_not_exists(licence_hash)")
        .send()
        .await?;
    audit(app, admin_email, "licence", &hash[..16]).await?;
    reply(200, json!({ "key": key, "licence_hash": hash, "seats": seats }))
}

fn is_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Admin action: change how many PCs a licence allows (never below the seats already used).
async fn set_seats(app: &App, admin_email: &str, hash: &str, seats: &str) -> Result<Response<Body>, Error> {
    let Some(seats) = seats.parse::<u32>().ok().filter(|n| (1..=100).contains(n)) else {
        return reply(400, json!({ "error": "seats must be 1 to 100" }));
    };
    let r = app
        .db
        .update_item()
        .table_name(&app.licences)
        .key("licence_hash", s(hash))
        .update_expression("SET seats = :s")
        .condition_expression("attribute_exists(licence_hash) AND used <= :s")
        .expression_attribute_values(":s", n(seats))
        .send()
        .await;
    if let Err(e) = r {
        if e.as_service_error().is_some_and(|s| s.is_conditional_check_failed_exception()) {
            return reply(409, json!({ "error": "no such licence, or more PCs already use it than that" }));
        }
        return Err(e.into());
    }
    audit(app, admin_email, &format!("licence.seats.{seats}"), &hash[..16]).await?;
    reply(200, json!({ "licence_hash": hash, "seats": seats }))
}

/// Admin action: delete a licence. Every PC registered with it is revoked at the edge first, so
/// Tier 2 refuses them, and the key can't register new PCs.
async fn delete_licence(app: &App, admin_email: &str, hash: &str) -> Result<Response<Body>, Error> {
    let mut revoked = 0;
    for d in scan(app, &app.devices, None).await? {
        if attr(&d, "licence_hash") == hash && attr(&d, "status") == "active" {
            if set_status(app, admin_email, attr(&d, "device_id"), "revoke").await?.status() != 200 {
                // Keep the licence so the delete can be retried; the PCs already revoked stay revoked.
                return reply(502, json!({ "error": "a device could not be revoked at the edge; try again", "edge_updated": false }));
            }
            revoked += 1;
        }
    }
    app.db.delete_item().table_name(&app.licences).key("licence_hash", s(hash)).send().await?;
    audit(app, admin_email, "licence.delete", &hash[..16]).await?;
    reply(200, json!({ "licence_hash": hash, "devices_revoked": revoked }))
}

/// Blocked IPs are a JSON array in KV under "blocked_ips"; the Worker refuses them (worker/src/auth.js).
/// A Cloudflare IP List would need a zone firewall, which workers.dev doesn't have.
async fn block_ip(app: &App, admin_email: &str, ip: &str, action: &str) -> Result<Response<Body>, Error> {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return reply(400, json!({ "error": "not an IP address" }));
    }
    let url = format!("{}/blocked_ips", app.kv_url);
    let r = app.http.get(&url).bearer_auth(&app.cf_token).send().await?;
    let mut list: Vec<String> = match r.status().as_u16() {
        200 => match r.json().await {
            Ok(v) => v,
            Err(_) => return reply(502, json!({ "error": "the edge block list is unreadable; not overwritten", "edge_updated": false })),
        },
        404 => Vec::new(),
        code => return reply(502, json!({ "error": format!("edge block list unavailable ({code})"), "edge_updated": false })),
    };
    list.retain(|x| x != ip);
    if action == "block" {
        list.push(ip.to_string());
    }
    let put = app.http.put(&url).bearer_auth(&app.cf_token).json(&list).send().await;
    let ok = put.is_ok_and(|r| r.status().is_success());
    audit(app, admin_email, action, ip).await?;
    // shortcut: the AWS fallback path doesn't read this list; it uses the `blocked_ips` Terraform variable.
    reply(if ok { 200 } else { 502 }, json!({ "ip": ip, "action": action, "edge_updated": ok }))
}

const ROLES: [&str; 3] = ["admin", "analyst", "viewer"]; // highest first

/// Console admins: the members of the Cognito role groups, each listed once at their highest role.
async fn admins(app: &App) -> Result<Response<Body>, Error> {
    let mut out: Vec<Value> = Vec::new();
    for role in ROLES {
        // shortcut: first page only (60 users per group), plenty for a small admin team.
        let page = app.idp.list_users_in_group().user_pool_id(&app.pool_id).group_name(role).send().await?;
        for u in page.users() {
            let email = u.attributes().iter().find(|a| a.name() == "email").and_then(|a| a.value()).unwrap_or_default();
            if !out.iter().any(|o| o["email"] == email) {
                out.push(json!({ "email": email, "role": role, "status": u.user_status().map(|s| s.as_str()).unwrap_or(""), "enabled": u.enabled() }));
            }
        }
    }
    reply(200, Value::Array(out))
}

fn valid_email(e: &str) -> bool {
    let Some((user, host)) = e.split_once('@') else { return false };
    e.len() <= 254
        && !user.is_empty()
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains('@')
        && !e.chars().any(|c| c.is_whitespace() || c.is_control() || c == ',' || c == '"')
}

/// Admin action: a Cognito login (AWS emails a temporary password) in a role group, plus the
/// Access email list when a Zero Trust token is configured.
async fn add_admin(app: &App, admin_email: &str, email: &str, role: &str) -> Result<Response<Body>, Error> {
    let email = email.trim().to_lowercase();
    if !valid_email(&email) {
        return reply(400, json!({ "error": "not an email address" }));
    }
    if !ROLES.contains(&role) {
        return reply(400, json!({ "error": "role must be admin, analyst or viewer" }));
    }
    let attr = |name: &str, value: &str| AttributeType::builder().name(name).value(value).build();
    let created = app
        .idp
        .admin_create_user()
        .user_pool_id(&app.pool_id)
        .username(&email)
        .user_attributes(attr("email", &email)?)
        .user_attributes(attr("email_verified", "true")?)
        .desired_delivery_mediums(DeliveryMediumType::Email)
        .send()
        .await;
    let invited = match created {
        Ok(_) => true,
        Err(e) if e.as_service_error().is_some_and(|s| s.is_username_exists_exception()) => false, // already has a login
        Err(e) => return Err(e.into()),
    };
    app.idp.admin_add_user_to_group().user_pool_id(&app.pool_id).username(&email).group_name(role).send().await?;
    let access = !app.access_list_url.is_empty() && !app.zt_token.is_empty() && {
        let r = app.http.patch(&app.access_list_url).bearer_auth(&app.zt_token).json(&json!({ "append": [{ "value": email }] })).send().await;
        r.is_ok_and(|r| r.status().is_success())
    };
    audit(app, admin_email, &format!("admin.{role}"), &email).await?;
    reply(200, json!({ "email": email, "role": role, "invited": invited, "access_updated": access }))
}

/// Admin action: move an admin to one role (out of the others). Not your own: no locking yourself out.
async fn set_role(app: &App, admin_email: &str, email: &str, role: &str) -> Result<Response<Body>, Error> {
    let email = email.trim().to_lowercase();
    if !ROLES.contains(&role) {
        return reply(400, json!({ "error": "role must be admin, analyst or viewer" }));
    }
    if email == admin_email.to_lowercase() {
        return reply(400, json!({ "error": "you can't change your own role; ask another admin" }));
    }
    app.idp.admin_add_user_to_group().user_pool_id(&app.pool_id).username(&email).group_name(role).send().await?;
    for other in ROLES.iter().filter(|r| **r != role) {
        app.idp.admin_remove_user_from_group().user_pool_id(&app.pool_id).username(&email).group_name(*other).send().await?;
    }
    audit(app, admin_email, &format!("admin.role.{role}"), &email).await?;
    reply(200, json!({ "email": email, "role": role }))
}

/// Admin action: delete an admin's login and take them off the Access list (when that's configured).
async fn remove_admin(app: &App, admin_email: &str, email: &str) -> Result<Response<Body>, Error> {
    let email = email.trim().to_lowercase();
    if email == admin_email.to_lowercase() {
        return reply(400, json!({ "error": "you can't remove yourself; ask another admin" }));
    }
    let r = app.idp.admin_delete_user().user_pool_id(&app.pool_id).username(&email).send().await;
    if let Err(e) = r {
        if !e.as_service_error().is_some_and(|s| s.is_user_not_found_exception()) {
            return Err(e.into());
        }
    }
    let access = !app.access_list_url.is_empty() && !app.zt_token.is_empty() && {
        let r = app.http.patch(&app.access_list_url).bearer_auth(&app.zt_token).json(&json!({ "remove": [email] })).send().await;
        r.is_ok_and(|r| r.status().is_success())
    };
    audit(app, admin_email, "admin.remove", &email).await?;
    reply(200, json!({ "email": email, "removed": true, "access_updated": access }))
}

/// The Cloud pages: one cached fetch per source and range (plan 6.3).
async fn metrics(app: &App, which: &str, range: Option<&str>, q: Option<&str>) -> Result<Response<Body>, Error> {
    let Some((label, secs, step)) = cloud::range(range) else {
        return reply(400, json!({ "error": "range must be 1h, 6h or 24h" }));
    };
    let o = &app.obs;
    let t = now();
    let cached = |key: String, fetched: Result<Value, String>| fetched.inspect(|v| o.cache.put(&key, t, v.clone()));
    let key = format!("{which}:{label}");
    let mut body = match o.cache.get(&key, t) {
        Some(v) => Ok(v),
        None if which == "aws" => {
            let a = cloud::Aws { cw: &o.cw, cw_us_east_1: &o.cw_us_east_1, function: &o.function, tables: &o.tables, distribution: &o.distribution, queue: &o.queue };
            cached(key, cloud::aws(&a, label, secs, step, t).await)
        }
        None if o.cf_graphql_token.is_empty() || o.cf_zone.is_empty() => {
            return reply(503, json!({ "error": "Cloudflare analytics is not configured (CF_ANALYTICS_TOKEN, CF_ZONE_ID)" }));
        }
        None => cached(key, cloudflare(app, label, secs, step, t).await),
    };
    if let (Ok(Value::Object(m)), Some(q)) = (&mut body, q.filter(|_| which == "aws")) {
        let q = cap(q, 200);
        let key = format!("logs:{label}:{q}");
        let group = format!("/aws/lambda/{}", o.function);
        let found = match o.cache.get(&key, t) {
            Some(v) => Ok(v),
            None => cached(key, cloud::logs(&o.logs, &group, &q, t - secs, t).await),
        };
        m.insert("logs".into(), found.unwrap_or_else(|e| json!({ "error": e })));
    }
    match body {
        Ok(v) => reply(200, v),
        Err(e) => {
            eprintln!("metrics: {e}");
            reply(502, json!({ "error": e }))
        }
    }
}

async fn cloudflare(app: &App, label: &str, secs: i64, step: i64, t: i64) -> Result<Value, String> {
    let o = &app.obs;
    let (t0, n) = cloud::grid(t, secs, step);
    let body = json!({ "query": cloud::cf_query(step), "variables": cloud::cf_vars(&o.cf_zone, &o.cf_account, &o.cf_worker, t0, t) });
    let r = app
        .http
        .post("https://api.cloudflare.com/client/v4/graphql")
        .bearer_auth(&o.cf_graphql_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Cloudflare analytics: {e}"))?;
    let resp: Value = r.json().await.map_err(|e| format!("Cloudflare analytics: {e}"))?;
    cloud::cf_panels(&resp, label, t0, step, n, t)
}

async fn admin_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    let path = req.uri().path().trim_end_matches('/').to_string();
    let parts: Vec<&str> = path.split('/').skip(2).collect(); // after "/admin"
    let post = req.method() == "POST";
    let need = match (post, parts.first().copied()) {
        (true, _) => Role::Admin,
        (false, Some("reports")) => Role::Analyst,
        (false, Some("admins")) => Role::Admin,
        _ => Role::Viewer,
    };
    let user = match admin_user(app, req, need, post).await {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let params = req.query_string_parameters();
    let t = now();
    let day_param = params.first("day").filter(|d| d.len() == 10 && d.bytes().all(|c| c.is_ascii_digit() || c == b'-'));
    let on_day = |prefix: &str| format!("{prefix}#{}", day_param.map_or_else(|| day(t), str::to_string));
    let list = |items: Vec<Item>| reply(200, Value::Array(items.iter().map(item_json).collect()));

    match (post, parts.as_slice()) {
        (false, ["overview"]) => overview(app).await,
        (false, ["devices"]) => list(scan(app, &app.devices, None).await?),
        (false, ["devices", id]) => {
            let Some(d) = device(app, id).await? else { return reply(404, json!({ "error": "no such device" })) };
            let ips = query(app, &app.index, format!("d#{id}"), 500).await?;
            reply(200, json!({ "device": item_json(&d), "ips": ips.iter().map(item_json).collect::<Vec<_>>() }))
        }
        (false, ["ips"]) => ips(app).await,
        (false, ["events"]) => list(query(app, &app.events, on_day("e"), 500).await?),
        (false, ["reports"]) => list(query(app, &app.events, on_day("r"), 500).await?),
        (false, ["audit"]) => list(query(app, &app.events, on_day("a"), 500).await?),
        (false, ["licences"]) => list(scan(app, &app.licences, None).await?),
        (true, ["licences", "new"]) => create_licence(app, &user, params.first("seats").unwrap_or("1")).await,
        (true, ["licences", h, "seats"]) if is_hash(h) => set_seats(app, &user, h, params.first("seats").unwrap_or("")).await,
        (true, ["licences", h, "delete"]) if is_hash(h) => delete_licence(app, &user, h).await,
        (false, ["admins"]) => admins(app).await,
        (true, ["admins", "new"]) => {
            add_admin(app, &user, params.first("email").unwrap_or(""), params.first("role").unwrap_or("viewer")).await
        }
        (true, ["admins", "role"]) => {
            set_role(app, &user, params.first("email").unwrap_or(""), params.first("role").unwrap_or("")).await
        }
        (true, ["admins", "remove"]) => remove_admin(app, &user, params.first("email").unwrap_or("")).await,
        (false, ["metrics", which @ ("aws" | "cloudflare")]) => metrics(app, which, params.first("range"), params.first("q")).await,
        (true, ["devices", id, action @ ("revoke" | "restore")]) => set_status(app, &user, id, action).await,
        (true, ["ips", ip, action @ ("block" | "unblock")]) => block_ip(app, &user, ip, action).await,
        _ => reply(404, json!({ "error": "not found" })),
    }
}

async fn handler(app: &App, req: Request) -> Result<Response<Body>, Error> {
    let path = req.uri().path().to_string();
    let post = req.method() == "POST";
    if post && path == "/v1/score" {
        return score_route(app, &req).await; // the only route that doesn't come through Cloudflare
    }
    if !auth::secret_eq(header(&req, "x-tt-origin-secret"), &app.origin_secret) {
        return reply(404, json!({ "error": "not found" })); // not via Cloudflare: look absent
    }
    match (post, path.as_str()) {
        (true, "/v1/register") => register_route(app, &req).await,
        (true, "/v1/report") => report_route(app, &req).await,
        (true, "/internal/log") => internal_log_route(app, &req).await,
        _ if path.starts_with("/admin/") => admin_route(app, &req).await,
        _ => reply(404, json!({ "error": "not found" })),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let env = |k: &str| std::env::var(k).map_err(|_| format!("missing env var {k}"));
    let seed: [u8; 32] = B64
        .decode(env("RESPONSE_SIGNING_SEED")?)?
        .try_into()
        .map_err(|_| "RESPONSE_SIGNING_SEED must be 32 bytes")?;
    let cf = |path: &str| -> Result<String, String> {
        Ok(format!("https://api.cloudflare.com/client/v4/accounts/{}/{path}", env("CF_ACCOUNT_ID")?))
    };
    let opt = |k: &str| std::env::var(k).unwrap_or_default();
    let aws = aws_config::load_from_env().await;
    let us_east_1 = aws_sdk_cloudwatch::config::Builder::from(&aws).region(aws_config::Region::new("us-east-1")).build();
    // {"<table>": [RCU, WCU]} from Terraform: the tables to chart and their provisioned capacity.
    let capacity: HashMap<String, (f64, f64)> = serde_json::from_str(&opt("DDB_CAPACITY")).unwrap_or_default();
    let mut tables: Vec<(String, f64, f64)> = capacity.into_iter().map(|(k, (r, w))| (k, r, w)).collect();
    tables.sort_by(|a, b| a.0.cmp(&b.0));
    let obs = Observability {
        cw: aws_sdk_cloudwatch::Client::new(&aws),
        cw_us_east_1: aws_sdk_cloudwatch::Client::from_conf(us_east_1),
        logs: aws_sdk_cloudwatchlogs::Client::new(&aws),
        function: std::env::var("AWS_LAMBDA_FUNCTION_NAME").unwrap_or_else(|_| "haltline-api".into()),
        tables,
        distribution: opt("CLOUDFRONT_DISTRIBUTION_ID"),
        queue: opt("SQS_QUEUE"),
        cf_graphql_token: opt("CF_ANALYTICS_TOKEN"),
        cf_account: opt("CF_ACCOUNT_ID"),
        cf_zone: opt("CF_ZONE_ID"),
        cf_worker: opt("CF_WORKER_SCRIPT"),
        cache: cloud::Cache::default(),
    };
    let access_team = env("ACCESS_TEAM_DOMAIN")?; // e.g. myteam.cloudflareaccess.com
    let cognito_issuer = env("COGNITO_ISSUER")?; // https://cognito-idp.<region>.amazonaws.com/<pool id>
    let pool_id = cognito_issuer.rsplit('/').next().unwrap_or_default().to_string();
    let app = App {
        db: aws_sdk_dynamodb::Client::new(&aws),
        devices: env("DEVICES_TABLE")?,
        licences: env("LICENCES_TABLE")?,
        events: env("EVENTS_TABLE")?,
        index: env("INDEX_TABLE")?,
        seed,
        origin_secret: env("ORIGIN_SECRET")?,
        kv_url: cf(&format!("storage/kv/namespaces/{}/values", env("CF_KV_NAMESPACE")?))?,
        cf_token: env("CF_API_TOKEN")?,
        idp: aws_sdk_cognitoidentityprovider::Client::new(&aws),
        pool_id,
        access_list_url: if opt("CF_ACCESS_LIST_ID").is_empty() { String::new() } else { cf(&format!("gateway/lists/{}", opt("CF_ACCESS_LIST_ID")))? },
        zt_token: opt("CF_ZT_TOKEN"),
        access: Jwks::new(
            format!("https://{access_team}/cdn-cgi/access/certs"),
            format!("https://{access_team}"),
            env("ACCESS_AUD")?,
        ),
        cognito: Jwks::new(format!("{cognito_issuer}/.well-known/jwks.json"), cognito_issuer, env("COGNITO_CLIENT_ID")?),
        http: reqwest::Client::new(),
        guard: Guard::default(),
        rejects: Mutex::new(HashMap::new()),
        obs,
    };
    let app: &'static App = Box::leak(Box::new(app)); // lives as long as the Lambda container
    run(service_fn(move |req| handler(app, req))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_must_be_99_finite_numbers() {
        let body = |n: usize, v: &str| format!("{{\"features\":[{}]}}", vec![v; n].join(","));
        assert!(parse_features(body(99, "0.5").as_bytes()).is_some());
        assert!(parse_features(body(98, "0.5").as_bytes()).is_none());
        assert!(parse_features(body(99, "1e999").as_bytes()).is_none());
        assert!(parse_features(b"not json").is_none());
    }

    #[test]
    fn utc_days() {
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(951_782_400), "2000-02-29");
        assert_eq!(day(1_700_000_000), "2023-11-14");
        assert_eq!(day(1_798_675_200), "2026-12-31");
    }

    #[test]
    fn admin_emails_are_checked() {
        for ok in ["a@b.co", "rkg270954@gmail.com", "first.last+tag@sub.example.org"] {
            assert!(valid_email(ok), "{ok}");
        }
        for bad in ["", "no-at", "@b.co", "a@", "a@b", "a@.b.co", "a@b.co.", "a b@c.co", "a@b@c.co", "a,b@c.co", "a@b.co\n"] {
            assert!(!valid_email(bad), "{bad:?}");
        }
    }

    #[test]
    fn licence_keys_are_readable_and_unique() {
        let a = new_licence_key().unwrap();
        let b = new_licence_key().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 3 + 4 * 5 + 3);
        let groups: Vec<&str> = a.trim_start_matches("HL-").split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())));
        assert!(!a[3..].contains(['I', 'L', 'O', 'U']));
    }

    #[test]
    fn batch_updates_the_index_once_per_device_and_ip() {
        let ev = |device: &str, ip: &str, status: u16, country: &str| LogEvent {
            device: device.into(),
            ip: ip.into(),
            status,
            country: country.into(),
            ..Default::default()
        };
        let (a, b) = ("a".repeat(32), "b".repeat(32));
        let p = pairs(&[
            ev(&a, "1.1.1.1", 200, "IN"),
            ev(&a, "1.1.1.1", 200, "US"),
            ev(&a, "2.2.2.2", 200, "IN"),
            ev(&b, "1.1.1.1", 401, "IN"), // rejected: not in the IP picture
            ev("not-an-id", "1.1.1.1", 200, "IN"),
            ev(&b, "", 200, "IN"),
        ]);
        assert_eq!(p.len(), 2);
        assert_eq!(p[&(a.clone(), "1.1.1.1".into())], (2, "US".into()));
        assert_eq!(p[&(a, "2.2.2.2".into())], (1, "IN".into()));
    }

    #[test]
    fn caps_and_percentiles() {
        assert_eq!(cap("héllo", 2), "hé");
        assert_eq!(percentile(&[], 0.5), 0.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.5), 3.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.99), 5.0);
    }
}
