//! AWS Lambda for the Tier-2 API (plan sections 3.2 and 4.1).
//!   POST /v1/score     fallback scorer (via CloudFront): signed request -> signed verdict
//!   POST /v1/register  reached only through the Cloudflare Worker (origin secret header)
//! Env: DEVICES_TABLE, LICENCES_TABLE, RESPONSE_SIGNING_SEED (base64 32 bytes), ORIGIN_SECRET,
//!      CF_ACCOUNT_ID, CF_KV_NAMESPACE, CF_API_TOKEN (KV write only).
// shortcut: secrets come from Lambda env vars (encrypted at rest); move them to SSM in hardening.

use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tier2_scorer::auth::{self, AuthError, Guard, SignedHeaders};
use tier2_scorer::{score, verdict, FEATURE_DIM};

struct App {
    db: aws_sdk_dynamodb::Client,
    devices: String,
    licences: String,
    seed: [u8; 32],
    origin_secret: String,
    kv_url: String,
    cf_token: String,
    http: reqwest::Client,
    guard: Guard,
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

fn reply(status: u16, body: Value) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into())?)
}

fn signed(app: &App, body: Value) -> Result<Response<Body>, Error> {
    let text = body.to_string();
    Ok(Response::builder()
        .header("content-type", "application/json")
        .header("x-tt-resp-sig", auth::sign_reply(&app.seed, &text))
        .body(text.into())?)
}

fn deny(e: AuthError) -> Result<Response<Body>, Error> {
    match e {
        AuthError::Unauthorized => reply(401, json!({ "error": "unauthorized" })),
        AuthError::RateLimited => reply(429, json!({ "error": "rate limited" })),
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

fn attr<'a>(item: &'a HashMap<String, AttributeValue>, name: &str) -> &'a str {
    item.get(name).and_then(|v| v.as_s().ok()).map_or("", |s| s.as_str())
}

/// Exactly 99 finite numbers in "features", or None.
fn parse_features(body: &[u8]) -> Option<[f32; FEATURE_DIM]> {
    let f = serde_json::from_slice::<ScoreRequest>(body).ok()?.features;
    if f.iter().all(|x| x.is_finite()) { f.try_into().ok() } else { None }
}

async fn device(app: &App, id: &str) -> Result<Option<HashMap<String, AttributeValue>>, Error> {
    let out = app.db.get_item().table_name(&app.devices).key("device_id", AttributeValue::S(id.into())).send().await?;
    Ok(out.item)
}

async fn score_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    let h = signed_headers(req);
    if !auth::is_id(h.device) {
        return deny(AuthError::Unauthorized);
    }
    let Some(item) = device(app, h.device).await? else { return deny(AuthError::Unauthorized) };
    if attr(&item, "status") != "active" {
        return reply(403, json!({ "error": "revoked" }));
    }
    let pk = B64.decode(attr(&item, "pk")).unwrap_or_default();
    if let Err(e) = app.guard.verify(&h, "POST", "/v1/score", req.body(), &pk, now()) {
        return deny(e);
    }
    let Some(x) = parse_features(req.body()) else {
        return reply(400, json!({ "error": "body must be {\"features\": [99 finite numbers]}" }));
    };
    let request_id = req.lambda_context_ref().map(|c| c.request_id.clone()).unwrap_or_default();
    signed(app, json!({ "verdict": verdict(score(&x)), "request_id": request_id, "nonce": h.nonce }))
}

async fn register_route(app: &App, req: &Request) -> Result<Response<Body>, Error> {
    if !auth::secret_eq(header(req, "x-tt-origin-secret"), &app.origin_secret) {
        return reply(404, json!({ "error": "not found" })); // not via Cloudflare: look absent
    }
    let Ok(r) = serde_json::from_slice::<RegisterRequest>(req.body()) else {
        return reply(400, json!({ "error": "body must be {licence_key, public_key, key_kind}" }));
    };
    let pk = B64.decode(&r.public_key).unwrap_or_default();
    let h = signed_headers(req);
    // The signature proves the caller holds the private key for `public_key`.
    if let Err(e) = app.guard.verify(&h, "POST", "/v1/register", req.body(), &pk, now()) {
        return deny(e);
    }

    match device(app, h.device).await? {
        Some(item) if attr(&item, "pk") == r.public_key && attr(&item, "status") == "active" => {} // re-register
        Some(_) => return reply(403, json!({ "error": "revoked" })),
        None => {
            let licence = auth::hex(&Sha256::digest(r.licence_key.as_bytes()));
            let seat = app
                .db
                .update_item()
                .table_name(&app.licences)
                .key("licence_hash", AttributeValue::S(licence.clone()))
                .update_expression("SET used = used + :one")
                .condition_expression("attribute_exists(licence_hash) AND used < seats")
                .expression_attribute_values(":one", AttributeValue::N("1".into()))
                .send()
                .await;
            if let Err(e) = seat {
                if e.as_service_error().is_some_and(|s| s.is_conditional_check_failed_exception()) {
                    return reply(403, json!({ "error": "licence invalid or full" }));
                }
                return Err(e.into());
            }
            // shortcut: two simultaneous first registrations of one device can both take a
            // seat; rare, and fixable from the admin console (step 5).
            let kind = if r.key_kind == "tpm" { "tpm" } else { "software" };
            let put = app
                .db
                .put_item()
                .table_name(&app.devices)
                .item("device_id", AttributeValue::S(h.device.into()))
                .item("pk", AttributeValue::S(r.public_key.clone()))
                .item("kind", AttributeValue::S(kind.into()))
                .item("status", AttributeValue::S("active".into()))
                .item("licence_hash", AttributeValue::S(licence))
                .item("first_ip", AttributeValue::S(header(req, "x-tt-client-ip").into()))
                .item("created_at", AttributeValue::N(now().to_string()))
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
    let kv = json!({ "pk": r.public_key, "status": "active" }).to_string();
    let published = app.http.put(format!("{}/{}", app.kv_url, h.device)).bearer_auth(&app.cf_token).body(kv).send().await;
    if !published.is_ok_and(|r| r.status().is_success()) {
        return reply(502, json!({ "error": "edge publish failed, retry" }));
    }
    signed(app, json!({ "device_id": h.device, "nonce": h.nonce }))
}

async fn handler(app: &App, req: Request) -> Result<Response<Body>, Error> {
    if req.method() != "POST" {
        return reply(404, json!({ "error": "not found" }));
    }
    match req.uri().path() {
        "/v1/score" => score_route(app, &req).await,
        "/v1/register" => register_route(app, &req).await,
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
    let app = App {
        db: aws_sdk_dynamodb::Client::new(&aws_config::load_from_env().await),
        devices: env("DEVICES_TABLE")?,
        licences: env("LICENCES_TABLE")?,
        seed,
        origin_secret: env("ORIGIN_SECRET")?,
        kv_url: format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values",
            env("CF_ACCOUNT_ID")?,
            env("CF_KV_NAMESPACE")?
        ),
        cf_token: env("CF_API_TOKEN")?,
        http: reqwest::Client::new(),
        guard: Guard::default(),
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
}
