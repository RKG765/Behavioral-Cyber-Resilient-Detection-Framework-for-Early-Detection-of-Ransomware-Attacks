//! Cloud observability for the SOC console (plan section 6.3). The admin Lambda reads CloudWatch
//! and Cloudflare's GraphQL Analytics API for the console, so the browser never holds a cloud
//! credential. Results are cached for 60 s.
//!
//! CloudWatch is read with `GetMetricStatistics` (one call per metric, run concurrently), not
//! `GetMetricData`: the free tier's 1M API requests cover the former, while `GetMetricData` is
//! billed from the first metric.

use aws_sdk_cloudwatch::primitives::DateTime;
use aws_sdk_cloudwatch::types::{Dimension, Statistic};
use futures_util::future::{try_join, try_join_all};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub const CACHE_S: i64 = 60;

/// `?range=` -> (label, seconds, bucket seconds). Cloudflare's Free plan keeps adaptive analytics
/// for a short window, so ranges stop at 24 h.
pub fn range(r: Option<&str>) -> Option<(&'static str, i64, i64)> {
    match r.unwrap_or("6h") {
        "1h" => Some(("1h", 3_600, 60)),
        "6h" => Some(("6h", 21_600, 60)),
        "24h" => Some(("24h", 86_400, 300)),
        _ => None,
    }
}

/// Bucket grid for a range ending now: (first bucket start, bucket count). The last bucket is the
/// current, partial one.
pub fn grid(now: i64, secs: i64, step: i64) -> (i64, usize) {
    ((now - secs).div_euclid(step) * step, (secs / step + 1) as usize)
}

/// Per-container cache, shared by every admin. Expired entries are dropped on each write.
// shortcut: two admins missing at the same moment both fetch; fine at console scale.
#[derive(Default)]
pub struct Cache(Mutex<HashMap<String, (i64, Value)>>);

impl Cache {
    pub fn get(&self, key: &str, now: i64) -> Option<Value> {
        let m = self.0.lock().unwrap();
        m.get(key).filter(|(at, _)| now - at < CACHE_S).map(|(_, v)| v.clone())
    }

    pub fn put(&self, key: &str, now: i64, v: Value) {
        let mut m = self.0.lock().unwrap();
        m.retain(|_, (at, _)| now - *at < CACHE_S);
        m.insert(key.to_string(), (now, v));
    }
}

/// Points on the bucket grid; a missing bucket is `missing` (0 for counts, None otherwise).
pub fn buckets(t0: i64, step: i64, n: usize, points: &[(i64, f64)], missing: Option<f64>) -> Vec<Option<f64>> {
    let mut out = vec![missing; n];
    for &(t, v) in points {
        let i = (t - t0).div_euclid(step);
        if (0..n as i64).contains(&i) {
            out[i as usize] = Some(v);
        }
    }
    out
}

/// Spikes: points with a robust z-score (median / MAD) above 3.5. Only upward, because a flood
/// or a scan is what the SOC watches for; the MAD floor of 1 stops a flat series flagging noise.
pub fn anomalies(v: &[Option<f64>]) -> Vec<usize> {
    let mut xs: Vec<f64> = v.iter().flatten().copied().collect();
    if xs.len() < 10 {
        return vec![];
    }
    xs.sort_by(f64::total_cmp);
    let med = xs[xs.len() / 2];
    let mut dev: Vec<f64> = xs.iter().map(|x| (x - med).abs()).collect();
    dev.sort_by(f64::total_cmp);
    let mad = dev[dev.len() / 2].max(1.0);
    v.iter()
        .enumerate()
        .filter(|(_, x)| x.is_some_and(|x| 0.6745 * (x - med) / mad > 3.5))
        .map(|(i, _)| i)
        .collect()
}

/// Requests per minute, with its anomalies, from per-bucket counts.
fn rpm(label: &str, counts: &[Option<f64>], step: i64) -> Value {
    let v: Vec<Option<f64>> = counts.iter().map(|c| c.map(|c| c * 60.0 / step as f64)).collect();
    json!({ "label": label, "anomalies": anomalies(&v), "v": v })
}

fn quota(label: &str, used: f64, limit: f64, unit: &str) -> Value {
    json!({ "label": label, "used": used, "limit": limit, "unit": unit })
}

/// UTC calendar day "YYYY-MM-DD" for Unix seconds (days-from-civil, inverted).
pub fn day(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// "YYYY-MM-DDTHH:MM:SSZ", the form Cloudflare's GraphQL `Time` uses.
pub fn rfc3339(secs: i64) -> String {
    let s = secs.rem_euclid(86_400);
    format!("{}T{:02}:{:02}:{:02}Z", day(secs), s / 3600, s % 3600 / 60, s % 60)
}

/// Midnight UTC on the first of the month that contains `secs`.
pub fn month_start(secs: i64) -> i64 {
    let dom: i64 = day(secs)[8..].parse().unwrap_or(1);
    secs - secs.rem_euclid(86_400) - (dom - 1) * 86_400
}

// ───────────────────────── AWS ─────────────────────────

/// What the AWS page reads. Table capacity is the provisioned (RCU, WCU) from Terraform.
pub struct Aws<'a> {
    pub cw: &'a aws_sdk_cloudwatch::Client,
    pub cw_us_east_1: &'a aws_sdk_cloudwatch::Client, // CloudFront metrics live only there
    pub function: &'a str,
    pub tables: &'a [(String, f64, f64)],
    pub distribution: &'a str,
    pub queue: &'a str,
}

/// One metric on the page. Series with the same panel and label are summed (throttles across tables).
struct Spec {
    panel: &'static str,
    label: String,
    unit: &'static str,
    ns: &'static str,
    name: &'static str,
    dims: Vec<(&'static str, String)>,
    stat: &'static str, // Sum, Maximum, Average, or a percentile such as p99
    global: bool,
    per_s: bool, // Sum per bucket -> per second (DynamoDB capacity units)
}

fn spec(panel: &'static str, label: &str, unit: &'static str, ns: &'static str, name: &'static str, dims: Vec<(&'static str, String)>, stat: &'static str) -> Spec {
    Spec { panel, label: label.into(), unit, ns, name, dims, stat, global: false, per_s: false }
}

fn aws_specs(a: &Aws) -> Vec<Spec> {
    let f = || vec![("FunctionName", a.function.to_string())];
    let mut out = vec![
        spec("Lambda", "Invocations", "", "AWS/Lambda", "Invocations", f(), "Sum"),
        spec("Lambda", "Errors", "", "AWS/Lambda", "Errors", f(), "Sum"),
        spec("Lambda", "Throttles", "", "AWS/Lambda", "Throttles", f(), "Sum"),
        spec("Lambda", "Duration p50", "ms", "AWS/Lambda", "Duration", f(), "p50"),
        spec("Lambda", "Duration p99", "ms", "AWS/Lambda", "Duration", f(), "p99"),
        spec("Lambda", "Concurrent executions", "", "AWS/Lambda", "ConcurrentExecutions", f(), "Maximum"),
    ];
    for (table, _, _) in a.tables {
        let t = || vec![("TableName", table.clone())];
        let short = table.trim_start_matches("haltline_");
        for (label, name) in [("reads / s", "ConsumedReadCapacityUnits"), ("writes / s", "ConsumedWriteCapacityUnits")] {
            out.push(Spec { per_s: true, ..spec("DynamoDB", &format!("{short} {label}"), "units", "AWS/DynamoDB", name, t(), "Sum") });
        }
        for name in ["ReadThrottleEvents", "WriteThrottleEvents"] {
            out.push(spec("DynamoDB", "Throttled requests (all tables)", "", "AWS/DynamoDB", name, t(), "Sum"));
        }
    }
    if !a.queue.is_empty() {
        let q = || vec![("QueueName", a.queue.to_string())];
        out.push(spec("SQS", "Queue depth", "", "AWS/SQS", "ApproximateNumberOfMessagesVisible", q(), "Maximum"));
        out.push(spec("SQS", "Oldest message age", "s", "AWS/SQS", "ApproximateAgeOfOldestMessage", q(), "Maximum"));
    }
    if !a.distribution.is_empty() {
        let d = || vec![("DistributionId", a.distribution.to_string()), ("Region", "Global".to_string())];
        for (label, unit, name, stat) in [("Requests", "", "Requests", "Sum"), ("4xx rate", "%", "4xxErrorRate", "Average"), ("5xx rate", "%", "5xxErrorRate", "Average")] {
            out.push(Spec { global: true, ..spec("CloudFront (fallback path)", label, unit, "AWS/CloudFront", name, d(), stat) });
        }
    }
    out
}

async fn stat(cw: &aws_sdk_cloudwatch::Client, s: &Spec, start: i64, end: i64, step: i64) -> Result<Vec<(i64, f64)>, String> {
    let mut q = cw
        .get_metric_statistics()
        .namespace(s.ns)
        .metric_name(s.name)
        .start_time(DateTime::from_secs(start))
        .end_time(DateTime::from_secs(end))
        .period(step as i32);
    for (k, v) in &s.dims {
        q = q.dimensions(Dimension::builder().name(*k).value(v).build());
    }
    let pct = s.stat.starts_with('p');
    q = if pct { q.extended_statistics(s.stat) } else { q.statistics(Statistic::from(s.stat)) };
    let out = q.send().await.map_err(|e| format!("CloudWatch {}: {}", s.name, aws_sdk_cloudwatch::error::DisplayErrorContext(e)))?;
    Ok(out
        .datapoints()
        .iter()
        .filter_map(|d| {
            let v = match s.stat {
                _ if pct => d.extended_statistics()?.get(s.stat).copied(),
                "Sum" => d.sum(),
                "Maximum" => d.maximum(),
                _ => d.average(),
            }?;
            Some((d.timestamp()?.secs(), v))
        })
        .collect())
}

type Series<'a> = (String, &'a str, &'a str, Vec<Option<f64>>); // label, unit, agg, values

/// Grid series from each spec's datapoints, grouped into panels in spec order.
fn aws_panels(specs: &[Spec], points: &[Vec<(i64, f64)>], t0: i64, step: i64, n: usize) -> Vec<Value> {
    let mut panels: Vec<(&str, Vec<Series>)> = Vec::new();
    for (s, p) in specs.iter().zip(points) {
        let sum = s.stat == "Sum";
        let mut v = buckets(t0, step, n, p, if sum { Some(0.0) } else { None });
        if s.per_s {
            v.iter_mut().flatten().for_each(|x| *x /= step as f64);
        }
        let agg = if sum && !s.per_s { "sum" } else { "max" };
        if panels.last().is_none_or(|(title, _)| *title != s.panel) {
            panels.push((s.panel, Vec::new()));
        }
        let series = &mut panels.last_mut().unwrap().1;
        match series.iter_mut().find(|(label, ..)| *label == s.label) {
            Some((.., acc)) => acc.iter_mut().zip(&v).for_each(|(a, b)| *a = Some(a.unwrap_or(0.0) + b.unwrap_or(0.0))),
            None => series.push((s.label.clone(), s.unit, agg, v)),
        }
    }
    panels
        .into_iter()
        .map(|(title, series)| {
            let series: Vec<Value> = series.into_iter().map(|(label, unit, agg, v)| json!({ "label": label, "unit": unit, "agg": agg, "v": v })).collect();
            json!({ "title": title, "series": series })
        })
        .collect()
}

/// The AWS page's metrics: panels, Lambda requests per minute and the free-quota gauges.
pub async fn aws(a: &Aws<'_>, label: &str, secs: i64, step: i64, now: i64) -> Result<Value, String> {
    let (t0, n) = grid(now, secs, step);
    let specs = aws_specs(a);
    let f = vec![("FunctionName", a.function.to_string())];
    let mut monthly = vec![spec("", "Lambda requests this month", "", "AWS/Lambda", "Invocations", f, "Sum")];
    if !a.distribution.is_empty() {
        let d = vec![("DistributionId", a.distribution.to_string()), ("Region", "Global".to_string())];
        monthly.push(Spec { global: true, ..spec("", "CloudFront requests this month", "", "AWS/CloudFront", "Requests", d, "Sum") });
    }
    if !a.queue.is_empty() {
        let q = vec![("QueueName", a.queue.to_string())];
        monthly.push(spec("", "SQS messages sent this month", "", "AWS/SQS", "NumberOfMessagesSent", q, "Sum"));
    }
    let client = |s: &Spec| if s.global { a.cw_us_east_1 } else { a.cw };
    let month = month_start(now);
    let (points, month_points) = try_join(
        try_join_all(specs.iter().map(|s| stat(client(s), s, t0, now, step))),
        try_join_all(monthly.iter().map(|s| stat(client(s), s, month, now, 86_400))),
    )
    .await?;

    let total = |i: usize| month_points[i].iter().map(|(_, v)| v).sum::<f64>();
    let (rcu, wcu) = a.tables.iter().fold((0.0, 0.0), |(r, w), t| (r + t.1, w + t.2));
    let mut quotas = vec![
        quota(&monthly[0].label, total(0), 1e6, "requests"),
        quota("DynamoDB read capacity provisioned", rcu, 25.0, "RCU"),
        quota("DynamoDB write capacity provisioned", wcu, 25.0, "WCU"),
    ];
    for (i, s) in monthly.iter().enumerate().skip(1) {
        quotas.push(quota(&s.label, total(i), if s.ns == "AWS/CloudFront" { 1e7 } else { 1e6 }, "requests"));
    }
    let invocations = buckets(t0, step, n, &points[0], Some(0.0));
    Ok(json!({
        "range": label, "t0": t0, "step": step, "generated": now,
        "rpm": rpm("Lambda invocations per minute", &invocations, step),
        "panels": aws_panels(&specs, &points, t0, step, n),
        "quotas": quotas,
    }))
}

/// CloudWatch Logs search on the API's log group: the first 100 matches in the range.
// shortcut: FilterLogEvents scans in time order; move heavy searches to Logs Insights if it gets slow.
pub async fn logs(cwl: &aws_sdk_cloudwatchlogs::Client, group: &str, pattern: &str, start: i64, end: i64) -> Result<Value, String> {
    let mut rows = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..5 {
        let mut q = cwl.filter_log_events().log_group_name(group).start_time(start * 1000).end_time(end * 1000).limit(100).set_next_token(token);
        if !pattern.is_empty() {
            q = q.filter_pattern(pattern);
        }
        let out = q.send().await.map_err(|e| format!("CloudWatch Logs: {}", aws_sdk_cloudwatchlogs::error::DisplayErrorContext(e)))?;
        rows.extend(out.events().iter().map(|e| {
            json!({
                "ts": e.timestamp().unwrap_or(0) as f64 / 1000.0,
                "stream": e.log_stream_name().unwrap_or(""),
                "message": e.message().unwrap_or("").chars().take(2000).collect::<String>(),
            })
        }));
        token = out.next_token().map(str::to_string);
        if token.is_none() || rows.len() >= 100 {
            break;
        }
    }
    rows.truncate(100);
    Ok(Value::Array(rows))
}

// ───────────────────────── Cloudflare ─────────────────────────

/// One GraphQL query for the Cloudflare page. The bucket is a fixed dimension name, never user input.
/// `zone` false (no domain yet, workers.dev only): the account's Worker numbers only.
pub fn cf_query(step: i64, zone: bool) -> String {
    let q = cf_query_full(step);
    if zone {
        return q;
    }
    let (head, rest) = q.split_once("  zones(").expect("zones block");
    let accounts = &rest[rest.find("  accounts(").expect("accounts block")..];
    head.replace("$zone: String!, ", "") + accounts
}

fn cf_query_full(step: i64) -> String {
    let bucket = if step >= 300 { "datetimeFiveMinutes" } else { "datetimeMinute" };
    let f = "filter: {datetime_geq: $start, datetime_lt: $end}";
    format!(
        "query ($zone: String!, $account: String!, $script: String!, $start: Time!, $end: Time!, $dayStart: Time!) {{ viewer {{
  zones(filter: {{zoneTag: $zone}}) {{
    traffic: httpRequestsAdaptiveGroups(limit: 2000, {f}, orderBy: [{bucket}_ASC]) {{ count dimensions {{ t: {bucket} }} }}
    status: httpRequestsAdaptiveGroups(limit: 20, {f}, orderBy: [count_DESC]) {{ count dimensions {{ edgeResponseStatus }} }}
    cache: httpRequestsAdaptiveGroups(limit: 10, {f}, orderBy: [count_DESC]) {{ count dimensions {{ cacheStatus }} }}
    countries: httpRequestsAdaptiveGroups(limit: 5, {f}, orderBy: [count_DESC]) {{ count dimensions {{ clientCountryName }} }}
    firewall: firewallEventsAdaptive(limit: 1000, {f}, orderBy: [datetime_DESC]) {{ action source ruleId clientIP clientAsn clientCountryName }}
  }}
  accounts(filter: {{accountTag: $account}}) {{
    workers: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: $start, datetime_lt: $end, scriptName: $script}}) {{ sum {{ requests errors subrequests }} quantiles {{ cpuTimeP50 cpuTimeP99 }} }}
    today: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: $dayStart, datetime_lt: $end, scriptName: $script}}) {{ sum {{ requests }} }}
  }}
}} }}"
    )
}

/// GraphQL variables for `cf_query`.
pub fn cf_vars(zone: &str, account: &str, script: &str, t0: i64, now: i64) -> Value {
    let mut v = json!({
        "account": account, "script": script,
        "start": rfc3339(t0), "end": rfc3339(now + 1), "dayStart": rfc3339(now - now.rem_euclid(86_400)),
    });
    if !zone.is_empty() {
        v["zone"] = json!(zone); // an unused declared variable is a GraphQL error, so only with the zone block
    }
    v
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Count rows by key, largest first, at most `top`.
fn top_by(rows: &[Value], key: impl Fn(&Value) -> String, top: usize) -> Vec<(String, f64)> {
    let mut m: HashMap<String, f64> = HashMap::new();
    for r in rows {
        *m.entry(key(r)).or_default() += 1.0;
    }
    let mut out: Vec<(String, f64)> = m.into_iter().collect();
    out.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.truncate(top);
    out
}

fn table(title: &str, columns: Value, rows: Vec<Value>) -> Value {
    json!({ "title": title, "columns": columns, "rows": rows })
}

/// The GraphQL response -> the Cloudflare page's panels. API errors come back as Err.
pub fn cf_panels(resp: &Value, label: &str, t0: i64, step: i64, n: usize, now: i64) -> Result<Value, String> {
    if let Some(e) = resp["errors"].as_array().and_then(|e| e.first()) {
        return Err(format!("Cloudflare analytics: {}", text(&e["message"])));
    }
    let zone = &resp["data"]["viewer"]["zones"][0];
    let acct = &resp["data"]["viewer"]["accounts"][0];
    let rows = |v: &Value| v.as_array().cloned().unwrap_or_default();

    // Buckets come back as RFC 3339 strings; match them against the grid instead of parsing dates.
    let index: HashMap<String, i64> = (0..n as i64).map(|i| (rfc3339(t0 + i * step), t0 + i * step)).collect();
    let points: Vec<(i64, f64)> = rows(&zone["traffic"])
        .iter()
        .filter_map(|r| Some((*index.get(r["dimensions"]["t"].as_str()?)?, r["count"].as_f64()?)))
        .collect();
    let traffic = buckets(t0, step, n, &points, Some(0.0));

    let grouped = |key: &str, dim: &str, title: &str| {
        let rs = rows(&zone[key]).iter().map(|r| json!({ "key": text(&r["dimensions"][dim]), "count": r["count"] })).collect();
        table(title, json!([{ "key": "key", "label": title }, { "key": "count", "label": "Requests", "num": true }]), rs)
    };

    let fw = rows(&zone["firewall"]);
    let of_latest = if fw.len() >= 1000 { " (latest 1,000 events)" } else { "" };
    let by_action = top_by(&fw, |r| format!("{}\u{1f}{}", text(&r["action"]), text(&r["source"])), 20);
    let ip_info: HashMap<String, (String, String)> = fw.iter().map(|r| (text(&r["clientIP"]), (text(&r["clientAsn"]), text(&r["clientCountryName"])))).collect();
    let ddos = fw.iter().filter(|r| r["source"].as_str().is_some_and(|s| s.contains("ddos"))).count();
    let blocks = fw.iter().filter(|r| matches!(r["action"].as_str(), Some("block" | "drop" | "challenge" | "managed_challenge" | "jschallenge"))).count();

    let w = rows(&acct["workers"]);
    let wsum = |k: &str| w.iter().filter_map(|r| r["sum"][k].as_f64()).sum::<f64>();
    let wq = |k: &str| w.iter().filter_map(|r| r["quantiles"][k].as_f64()).fold(0.0, f64::max) / 1000.0; // µs -> ms
    let today = rows(&acct["today"]).iter().filter_map(|r| r["sum"]["requests"].as_f64()).sum::<f64>();
    let fig = |label: &str, value: f64, unit: &str| json!({ "label": label, "value": value, "unit": unit });

    let action_rows = by_action
        .into_iter()
        .map(|(k, c)| {
            let (a, s) = k.split_once('\u{1f}').unwrap_or((&k, ""));
            json!({ "action": a, "source": s, "count": c })
        })
        .collect();
    let ip_rows = top_by(&fw, |r| text(&r["clientIP"]), 10)
        .into_iter()
        .map(|(ip, c)| {
            let (asn, cc) = ip_info.get(&ip).cloned().unwrap_or_default();
            json!({ "ip": ip, "asn": asn, "country": cc, "count": c })
        })
        .collect();
    let asn_rows = top_by(&fw, |r| text(&r["clientAsn"]), 10).into_iter().map(|(asn, c)| json!({ "asn": asn, "count": c })).collect();

    let worker_panel = json!({ "title": "Worker", "series": [
        fig("Requests", wsum("requests"), ""), fig("Errors", wsum("errors"), ""), fig("Subrequests", wsum("subrequests"), ""),
        fig("CPU p50", wq("cpuTimeP50"), "ms"), fig("CPU p99", wq("cpuTimeP99"), "ms")] });
    let quotas = json!([quota("Worker requests today (UTC)", today, 1e5, "requests")]);
    if zone.is_null() {
        // No zone queried (no domain yet): the Worker numbers only.
        return Ok(json!({
            "range": label, "t0": t0, "step": step, "generated": now, "rpm": null,
            "note": "Edge traffic, security events and the request chart need a domain on Cloudflare (a zone). Until then this page shows the Worker only.",
            "panels": [worker_panel], "quotas": quotas, "tables": [],
        }));
    }

    Ok(json!({
        "range": label, "t0": t0, "step": step, "generated": now,
        "rpm": rpm("Edge requests per minute", &traffic, step),
        "panels": [
            { "title": "Edge traffic", "series": [{ "label": "Requests", "unit": "", "agg": "sum", "v": traffic }] },
            { "title": format!("Security events{of_latest}"), "series": [
                fig("Events", fw.len() as f64, ""), fig("Blocked or challenged", blocks as f64, ""), fig("DDoS mitigations", ddos as f64, "")] },
            worker_panel,
        ],
        "quotas": quotas,
        "tables": [
            table(&format!("Security events by action{of_latest}"),
                json!([{ "key": "action", "label": "Action" }, { "key": "source", "label": "Source" }, { "key": "count", "label": "Events", "num": true }]), action_rows),
            table(&format!("Top IPs{of_latest}"),
                json!([{ "key": "ip", "label": "IP", "mono": true }, { "key": "asn", "label": "ASN", "mono": true }, { "key": "country", "label": "Country" }, { "key": "count", "label": "Events", "num": true }]), ip_rows),
            table(&format!("Top ASNs{of_latest}"),
                json!([{ "key": "asn", "label": "ASN", "mono": true }, { "key": "count", "label": "Events", "num": true }]), asn_rows),
            grouped("status", "edgeResponseStatus", "Status code"),
            grouped("cache", "cacheStatus", "Cache status"),
            grouped("countries", "clientCountryName", "Country"),
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_and_grid() {
        assert_eq!(range(None), Some(("6h", 21_600, 60)));
        assert_eq!(range(Some("24h")), Some(("24h", 86_400, 300)));
        assert_eq!(range(Some("7d")), None);
        assert_eq!(range(Some("1h; drop")), None);
        assert_eq!(grid(3_661, 3_600, 60), (60, 61)); // starts on a bucket, ends on the partial one
    }

    #[test]
    fn cache_expires_after_60_s() {
        let c = Cache::default();
        c.put("aws:6h", 1_000, json!(1));
        assert_eq!(c.get("aws:6h", 1_059), Some(json!(1)));
        assert_eq!(c.get("aws:6h", 1_060), None);
        assert_eq!(c.get("cf:6h", 1_000), None);
        c.put("cf:6h", 1_070, json!(2)); // the expired entry is dropped
        assert_eq!(c.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn buckets_fill_gaps_and_drop_outsiders() {
        let pts = [(120, 5.0), (60, 2.0), (999, 9.0), (-60, 1.0)];
        assert_eq!(buckets(60, 60, 3, &pts, Some(0.0)), vec![Some(2.0), Some(5.0), Some(0.0)]);
        assert_eq!(buckets(60, 60, 3, &pts, None), vec![Some(2.0), Some(5.0), None]);
    }

    #[test]
    fn anomalies_flag_spikes_only() {
        let mut v: Vec<Option<f64>> = (0..30).map(|i| Some(10.0 + (i % 3) as f64)).collect();
        assert!(anomalies(&v).is_empty());
        v[7] = Some(80.0);
        v[20] = Some(0.0); // a drop is not flagged
        v[25] = None;
        assert_eq!(anomalies(&v), vec![7]);
        assert!(anomalies(&[Some(0.0), Some(500.0)]).is_empty()); // too short to judge
        let flat: Vec<Option<f64>> = (0..30).map(|i| Some(if i == 4 { 3.0 } else { 0.0 })).collect();
        assert!(anomalies(&flat).is_empty()); // MAD floor: 3 req/min over 0 is noise
    }

    #[test]
    fn times() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(month_start(1_700_000_000), 1_698_796_800); // 2023-11-01
        assert_eq!(month_start(1_698_796_800), 1_698_796_800);
    }

    fn client() -> aws_sdk_cloudwatch::Client {
        let conf = aws_sdk_cloudwatch::Config::builder().behavior_version(aws_sdk_cloudwatch::config::BehaviorVersion::latest()).build();
        aws_sdk_cloudwatch::Client::from_conf(conf)
    }

    #[test]
    fn aws_panels_group_scale_and_sum() {
        let tables = [("haltline_events".to_string(), 5.0, 10.0), ("haltline_index".to_string(), 5.0, 6.0)];
        let cw = client();
        let a = Aws { cw: &cw, cw_us_east_1: &cw, function: "haltline-api", tables: &tables, distribution: "", queue: "" };
        let specs = aws_specs(&a);
        assert_eq!(specs.len(), 6 + 2 * 4); // no SQS or CloudFront specs when they aren't configured
        let points: Vec<Vec<(i64, f64)>> = specs
            .iter()
            .map(|s| match (s.name, s.dims[0].1.as_str()) {
                ("Invocations", _) => vec![(0, 120.0), (120, 60.0)],
                ("ConsumedWriteCapacityUnits", "haltline_events") => vec![(60, 300.0)],
                ("ReadThrottleEvents", "haltline_events") => vec![(0, 2.0)],
                ("WriteThrottleEvents", "haltline_index") => vec![(0, 1.0), (60, 4.0)],
                ("Duration", _) => vec![(60, 31.5)],
                _ => vec![],
            })
            .collect();
        let panels = aws_panels(&specs, &points, 0, 60, 3);
        assert_eq!(panels.len(), 2);
        assert_eq!(panels[0]["title"], "Lambda");
        assert_eq!(panels[0]["series"][0]["v"], json!([120.0, 0.0, 60.0])); // counts: gaps are 0
        assert_eq!(panels[0]["series"][3]["v"], json!([null, 31.5, null])); // percentiles: gaps stay empty
        let ddb = panels[1]["series"].as_array().unwrap();
        assert_eq!(ddb.len(), 5); // 2 tables x reads / writes + one throttle series
        let events_w = ddb.iter().find(|s| s["label"] == "events writes / s").unwrap();
        assert_eq!(events_w["v"], json!([0.0, 5.0, 0.0])); // 300 units in 60 s = 5 / s
        assert_eq!(events_w["agg"], "max");
        let thr = ddb.iter().find(|s| s["label"] == "Throttled requests (all tables)").unwrap();
        assert_eq!(thr["v"], json!([3.0, 4.0, 0.0]));
    }

    #[test]
    fn cloudflare_query_and_vars() {
        assert!(cf_query(60, true).contains("orderBy: [datetimeMinute_ASC]"));
        assert!(cf_query(300, true).contains("t: datetimeFiveMinutes"));
        let v = cf_vars("z", "a", "haltline-tier2", 1_700_000_000, 1_700_003_600);
        assert_eq!(v["start"], "2023-11-14T22:13:20Z");
        assert_eq!(v["dayStart"], "2023-11-14T00:00:00Z");
    }

    #[test]
    fn cloudflare_without_a_zone_asks_and_shows_the_worker_only() {
        let q = cf_query(60, false);
        assert!(!q.contains("zones(") && !q.contains("$zone"), "{q}");
        assert!(q.contains("accounts(filter") && q.trim_end().ends_with("} }"), "{q}");
        assert!(cf_vars("", "a", "w", 0, 60).get("zone").is_none(), "no unused $zone variable");
        let resp = json!({ "data": { "viewer": { "accounts": [{
            "workers": [{ "sum": { "requests": 7.0, "errors": 1.0, "subrequests": 7.0 }, "quantiles": { "cpuTimeP50": 1000.0, "cpuTimeP99": 3000.0 } }],
            "today": [{ "sum": { "requests": 42.0 } }] }] } } });
        let out = cf_panels(&resp, "1h", 0, 60, 2, 0).unwrap();
        assert!(out["rpm"].is_null() && out["note"].is_string());
        assert_eq!(out["panels"].as_array().unwrap().len(), 1);
        assert_eq!(out["panels"][0]["series"][0]["value"], 7.0);
        assert_eq!(out["quotas"][0]["used"], 42.0);
    }

    #[test]
    fn cloudflare_response_parses() {
        let t0 = 1_700_000_040; // a minute boundary
        let fw = |action: &str, source: &str, ip: &str, asn: Value, cc: &str| {
            json!({ "action": action, "source": source, "clientIP": ip, "clientAsn": asn, "clientCountryName": cc })
        };
        let resp = json!({ "data": { "viewer": {
            "zones": [{
                "traffic": [
                    { "count": 30, "dimensions": { "t": rfc3339(t0) } },
                    { "count": 900, "dimensions": { "t": rfc3339(t0 + 120) } },
                    { "count": 7, "dimensions": { "t": "2001-01-01T00:00:00Z" } }],
                "status": [{ "count": 920, "dimensions": { "edgeResponseStatus": 200 } }, { "count": 10, "dimensions": { "edgeResponseStatus": 429 } }],
                "cache": [{ "count": 930, "dimensions": { "cacheStatus": "dynamic" } }],
                "countries": [{ "count": 930, "dimensions": { "clientCountryName": "IN" } }],
                "firewall": [
                    fw("block", "firewallCustom", "192.0.2.9", json!("64500"), "US"),
                    fw("block", "firewallCustom", "192.0.2.9", json!("64500"), "US"),
                    fw("block", "ratelimit", "198.51.100.4", json!(64501), "DE"),
                    fw("drop", "l7ddos", "203.0.113.5", json!("64502"), "SG"),
                    fw("log", "firewallManaged", "203.0.113.5", json!("64502"), "SG")]
            }],
            "accounts": [{
                "workers": [{ "sum": { "requests": 930, "errors": 3, "subrequests": 40 }, "quantiles": { "cpuTimeP50": 1200, "cpuTimeP99": 4800 } }],
                "today": [{ "sum": { "requests": 85_000 } }]
            }]
        } }, "errors": null });
        let out = cf_panels(&resp, "1h", t0, 60, 4, t0 + 200).unwrap();
        assert_eq!(out["rpm"]["v"], json!([30.0, 0.0, 900.0, 0.0])); // the out-of-range bucket is ignored
        assert_eq!(out["panels"][1]["series"][1]["value"], 4.0); // blocks + the drop; "log" is not a block
        assert_eq!(out["panels"][1]["series"][2]["value"], 1.0); // DDoS
        assert_eq!(out["panels"][2]["series"][4]["value"], 4.8); // CPU p99 in ms
        assert_eq!(out["quotas"][0]["used"], 85_000.0);
        let t = &out["tables"];
        assert_eq!(t[0]["rows"][0], json!({ "action": "block", "source": "firewallCustom", "count": 2.0 }));
        assert_eq!(t[1]["rows"][0], json!({ "ip": "192.0.2.9", "asn": "64500", "country": "US", "count": 2.0 }));
        assert!(t[2]["rows"].as_array().unwrap().iter().any(|r| r["asn"] == "64501")); // a numeric ASN reads as text
        assert_eq!(t[3]["rows"][1], json!({ "key": "429", "count": 10 }));
    }

    #[test]
    fn cloudflare_errors_surface() {
        let resp = json!({ "data": null, "errors": [{ "message": "not authorized for that account" }] });
        assert_eq!(cf_panels(&resp, "1h", 0, 60, 2, 0).unwrap_err(), "Cloudflare analytics: not authorized for that account");
    }
}
