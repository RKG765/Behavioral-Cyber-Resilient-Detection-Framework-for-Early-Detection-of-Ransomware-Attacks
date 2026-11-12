// Local preview only. app.js imports this on localhost with `?demo` in the URL; it answers /admin/*
// with synthetic sample data (documentation IP ranges, made-up IDs) so the console can be viewed
// without AWS. Production never loads it: the import is gated on the hostname.
const now = () => Math.floor(Date.now() / 1000);
const T = now();
let seed = 7;
const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const hex = (n) => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(rnd() * 16)]).join("");

const OFFICE = "203.0.113.24"; // one NAT with several devices behind it
const devices = [
  ...Array.from({ length: 9 }, () => ({ kind: "tpm", status: "active" })),
  ...Array.from({ length: 3 }, () => ({ kind: "software", status: "active" })),
  { kind: "tpm", status: "revoked" },
  { kind: "software", status: "revoked" },
].map((d, i) => {
  const ip = i < 5 ? OFFICE : `198.51.100.${10 + i * 7}`;
  return {
    ...d, device_id: hex(32), last_ip: ip, first_ip: i % 4 === 0 ? `192.0.2.${40 + i}` : ip,
    created_at: T - 86_400 * (3 + i * 2), last_seen: T - (d.status === "revoked" ? 86_400 * 2 : Math.floor(rnd() * 20_000)),
  };
});
const COUNTRY = { [OFFICE]: "IN" };
const country = (ip) => (COUNTRY[ip] ??= pick(["IN", "IN", "US", "DE", "GB", "SG"]));

function event(ts, forceReject) {
  const d = pick(devices);
  const roll = rnd();
  if (forceReject || roll < 0.14) {
    const [status, reason, verified, dev] = pick([
      [401, "unknown device", "failed", null], [401, "bad signature", "failed", d.device_id],
      [401, "stale timestamp", "failed", d.device_id], [429, "rate limited", d.kind, d.device_id],
      [403, "revoked", d.kind, devices[12].device_id],
    ]);
    const ip = dev ? d.last_ip : "192.0.2.199";
    return { ts, device: dev, ip, country: country(ip), verified, path: "/v1/score", status, reason, ms: 1 + rnd() * 3 };
  }
  const path = roll > 0.96 ? "/v1/report" : "/v1/score";
  return {
    ts, device: d.device_id, ip: d.last_ip, country: country(d.last_ip), verified: d.kind, path, status: 200,
    verdict: path === "/v1/score" ? (rnd() < 0.08 ? "KILL" : "BENIGN") : undefined, reason: "", ms: 18 + rnd() * 40 + (rnd() < 0.05 ? 160 : 0),
  };
}
const events = Array.from({ length: 70 }, (_, i) => event(T - 6 * 3600 + i * 300 + Math.floor(rnd() * 200), i % 23 === 5 || i === 66 || i === 68));
setInterval(() => events.push(event(now())), 7000); // keeps the live log moving

const reports = [
  { name: "invoice_viewer.exe", reason: "I trust this app", path: "C:\\Users\\asha\\Downloads\\invoice_viewer.exe", reasons: ["renamed 412 files in Documents", "deleted shadow copies"] },
  { name: "backup-sync.exe", reason: "It is my backup tool", path: "C:\\Program Files\\BackupSync\\backup-sync.exe", reasons: ["rewrote 1,904 files in 40 s"] },
  { name: "setup_x64 (1).exe", reason: "I don't know this app", path: "C:\\Users\\ravi\\AppData\\Local\\Temp\\setup_x64 (1).exe", reasons: ["wrote high-entropy files", "dropped a ransom note"] },
  { name: "photo-tool.exe", reason: "False alarm", path: "D:\\Tools\\photo-tool.exe", reasons: ["bulk renamed 230 images"] },
].map((r, i) => ({ ...r, ts: T - 3600 * (5 - i), device: devices[i * 2].device_id, sha256: hex(64), ip: devices[i * 2].last_ip }));

const licences = [[25, 11], [10, 10], [5, 2], [100, 37]].map(([seats, used]) => ({ licence_hash: hex(64), seats, used }));
const admins = [{ email: "admin@example.com", role: "admin", status: "CONFIRMED", enabled: true }, { email: "analyst@example.com", role: "analyst", status: "FORCE_CHANGE_PASSWORD", enabled: true }];
const audit = [
  { ts: T - 7200, admin: "priya@example.com", action: "revoke", target: devices[12].device_id },
  { ts: T - 6900, admin: "priya@example.com", action: "block", target: "192.0.2.199" },
  { ts: T - 3000, admin: "analyst@example.com", action: "restore", target: devices[3].device_id },
];

function ips() {
  const m = new Map();
  for (const e of events) {
    const r = m.get(e.ip) ?? { ip: e.ip, devices: new Set(), hits: 0, last_seen: 0, country: e.country };
    if (e.device) r.devices.add(e.device);
    r.hits++;
    r.last_seen = Math.max(r.last_seen, e.ts);
    m.set(e.ip, r);
  }
  return [...m.values()].map((r) => ({ ...r, devices: r.devices.size }));
}

function overview() {
  const hour = events.filter((e) => e.ts > now() - 3600);
  const ms = hour.filter((e) => e.status === 200).map((e) => e.ms).sort((a, b) => a - b);
  const p = (q) => ms[Math.min(ms.length - 1, Math.floor(q * ms.length))] ?? 0;
  return {
    devices: devices.length, online_24h: devices.filter((d) => d.last_seen > now() - 86_400).length,
    revoked: devices.filter((d) => d.status === "revoked").length, lower_trust: devices.filter((d) => d.kind === "software").length,
    requests_1h: hour.length, rejected_1h: hour.filter((e) => e.status !== 200).length, kills_1h: hour.filter((e) => e.verdict === "KILL").length,
    p50_ms: p(0.5), p99_ms: p(0.99),
  };
}

// Cloud pages: the shapes the Lambda's /admin/metrics/* returns (tier2_scorer/src/cloud.rs). The
// spikes are planted, and listed as the anomalies the server would flag.
const RANGES = { "1h": [3600, 60], "6h": [21_600, 60], "24h": [86_400, 300] };
function metrics(kind, range, q) {
  const [secs, step] = RANGES[range] ?? RANGES["6h"];
  const t = now(), t0 = Math.floor((t - secs) / step) * step, n = secs / step + 1;
  const spikes = [Math.floor(n * 0.31), Math.floor(n * 0.78)];
  const per = step / 60;
  const wave = (base, amp, kick = [6, 9]) => Array.from({ length: n }, (_, i) => {
    const v = Math.max(0, base + amp * Math.sin(i / (n / 5)) + (rnd() - 0.5) * amp * 0.8);
    const k = spikes.indexOf(i);
    return Math.round((k < 0 ? v : v * kick[k]) * 10) / 10;
  });
  const series = (f) => Array.from({ length: n }, (_, i) => f(i));
  const s = (label, v, agg = "sum", unit = "") => ({ label, unit, agg, v });
  const fig = (label, value, unit = "") => ({ label, value, unit });
  const base = { range: range ?? "6h", t0, step, generated: t };
  if (kind === "aws") {
    const rpm = wave(24, 8);
    const inv = rpm.map((v) => Math.round(v * per));
    const lines = [
      "REPORT RequestId: 3f1c… Duration: 23.41 ms Billed Duration: 61 ms Memory Size: 128 MB Max Memory Used: 31 MB",
      "log failed: DynamoDB ProvisionedThroughputExceededException: The level of configured provisioned throughput for the table was exceeded",
      "metrics: CloudWatch Duration: ThrottlingException: Rate exceeded",
      "thread 'main' panicked at src/bin/lambda.rs:362: called `Option::unwrap()` on a `None` value",
      "START RequestId: 9a20… Version: $LATEST",
    ];
    const terms = (q ?? "").replace(/\?/g, " ").split(/\s+/).filter(Boolean);
    const logs = Array.from({ length: 24 }, (_, i) => ({ ts: t - secs + 900 * i + 37, stream: `2026/11/08/[$LATEST]${hex(32)}`, message: lines[i % lines.length] }))
      .filter((r) => !terms.length || terms.some((w) => r.message.includes(w)));
    const tbl = (name) => [`${name} reads / s`, `${name} writes / s`];
    return { ...base, rpm: { label: "Lambda invocations per minute", v: rpm, anomalies: spikes },
      panels: [
        { title: "Lambda", series: [s("Invocations", inv), s("Errors", series((i) => (spikes.includes(i) ? 3 : rnd() < 0.02 ? 1 : 0))),
          s("Throttles", series(() => 0)), s("Duration p50", series(() => 20 + rnd() * 6), "max", "ms"),
          s("Duration p99", series((i) => 48 + rnd() * 20 + (spikes.includes(i) ? 140 : 0)), "max", "ms"), s("Concurrent executions", series((i) => (spikes.includes(i) ? 4 : 1 + Math.round(rnd()))), "max")] },
        { title: "DynamoDB", series: [
          ...["devices", "events", "index", "licences"].flatMap((name, k) => tbl(name).map((label, w) => s(label, series((i) => Math.round((rnd() * (w ? 3 : 4) + (spikes.includes(i) && k === 1 ? 6 : 0)) * 10) / 10), "max", "units"))),
          s("Throttled requests (all tables)", series((i) => (i === spikes[1] ? 2 : 0)))] },
        { title: "CloudFront (fallback path)", series: [s("Requests", series(() => Math.round(rnd() * 3))), s("4xx rate", series(() => rnd() * 4), "max", "%"), s("5xx rate", series(() => 0), "max", "%")] },
      ],
      quotas: [
        { label: "Lambda requests this month", used: 412_380, limit: 1e6, unit: "requests" },
        { label: "DynamoDB read capacity provisioned", used: 22, limit: 25, unit: "RCU" },
        { label: "DynamoDB write capacity provisioned", used: 23, limit: 25, unit: "WCU" },
        { label: "CloudFront requests this month", used: 18_220, limit: 1e7, unit: "requests" },
      ],
      logs };
  }
  const rpm = wave(70, 22, [5, 7]);
  const fw = [["block", "firewallCustom", 212], ["block", "ratelimit", 96], ["managed_challenge", "firewallManaged", 31], ["drop", "l7ddos", 12], ["log", "firewallManaged", 4]];
  const ips = [["192.0.2.199", "64500", "US", 141], ["198.51.100.77", "64501", "DE", 88], ["203.0.113.5", "64502", "SG", 47], ["192.0.2.31", "64500", "US", 29], [OFFICE, "64511", "IN", 6]];
  const table = (title, columns, rows) => ({ title, columns, rows });
  const col = (key, label, more = {}) => ({ key, label, ...more });
  return { ...base, rpm: { label: "Edge requests per minute", v: rpm, anomalies: spikes },
    panels: [
      { title: "Edge traffic", series: [s("Requests", rpm.map((v) => Math.round(v * per)))] },
      { title: "Security events", series: [fig("Events", 355), fig("Blocked or challenged", 351), fig("DDoS mitigations", 12)] },
      { title: "Worker", series: [fig("Requests", Math.round(rpm.reduce((a, b) => a + b, 0) * per * 0.94)), fig("Errors", 7), fig("Subrequests", 1_204), fig("CPU p50", 1.4, "ms"), fig("CPU p99", 6.8, "ms")] },
    ],
    quotas: [{ label: "Worker requests today (UTC)", used: 83_610, limit: 1e5, unit: "requests" }],
    tables: [
      table("Security events by action", [col("action", "Action"), col("source", "Source"), col("count", "Events", { num: true })], fw.map(([action, source, count]) => ({ action, source, count }))),
      table("Top IPs", [col("ip", "IP", { mono: true }), col("asn", "ASN", { mono: true }), col("country", "Country"), col("count", "Events", { num: true })], ips.map(([ip, asn, country, count]) => ({ ip, asn, country, count }))),
      table("Top ASNs", [col("asn", "ASN", { mono: true }), col("count", "Events", { num: true })], [["64500", 170], ["64501", 88], ["64502", 47], ["64511", 6]].map(([asn, count]) => ({ asn, count }))),
      table("Status code", [col("key", "Status code"), col("count", "Requests", { num: true })], [["200", 24_120], ["401", 310], ["429", 96], ["403", 41], ["404", 12]].map(([key, count]) => ({ key, count }))),
      table("Cache status", [col("key", "Cache status"), col("count", "Requests", { num: true })], [["dynamic", 24_410], ["none", 169]].map(([key, count]) => ({ key, count }))),
      table("Country", [col("key", "Country"), col("count", "Requests", { num: true })], [["IN", 15_002], ["US", 4_870], ["DE", 2_210], ["GB", 1_480], ["SG", 1_017]].map(([key, count]) => ({ key, count }))),
    ] };
}

const today = new Date().toISOString().slice(0, 10);
function route(method, path, params) {
  const day = params.get("day");
  const [a, b, c] = path.split("/").map(decodeURIComponent);
  if (a === "metrics") return [200, metrics(b, params.get("range"), params.get("q"))];
  const onDay = (rows) => (!day || day === today ? rows : []);
  if (method === "POST" && a === "admins" && b === "new") {
    const email = params.get("email"), role = params.get("role");
    const known = admins.find((x) => x.email === email);
    if (!known) admins.push({ email, role, status: "FORCE_CHANGE_PASSWORD", enabled: true });
    return [200, { email, role, invited: !known, access_updated: false }];
  }
  if (method === "POST" && a === "licences" && b === "new") {
    const seats = Number(params.get("seats") ?? 1);
    const key = "HL-" + Array.from({ length: 4 }, () => hex(5).toUpperCase()).join("-");   // sample only
    licences.push({ licence_hash: hex(64), seats, used: 0 });
    audit.push({ ts: now(), admin: "analyst@example.com", action: "licence", target: hex(16) });
    return [200, { key, licence_hash: hex(64), seats }];
  }
  if (method === "POST" && a === "licences") {
    const i = licences.findIndex((x) => x.licence_hash === b);
    if (c === "seats") licences[i].seats = Number(params.get("seats"));
    if (c === "delete") licences.splice(i, 1);
    return [200, { ok: true }];
  }
  if (method === "POST" && a === "admins") {
    const i = admins.findIndex((x) => x.email === params.get("email"));
    if (b === "role") admins[i].role = params.get("role");
    if (b === "remove") admins.splice(i, 1);
    return [200, { ok: true }];
  }
  if (method === "POST") {
    const d = devices.find((x) => x.device_id === b);
    if (a === "devices" && d) d.status = c === "revoke" ? "revoked" : "active";
    audit.push({ ts: now(), admin: "analyst@example.com", action: c, target: b });
    return [200, { ok: true, edge_updated: true }];
  }
  if (a === "overview") return [200, overview()];
  if (a === "devices" && !b) return [200, devices];
  if (a === "devices") {
    const d = devices.find((x) => x.device_id === b);
    if (!d) return [404, { error: "no such device" }];
    const seen = [...new Set([d.first_ip, d.last_ip])];
    return [200, { device: d, ips: seen.map((ip, i) => ({
      sk: `ip#${ip}`, country: country(ip), hits: 40 + i * 113, first_seen: d.created_at + i * 86_400,
      last_seen: i === seen.length - 1 ? d.last_seen : d.created_at + 7200,
    })) }];
  }
  if (a === "ips") return [200, ips()];
  if (a === "events") return [200, onDay(events)];
  if (a === "reports") return [200, onDay(reports)];
  if (a === "audit") return [200, onDay(audit)];
  if (a === "licences") return [200, licences];
  if (a === "admins") return [200, admins];
  return [404, { error: "not found" }];
}

const real = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const url = new URL(String(input), location.origin);
  if (url.origin !== location.origin || !url.pathname.startsWith("/admin/")) return real(input, init);
  await new Promise((r) => setTimeout(r, 120));
  const [status, body] = route(init.method ?? "GET", url.pathname.slice(7), url.searchParams);
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
};

export const token = `x.${btoa(JSON.stringify({ email: "analyst@example.com" }))}.x`;
