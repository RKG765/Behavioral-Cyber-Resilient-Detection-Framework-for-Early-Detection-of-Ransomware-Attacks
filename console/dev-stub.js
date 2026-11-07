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

const today = new Date().toISOString().slice(0, 10);
function route(method, path, day) {
  const [a, b, c] = path.split("/").map(decodeURIComponent);
  const onDay = (rows) => (!day || day === today ? rows : []);
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
  return [404, { error: "not found" }];
}

const real = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const url = new URL(String(input), location.origin);
  if (url.origin !== location.origin || !url.pathname.startsWith("/admin/")) return real(input, init);
  await new Promise((r) => setTimeout(r, 120));
  const [status, body] = route(init.method ?? "GET", url.pathname.slice(7), url.searchParams.get("day"));
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
};

export const token = `x.${btoa(JSON.stringify({ email: "analyst@example.com" }))}.x`;
