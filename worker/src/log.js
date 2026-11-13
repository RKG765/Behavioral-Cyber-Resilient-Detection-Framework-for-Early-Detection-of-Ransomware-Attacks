// Request logging for the SOC console (plan section 6.1): one event per request, sent to the AWS
// log route in the background. Rejected requests are sampled so junk can't flood the log.

const lastReject = new Map(); // ip -> last logged (s), per isolate

/** True at most once per IP per minute. */
export function sampleReject(ip, now) {
  if ((lastReject.get(ip) ?? -Infinity) > now - 60) return false;
  if (lastReject.size > 10_000) lastReject.clear();
  lastReject.set(ip, now);
  return true;
}

export async function sha256hex(buf) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** POST to the AWS API through CloudFront with the Cloudflare-only origin secret. */
export async function toAws(env, path, body, extraHeaders = {}) {
  const headers = new Headers({ "content-type": "application/json", ...extraHeaders });
  headers.set("x-tt-origin-secret", env.ORIGIN_SECRET);
  headers.set("x-amz-content-sha256", await sha256hex(body)); // CloudFront OAC needs the body hash
  return fetch(`${env.AWS_API_URL}${path}`, { method: "POST", headers, body });
}

/** Event fields for one request; `verified` is the device's key kind, or "failed". */
export function logEvent(request, fields) {
  return {
    device: request.headers.get("x-tt-device") ?? "",
    ip: request.headers.get("cf-connecting-ip") ?? "",
    country: request.headers.get("cf-ipcountry") ?? "",
    asn: String(request.cf?.asn ?? ""),
    path: new URL(request.url).pathname,
    source: "cf",
    ...fields,
  };
}

// Events wait up to FLUSH_MS in this isolate and go to AWS as one call. One call per request would pass
// Lambda's free 1M requests a month at ~33K requests a day; SQS has the same per-message limit.
export const FLUSH_MS = 2000;
export const MAX_BATCH = 50; // the Lambda takes up to 100
let pending = [];

/** Queue one event; ctx.waitUntil keeps the isolate alive until its batch is sent (best effort). */
export function queueLog(env, ctx, event) {
  pending.push(event);
  if (pending.length >= MAX_BATCH) ctx.waitUntil(flushLog(env));
  else if (pending.length === 1) ctx.waitUntil(new Promise((r) => setTimeout(r, FLUSH_MS)).then(() => flushLog(env)));
}

export function flushLog(env) {
  if (!pending.length) return Promise.resolve();
  const batch = pending;
  pending = [];
  return toAws(env, "/internal/log", new TextEncoder().encode(JSON.stringify(batch))).catch(() => {});
}
