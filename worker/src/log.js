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

// shortcut: one log call to AWS per scored request; batch (Queues / SQS) past ~30K scores a day.
export function sendLog(env, event) {
  return toAws(env, "/internal/log", new TextEncoder().encode(JSON.stringify(event))).catch(() => {});
}
