// Cloudflare Worker, the primary Tier-2 entry point (plan sections 3.1, 4.1 and 6.1).
//   POST /v1/score     signed by the device key -> signed {"verdict", "request_id", "nonce"}
//   POST /v1/register  forwarded to the AWS API with the Cloudflare-only origin secret
//   POST /v1/report    forwarded the same way (the Lambda checks the device signature)
// Every scored request is logged to AWS in the background for the SOC console.
// Bindings (wrangler.toml): KV DEVICES (device_id -> {"pk", "status", "kind"}), var AWS_API_URL,
// secrets RESPONSE_SIGNING_SEED and ORIGIN_SECRET.
import scorerModule from "../../tier2_scorer/target/wasm32-unknown-unknown/release/tier2_scorer.wasm";
import { signedJson, unb64, verifyRequest } from "./auth.js";
import { logEvent, sampleReject, sendLog, toAws } from "./log.js";

let scorer; // instantiated once per isolate
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function score(request, env, log) {
  const body = await request.arrayBuffer();
  const device = request.headers.get("x-tt-device") ?? "";
  const record = /^[0-9a-f]{32}$/.test(device) ? await env.DEVICES.get(device, { type: "json", cacheTtl: 60 }) : null;
  if (!record) return log.reject(json({ error: "unauthorized" }, 401), "unknown device");
  if (record.status !== "active") return log.reject(json({ error: "revoked" }, 403), "revoked");

  const auth = await verifyRequest(request.headers, "POST", "/v1/score", body, unb64(record.pk), Date.now() / 1000);
  if (auth.error) return log.reject(json({ error: auth.error }, auth.status), auth.error);

  let features;
  try {
    features = JSON.parse(new TextDecoder().decode(body)).features;
  } catch {
    features = null;
  }
  if (!Array.isArray(features) || features.length !== 99 || !features.every(Number.isFinite)) {
    return json({ error: 'body must be {"features": [99 finite numbers]}' }, 400);
  }
  scorer ??= (await WebAssembly.instantiate(scorerModule)).exports;
  new Float32Array(scorer.memory.buffer, scorer.input_ptr(), 99).set(features);
  const verdict = scorer.score() >= scorer.threshold() ? "KILL" : "BENIGN";
  log.ok({ verified: record.kind ?? "tpm", verdict });
  return signedJson({ verdict, request_id: crypto.randomUUID(), nonce: auth.nonce }, env.RESPONSE_SIGNING_SEED);
}

async function forward(request, env, path) {
  const headers = Object.fromEntries(request.headers);
  headers["x-tt-client-ip"] = request.headers.get("cf-connecting-ip") ?? "";
  return toAws(env, path, await request.arrayBuffer(), headers);
}

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    const started = Date.now();
    const log = {
      ok: (fields) => ctx.waitUntil(sendLog(env, logEvent(request, { status: 200, ms: Date.now() - started, ...fields }))),
      reject: (res, reason) => {
        const ev = logEvent(request, { status: res.status, verified: "failed", reason, ms: Date.now() - started });
        if (sampleReject(ev.ip, Date.now() / 1000)) ctx.waitUntil(sendLog(env, ev));
        return res;
      },
    };
    if (request.method === "POST" && path === "/v1/score") return score(request, env, log);
    if (request.method === "POST" && (path === "/v1/register" || path === "/v1/report")) return forward(request, env, path);
    return json({ error: "not found" }, 404);
  },
};
