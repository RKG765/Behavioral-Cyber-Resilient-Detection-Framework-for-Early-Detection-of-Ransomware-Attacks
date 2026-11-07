// Cloudflare Worker, the primary Tier-2 entry point (plan sections 3.1 and 4.1).
//   POST /v1/score     signed by the device key -> signed {"verdict", "request_id", "nonce"}
//   POST /v1/register  forwarded to the AWS API with the Cloudflare-only origin secret
// Bindings (wrangler.toml): KV DEVICES (device_id -> {"pk", "status"}), var AWS_API_URL,
// secrets RESPONSE_SIGNING_SEED and ORIGIN_SECRET.
import scorerModule from "../../tier2_scorer/target/wasm32-unknown-unknown/release/tier2_scorer.wasm";
import { signedJson, unb64, verifyRequest } from "./auth.js";

let scorer; // instantiated once per isolate
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function score(request, env) {
  const body = await request.arrayBuffer();
  const device = request.headers.get("x-tt-device") ?? "";
  const record = /^[0-9a-f]{32}$/.test(device) ? await env.DEVICES.get(device, { type: "json", cacheTtl: 60 }) : null;
  if (!record) return json({ error: "unauthorized" }, 401);
  if (record.status !== "active") return json({ error: "revoked" }, 403);

  const auth = await verifyRequest(request.headers, "POST", "/v1/score", body, unb64(record.pk), Date.now() / 1000);
  if (auth.error) return json({ error: auth.error }, auth.status);

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
  return signedJson({ verdict, request_id: crypto.randomUUID(), nonce: auth.nonce }, env.RESPONSE_SIGNING_SEED);
}

function register(request, env) {
  const headers = new Headers(request.headers);
  headers.set("x-tt-origin-secret", env.ORIGIN_SECRET);
  headers.set("x-tt-client-ip", request.headers.get("cf-connecting-ip") ?? "");
  return fetch(`${env.AWS_API_URL}/v1/register`, { method: "POST", headers, body: request.body });
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (request.method === "POST" && path === "/v1/score") return score(request, env);
    if (request.method === "POST" && path === "/v1/register") return register(request, env);
    return json({ error: "not found" }, 404);
  },
};
