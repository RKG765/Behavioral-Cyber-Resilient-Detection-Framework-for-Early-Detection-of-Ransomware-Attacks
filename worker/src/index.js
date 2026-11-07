// Cloudflare Worker: POST /v1/score {"features": [99 numbers]} -> {"verdict", "request_id"}.
// Tier 2 runs in the Rust scorer compiled to WASM (tier2_scorer). No auth yet (build step 2).
import scorerModule from "../../tier2_scorer/target/wasm32-unknown-unknown/release/tier2_scorer.wasm";

let scorer; // instantiated once per isolate
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export default {
  async fetch(request) {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/score") {
      return json({ error: "not found" }, 404);
    }
    let features;
    try {
      features = (await request.json()).features;
    } catch {
      features = null;
    }
    if (!Array.isArray(features) || features.length !== 99 || !features.every(Number.isFinite)) {
      return json({ error: 'body must be {"features": [99 finite numbers]}' }, 400);
    }
    scorer ??= (await WebAssembly.instantiate(scorerModule)).exports;
    new Float32Array(scorer.memory.buffer, scorer.input_ptr(), 99).set(features);
    const verdict = scorer.score() >= scorer.threshold() ? "KILL" : "BENIGN";
    return json({ verdict, request_id: crypto.randomUUID() });
  },
};
