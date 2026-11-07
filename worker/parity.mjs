// Runs the Worker's WASM scorer over raw f32 feature rows; writes one f32 per row.
// Usage: node parity.mjs <tier2_scorer.wasm> <features.bin>  (called by tier2_scorer/parity_check.py)
import { readFileSync } from "node:fs";

const [wasmPath, featPath] = process.argv.slice(2);
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath));
const w = instance.exports;
const raw = readFileSync(featPath);
const feats = new Float32Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.length));
const out = new Float32Array(feats.length / 99);
for (let r = 0; r < out.length; r++) {
  new Float32Array(w.memory.buffer, w.input_ptr(), 99).set(feats.subarray(r * 99, r * 99 + 99));
  out[r] = w.score();
}
process.stdout.write(Buffer.from(out.buffer));
