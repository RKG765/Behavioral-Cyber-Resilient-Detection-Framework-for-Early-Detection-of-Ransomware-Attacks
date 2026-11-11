// node --test worker/test/auth.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64, canonical, deviceId, isBlocked, signedJson, verifyRequest } from "../src/auth.js";

test("the shared rate limiter can refuse a valid request (parallel connections can't dodge it)", async () => {
  const dev = await device();
  const body = enc.encode('{"features":[]}');
  const now = Math.floor(Date.now() / 1000);
  const seen = [];
  const limiter = { limit: async ({ key }) => (seen.push(key), { success: seen.length < 2 }) };
  assert.ok((await verifyRequest(await signed(dev, body, now), "POST", "/v1/score", body, dev.pk, now, limiter)).device);
  const r = await verifyRequest(await signed(dev, body, now), "POST", "/v1/score", body, dev.pk, now, limiter);
  assert.equal(r.status, 429);
  assert.deepEqual(seen, [dev.id, dev.id], "counted per device ID");
});

test("blocked IPs come from KV and are re-read at most once a minute", async () => {
  let list = ["9.9.9.9"], reads = 0;
  const env = { DEVICES: { get: async (key, type) => (reads++, assert.equal(key, "blocked_ips"), assert.equal(type, "json"), list) } };
  assert.equal(await isBlocked(env, "9.9.9.9", 1000), true);
  assert.equal(await isBlocked(env, "1.1.1.1", 1001), false);
  list = [];
  assert.equal(await isBlocked(env, "9.9.9.9", 1030), true, "cached for 60 s");
  assert.equal(reads, 1);
  assert.equal(await isBlocked(env, "9.9.9.9", 1061), false, "unblocked after the cache expires");
  const broken = { DEVICES: { get: async () => { throw new Error("kv down"); } } };
  assert.equal(await isBlocked(broken, "9.9.9.9", 9999), false, "a KV error never blocks everyone");
});

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function device() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const pk = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  return { privateKey, pk, id: await deviceId(pk) };
}

async function signed(dev, body, time, nonce = crypto.randomUUID().replaceAll("-", "")) {
  const msg = canonical("POST", "/v1/score", dev.id, String(time), nonce, hex(await crypto.subtle.digest("SHA-256", body)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, dev.privateKey, enc.encode(msg));
  return new Headers({ "x-tt-device": dev.id, "x-tt-time": String(time), "x-tt-nonce": nonce, "x-tt-sig": b64(sig) });
}

test("canonical string matches the protocol in tier2_scorer/README.md", () => {
  assert.equal(canonical("POST", "/v1/score", "d", "1", "n", "h"), "TT1\nPOST\n/v1/score\nd\n1\nn\nh");
});

test("valid request passes; tampering, old time, replay and wrong key fail", async () => {
  const dev = await device();
  const body = enc.encode('{"features":[1]}');
  const now = 1_700_000_000;
  const headers = await signed(dev, body, now);

  const ok = await verifyRequest(headers, "POST", "/v1/score", body, dev.pk, now);
  assert.equal(ok.device, dev.id);
  assert.equal((await verifyRequest(headers, "POST", "/v1/score", body, dev.pk, now)).status, 401, "replay");
  assert.equal((await verifyRequest(await signed(dev, body, now), "POST", "/v1/score", enc.encode("{}"), dev.pk, now)).status, 401, "tampered body");
  assert.equal((await verifyRequest(await signed(dev, body, now - 301), "POST", "/v1/score", body, dev.pk, now)).status, 401, "old timestamp");
  const other = await device();
  assert.equal((await verifyRequest(await signed(dev, body, now), "POST", "/v1/score", body, other.pk, now)).status, 401, "wrong key");
});

test("per-device rate limit", async () => {
  const dev = await device();
  const body = enc.encode("{}");
  const now = 1_700_000_100;
  let last;
  for (let i = 0; i < 61; i++) last = await verifyRequest(await signed(dev, body, now), "POST", "/v1/score", body, dev.pk, now);
  assert.equal(last.status, 429);
});

test("reply signature verifies with the server public key", async () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const res = await signedJson({ verdict: "BENIGN", nonce: "n" }, b64(seed));
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...seed]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const pub = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
  const text = await res.text();
  const sig = Uint8Array.from(atob(res.headers.get("x-tt-resp-sig")), (c) => c.charCodeAt(0));
  assert.ok(await crypto.subtle.verify("Ed25519", pub, sig, enc.encode(text)));
  assert.ok(!(await crypto.subtle.verify("Ed25519", pub, sig, enc.encode(text + " "))));
});
