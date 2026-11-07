// node --test infra/aws/edge_filter.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const src = readFileSync(new URL("./edge_filter.js", import.meta.url), "utf8").replaceAll("__BLOCKED_IPS__", '{"9.9.9.9": true}'); // like Terraform's replace()
const handler = new Function(`${src}; return handler;`)();

const signed = { "x-tt-device": "d", "x-tt-time": "1", "x-tt-nonce": "n", "x-tt-sig": "s", "x-amz-content-sha256": "h" };
const event = (method, uri, headers = {}, ip = "1.1.1.1") => ({
  viewer: { ip },
  request: { method, uri, headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, { value: v }])) },
});

test("signed score requests pass through unchanged", () => {
  const ev = event("POST", "/v1/score", signed);
  assert.equal(handler(ev), ev.request);
});

test("missing any signature header, or the body hash, is refused", () => {
  for (const name of Object.keys(signed)) {
    const headers = { ...signed };
    delete headers[name];
    assert.equal(handler(event("POST", "/v1/score", headers)).statusCode, 403, name);
  }
});

test("register needs the origin secret and body hash", () => {
  assert.equal(handler(event("POST", "/v1/register", { "x-amz-content-sha256": "h" })).statusCode, 404);
  const ev = event("POST", "/v1/register", { "x-tt-origin-secret": "x", "x-amz-content-sha256": "h" });
  assert.equal(handler(ev), ev.request);
});

test("other methods and paths look absent; blocked IPs are refused", () => {
  assert.equal(handler(event("GET", "/v1/score", signed)).statusCode, 404);
  assert.equal(handler(event("POST", "/admin", signed)).statusCode, 404);
  assert.equal(handler(event("POST", "/v1/score", signed, "9.9.9.9")).statusCode, 403);
});
