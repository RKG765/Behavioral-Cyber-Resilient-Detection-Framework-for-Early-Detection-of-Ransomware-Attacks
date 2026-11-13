// node --test worker/test/log.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import { FLUSH_MS, MAX_BATCH, logEvent, queueLog, sampleReject, sha256hex } from "../src/log.js";

test("log events go to AWS in batches: after FLUSH_MS, or at once when MAX_BATCH fill up", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const posts = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    posts.push({ url, events: JSON.parse(new TextDecoder().decode(init.body)), secret: init.headers.get("x-tt-origin-secret") });
    return new Response("{}");
  });
  const env = { AWS_API_URL: "https://aws.example", ORIGIN_SECRET: "s" };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };

  queueLog(env, ctx, { n: 1 });
  queueLog(env, ctx, { n: 2 });
  assert.equal(waits.length, 1, "one timer per batch");
  t.mock.timers.tick(FLUSH_MS);
  await Promise.all(waits);
  assert.deepEqual(posts.map((p) => p.events.length), [2]);
  assert.equal(posts[0].url, "https://aws.example/internal/log");
  assert.equal(posts[0].secret, "s");

  for (let i = 0; i < MAX_BATCH; i++) queueLog(env, ctx, { n: i });
  assert.equal(waits.length, 3, "a timer for the new batch, then an immediate flush when it filled");
  await waits[2]; // the full batch is sent without waiting for the timer
  assert.deepEqual(posts.map((p) => p.events.length), [2, MAX_BATCH]);
  t.mock.timers.tick(FLUSH_MS);
  await Promise.all(waits);
  assert.equal(posts.length, 2, "an empty buffer sends nothing");
});

test("rejects are logged at most once per IP per minute", () => {
  assert.equal(sampleReject("1.1.1.1", 1000), true);
  assert.equal(sampleReject("1.1.1.1", 1030), false);
  assert.equal(sampleReject("2.2.2.2", 1030), true, "other IPs are independent");
  assert.equal(sampleReject("1.1.1.1", 1061), true);
});

test("log event takes device, IP, country and ASN from the request", () => {
  const req = new Request("https://api.example.com/v1/score", {
    method: "POST",
    headers: { "x-tt-device": "d".repeat(32), "cf-connecting-ip": "9.9.9.9", "cf-ipcountry": "IN" },
  });
  const ev = logEvent(req, { status: 200, verdict: "KILL" });
  assert.deepEqual(
    { device: ev.device, ip: ev.ip, country: ev.country, path: ev.path, source: ev.source, verdict: ev.verdict },
    { device: "d".repeat(32), ip: "9.9.9.9", country: "IN", path: "/v1/score", source: "cf", verdict: "KILL" },
  );
});

test("body hash matches SHA-256", async () => {
  assert.equal(await sha256hex(new TextEncoder().encode("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
