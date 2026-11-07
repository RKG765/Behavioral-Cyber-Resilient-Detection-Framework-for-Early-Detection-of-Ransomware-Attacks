// node --test worker/test/log.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import { logEvent, sampleReject, sha256hex } from "../src/log.js";

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
