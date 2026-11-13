"""
hardening_test.py -- build step 8: attack tests against the LIVE Tier-2 endpoints (plan section 7).

    python tools/hardening_test.py --worker https://<name>.<acct>.workers.dev \
        --lambda https://<id>.lambda-url.<region>.on.aws --server-pubkey <base64 Ed25519> \
        --kv-namespace <DEVICES KV id> [--region ap-south-1] [--prefix haltline]

It creates a throwaway licence (1 seat) and a software device key, registers through the Worker,
runs the attacks, then deletes everything it wrote (licence, device, KV entry, log, report and IP
rows). About 150 requests: well inside the free daily quotas. Needs the AWS CLI (DynamoDB access)
and `npx wrangler` logged in (KV writes for the revocation test). Exit code 0 = every check passed.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


class Device:
    """A software P-256 key signing exactly like agent.CloudClient (protocol: tier2_scorer/README.md)."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.id = hashlib.sha256(self.pub).hexdigest()[:32]

    def headers(self, path, raw, stamp=None, nonce=None, sign_body=None):
        stamp = str(int(time.time()) if stamp is None else stamp)
        nonce = nonce or os.urandom(16).hex()
        h = hashlib.sha256(raw if sign_body is None else sign_body).hexdigest()
        msg = "\n".join(("TT1", "POST", path, self.id, stamp, nonce, h)).encode()
        r, s = utils.decode_dss_signature(self.key.sign(msg, ec.ECDSA(hashes.SHA256())))
        return {"content-type": "application/json", "x-tt-device": self.id, "x-tt-time": stamp, "x-tt-nonce": nonce,
                "x-amz-content-sha256": hashlib.sha256(raw).hexdigest(),
                "x-tt-sig": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()}


def body(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def features():
    return {"features": [round(random.random(), 4) for _ in range(99)]}


def aws(region, *args):
    out = subprocess.run(["aws", "--region", region, "--output", "json", *args], capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f"aws {' '.join(args[:2])}: {out.stderr.strip()}")
    return json.loads(out.stdout) if out.stdout.strip() else {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", required=True)
    ap.add_argument("--lambda", dest="lam", required=True)
    ap.add_argument("--server-pubkey", required=True)
    ap.add_argument("--kv-namespace", required=True)
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--prefix", default="haltline")
    a = ap.parse_args()
    worker, lam = a.worker.rstrip("/"), a.lam.rstrip("/")
    server = Ed25519PublicKey.from_public_bytes(base64.b64decode(a.server_pubkey))
    T = {k: f"{a.prefix}_{k}" for k in ("devices", "licences", "events", "index")}
    dev = Device()
    licence = "hardening-" + os.urandom(12).hex()
    licence_hash = hashlib.sha256(licence.encode()).hexdigest()
    s = requests.Session()   # keep-alive: replay and flood checks reach the same Worker isolate

    def post(base, path, raw, headers):
        return s.post(base + path, data=raw, headers=headers, timeout=15)

    def signed_ok(r, nonce):
        try:
            server.verify(base64.b64decode(r.headers.get("x-tt-resp-sig", "")), r.content)
            return r.json().get("nonce") == nonce
        except Exception:
            return False

    print(f"device {dev.id}, licence hash {licence_hash[:12]}...")
    aws(a.region, "dynamodb", "put-item", "--table-name", T["licences"], "--item",
        json.dumps({"licence_hash": {"S": licence_hash}, "seats": {"N": "1"}, "used": {"N": "0"}}))
    try:
        # ── setup: register through the Worker (Worker -> Lambda -> DynamoDB + KV) ──
        raw = body({"licence_key": licence, "key_kind": "software", "public_key": base64.b64encode(dev.pub).decode()})
        h = dev.headers("/v1/register", raw)
        r = post(worker, "/v1/register", raw, h)
        check("register through the Worker (signed reply)", r.status_code == 200 and signed_ok(r, h["x-tt-nonce"]), f"HTTP {r.status_code}")
        other = Device()
        raw2 = body({"licence_key": licence, "key_kind": "software", "public_key": base64.b64encode(other.pub).decode()})
        h2 = other.headers("/v1/register", raw2)
        r = post(worker, "/v1/register", raw2, h2)
        # Refused with a signed {"licence": "full"} (the agent stops on it), not a plain 403.
        check("a second device on a 1-seat licence is refused (signed licence=full)",
              r.status_code == 200 and signed_ok(r, h2["x-tt-nonce"]) and r.json().get("licence") == "full",
              f"HTTP {r.status_code} {r.text[:80]}")
        time.sleep(2)

        # ── a normal score, on both paths ──
        for name, base in (("Worker", worker), ("Lambda", lam)):
            raw = body(features())
            h = dev.headers("/v1/score", raw)
            r = post(base, "/v1/score", raw, h)
            keys = sorted(r.json()) if r.status_code == 200 else []
            check(f"score via {name}: 200, signed, verdict only (no probability)",
                  r.status_code == 200 and signed_ok(r, h["x-tt-nonce"]) and keys == ["nonce", "request_id", "verdict"],
                  f"HTTP {r.status_code} {keys}")

        # ── forged and replayed requests ──
        for name, base in (("Worker", worker), ("Lambda", lam)):
            raw = body(features())
            h = dev.headers("/v1/score", raw)
            first = post(base, "/v1/score", raw, h).status_code
            again = post(base, "/v1/score", raw, h).status_code
            check(f"replay via {name}: the same signed request twice is refused", first == 200 and again == 401, f"{first} then {again}")
            r = post(base, "/v1/score", raw, dev.headers("/v1/score", raw, stamp=int(time.time()) - 400))
            check(f"stale timestamp via {name} (400 s old)", r.status_code == 401, f"HTTP {r.status_code}")
            r = post(base, "/v1/score", raw, dev.headers("/v1/score", raw, sign_body=body(features())))
            check(f"edited body via {name} (signature over another body)", r.status_code == 401, f"HTTP {r.status_code}")
            thief = Device()
            thief.id = dev.id   # claims our device ID but holds a different key
            r = post(base, "/v1/score", raw, thief.headers("/v1/score", raw))
            check(f"stolen device ID with the wrong key via {name}", r.status_code == 401, f"HTTP {r.status_code}")
            r = post(base, "/v1/score", raw, Device().headers("/v1/score", raw))
            check(f"unregistered key via {name}", r.status_code == 401, f"HTTP {r.status_code}")
            r = s.post(base + "/v1/score", data=raw, headers={"content-type": "application/json"}, timeout=15)
            check(f"unsigned request via {name}", r.status_code in (401, 403), f"HTTP {r.status_code}")

        # ── synthetic vectors (mass querying to copy the model) ──
        codes = []
        for _ in range(5):
            raw = body({"features": [random.uniform(-1e6, 1e6) for _ in range(99)]})
            r = post(worker, "/v1/score", raw, dev.headers("/v1/score", raw))
            codes.append(r.status_code)
            if r.status_code == 200 and sorted(r.json()) != ["nonce", "request_id", "verdict"]:
                codes.append("leak")
        check("synthetic out-of-range vectors get a verdict only, nothing more", "leak" not in codes, str(codes))

        # ── flood: one device, more than RATE_PER_MIN (60) a minute ──
        # In parallel: one at a time can take over a minute and straddle two counting windows.
        from concurrent.futures import ThreadPoolExecutor

        def one(_):
            raw = body(features())
            return post(worker, "/v1/score", raw, dev.headers("/v1/score", raw)).status_code
        started = time.time()
        with ThreadPoolExecutor(8) as pool:
            statuses = list(pool.map(one, range(70)))
        n429 = statuses.count(429)
        check("flood: the per-device limit (60/min) answers 429", n429 > 0, f"{statuses.count(200)} x 200, {n429} x 429 "
              f"in {time.time() - started:.0f} s (counted per Worker isolate, so a few more than 60 can pass)")

        # ── origin bypass: AWS directly, skipping Cloudflare ──
        fake = {"content-type": "application/json", "x-tt-origin-secret": "guess", "x-amz-content-sha256": hashlib.sha256(b"{}").hexdigest()}
        for path in ("/v1/register", "/v1/report", "/internal/log"):
            r1 = requests.post(lam + path, data=b"{}", headers={"content-type": "application/json"}, timeout=15)
            r2 = requests.post(lam + path, data=b"{}", headers=fake, timeout=15)
            check(f"origin bypass: {path} on the Lambda URL looks absent", r1.status_code == 404 and r2.status_code == 404,
                  f"no secret {r1.status_code}, wrong secret {r2.status_code}")
        r = requests.get(lam + "/admin/overview", headers={"x-tt-origin-secret": "guess"}, timeout=15)
        check("origin bypass: /admin/* on the Lambda URL looks absent", r.status_code == 404, f"HTTP {r.status_code}")

        # ── a report, so the device-signed /v1/report path is exercised too ──
        raw = body({"name": "hardening-test.exe", "path": "C:\\Temp\\hardening-test.exe", "sha256": "0" * 64,
                    "reason": "hardening test", "reasons": ["test"]})
        h = dev.headers("/v1/report", raw)
        r = post(worker, "/v1/report", raw, h)
        check("report via the Worker (signed reply)", r.status_code == 200 and signed_ok(r, h["x-tt-nonce"]), f"HTTP {r.status_code}")

        # ── revocation: DynamoDB (Lambda path) and KV (Worker path) ──
        aws(a.region, "dynamodb", "update-item", "--table-name", T["devices"], "--key", json.dumps({"device_id": {"S": dev.id}}),
            "--update-expression", "SET #s = :r", "--expression-attribute-names", '{"#s":"status"}',
            "--expression-attribute-values", '{":r":{"S":"revoked"}}')
        raw = body(features())
        r = post(lam, "/v1/score", raw, dev.headers("/v1/score", raw))
        check("revoked device via Lambda: 403 at once", r.status_code == 403, f"HTTP {r.status_code}")
        kv = {"pk": base64.b64encode(dev.pub).decode(), "status": "revoked", "kind": "software"}
        subprocess.run(["npx", "--yes", "wrangler", "kv", "key", "put", "--remote", "--namespace-id", a.kv_namespace,
                        dev.id, json.dumps(kv)], capture_output=True, encoding="utf-8", errors="replace", shell=True, check=True)
        # The Worker answers a revoked device with a signed {"licence": "revoked"} (the agent stops on it).
        started, ok, code = time.time(), False, None
        while time.time() - started < 90:
            raw = body(features())
            h = dev.headers("/v1/score", raw)
            r = requests.post(worker + "/v1/score", data=raw, headers=h, timeout=15)
            code = r.status_code
            ok = code == 200 and signed_ok(r, h["x-tt-nonce"]) and r.json().get("licence") == "revoked"
            if ok:
                break
            time.sleep(10)
        check("revoked device via Worker: signed licence=revoked within KV propagation (90 s)", ok,
              f"HTTP {code} after {time.time() - started:.0f} s")
    finally:
        cleanup(a, T, dev, licence_hash)

    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


def cleanup(a, T, dev, licence_hash):
    """Delete every row the test wrote: device, licence, KV entry, IP history, log and report rows."""
    print("\ncleanup:")
    time.sleep(5)   # the Worker batches its log rows for ~2 s; let the last batch land first

    def key(k):
        return json.dumps({kk: {"S": v} for kk, v in k.items()})
    try:
        aws(a.region, "dynamodb", "delete-item", "--table-name", T["devices"], "--key", key({"device_id": dev.id}))
        aws(a.region, "dynamodb", "delete-item", "--table-name", T["licences"], "--key", key({"licence_hash": licence_hash}))
        rows = aws(a.region, "dynamodb", "query", "--table-name", T["index"], "--key-condition-expression", "pk = :p",
                   "--expression-attribute-values", json.dumps({":p": {"S": f"d#{dev.id}"}}))["Items"]
        for row in rows:
            ip = row["sk"]["S"][3:]
            aws(a.region, "dynamodb", "delete-item", "--table-name", T["index"], "--key", key({"pk": f"d#{dev.id}", "sk": f"ip#{ip}"}))
            aws(a.region, "dynamodb", "delete-item", "--table-name", T["index"], "--key", key({"pk": f"i#{ip}", "sk": f"d#{dev.id}"}))
        day = time.strftime("%Y-%m-%d", time.gmtime())
        n = 0
        for prefix in ("e", "r"):
            items = aws(a.region, "dynamodb", "query", "--table-name", T["events"], "--key-condition-expression", "pk = :p",
                        "--filter-expression", "device = :d", "--expression-attribute-values",
                        json.dumps({":p": {"S": f"{prefix}#{day}"}, ":d": {"S": dev.id}}))["Items"]
            for it in items:
                aws(a.region, "dynamodb", "delete-item", "--table-name", T["events"], "--key", key({"pk": it["pk"]["S"], "sk": it["sk"]["S"]}))
                n += 1
        subprocess.run(["npx", "--yes", "wrangler", "kv", "key", "delete", "--remote", "--namespace-id", a.kv_namespace, dev.id],
                       capture_output=True, encoding="utf-8", errors="replace", shell=True)
        print(f"  deleted device, licence, KV entry, {len(rows)} IP row pair(s), {n} log/report row(s)")
    except Exception as e:
        print(f"  CLEANUP INCOMPLETE: {e}  (device {dev.id}, licence hash {licence_hash})")


if __name__ == "__main__":
    sys.exit(main())
