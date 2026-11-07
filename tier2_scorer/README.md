# tier2_scorer: the Tier-2 model in Rust

One crate, two scorers (plan: `docs/PROD_ARCHITECTURE.md`, build step 1):

- **AWS Lambda** (native): `src/bin/lambda.rs`, built with `--features lambda`
- **Cloudflare Worker** (WASM): `../worker/src/index.js` loads the crate built for `wasm32-unknown-unknown`

Both serve `POST /v1/score` with `{"features": [99 numbers]}` and return
`{"verdict": "KILL" | "BENIGN", "request_id": "...", "nonce": "..."}`. Every request must be signed
by a registered device key, and every reply is signed by the server (build step 2).

## Protocol (v1)

**Requests** (`/v1/score`, `/v1/register`) carry these headers:

| Header | Value |
|---|---|
| `x-tt-device` | device id: first 32 hex chars of SHA-256(device public key, SEC1 uncompressed) |
| `x-tt-time` | Unix seconds; must be within ±300 s of the server clock |
| `x-tt-nonce` | 32 random hex chars, single use |
| `x-tt-sig` | base64 ECDSA P-256 signature, raw r‖s, over SHA-256 of the canonical string |

Canonical string (newline-separated):

```
TT1
POST
<path>
<x-tt-device>
<x-tt-time>
<x-tt-nonce>
<hex SHA-256 of the exact body bytes>
```

**Replies** carry `x-tt-resp-sig`: a base64 Ed25519 signature over the exact reply body. The body
echoes the request's `nonce`. The agent rejects any reply that isn't signed by its pinned server key
or doesn't echo its nonce.

**`POST /v1/register`** (Cloudflare only; the Worker adds the origin secret), body
`{"licence_key", "public_key": base64 SEC1, "key_kind": "tpm"|"software"}`, signed with that key.
Reply: `{"device_id", "nonce"}`. Registering is idempotent. It takes one licence seat the first time
and publishes `device_id -> {"pk", "status"}` to Workers KV.

**Errors:** 400 bad body, 401 bad or missing signature, stale time, replay or unknown device,
403 revoked device or licence invalid/full, 429 more than 60 requests per device per minute,
502 edge publish failed (retry register). Error replies are not signed.

## Setup

1. **Server signing key** (run once, keep the seed secret):
   ```bash
   python -c "import os,base64;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K;from cryptography.hazmat.primitives import serialization as s;seed=os.urandom(32);pub=K.from_private_bytes(seed).public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw);print('RESPONSE_SIGNING_SEED =',base64.b64encode(seed).decode());print('EDR_SERVER_PUBKEY     =',base64.b64encode(pub).decode())"
   ```
   The seed goes to the Worker secret and the Lambda env; the public key goes into the agent.
2. **Origin secret:** `python -c "import secrets;print(secrets.token_urlsafe(32))"` goes to the Worker
   secret `ORIGIN_SECRET` and the Lambda env `ORIGIN_SECRET`.
3. **DynamoDB (provisioned mode):**
   - `DEVICES_TABLE`, key `device_id` (S): items `{device_id, pk, kind, status, licence_hash, first_ip, created_at}`.
   - `LICENCES_TABLE`, key `licence_hash` (S): items `{licence_hash, seats (N), used (N)}`.
   Licence keys are stored only as their SHA-256 hex. To add one:
   ```bash
   aws dynamodb put-item --table-name <LICENCES_TABLE> --item '{"licence_hash":{"S":"<sha256 hex of the key>"},"seats":{"N":"3"},"used":{"N":"0"}}'
   ```
4. **Lambda env:** `DEVICES_TABLE`, `LICENCES_TABLE`, `RESPONSE_SIGNING_SEED`, `ORIGIN_SECRET`,
   `CF_ACCOUNT_ID`, `CF_KV_NAMESPACE`, `CF_API_TOKEN` (a Cloudflare token with *Workers KV Storage:
   Edit* only). The IAM role needs `dynamodb:GetItem`, `PutItem` and `UpdateItem` on the two tables.
5. **Agent env:** `EDR_CLOUD_ENDPOINTS=https://api.<domain>,https://<id>.cloudfront.net` (primary
   first), `EDR_LICENCE_KEY`, `EDR_SERVER_PUBKEY`. Without these the agent keeps using the local
   `server.py`.

## Weights

`weights.bin` is generated from `tier2_behavioral.pt`, with BatchNorm folded into the dense layers,
plus the threshold. Re-run this after retraining:

```bash
python tier2_scorer/export_weights.py
```

## Check

```bash
cargo test --release --features lambda --manifest-path tier2_scorer/Cargo.toml
cargo build --release --lib --target wasm32-unknown-unknown --manifest-path tier2_scorer/Cargo.toml
python tier2_scorer/parity_check.py
node --test worker/test/auth.test.mjs
```

The AWS SDK's newest releases need a newer Rust than 1.92. `Cargo.lock` pins versions that build on
1.92 (resolved with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo update`).

`parity_check.py` compares the native and WASM builds with PyTorch on all 1,470 dataset rows.
Last run: max |diff| 6.3e-7, no verdict flips, about 9-11 µs per score natively.

## Deploy (needs your accounts; not run yet)

- **Lambda (arm64):** install `cargo-lambda`, then
  `cargo lambda build --release --arm64 --features lambda --bin lambda`.
  Deploy the `bootstrap` zip as a `provided.al2023` function with a Function URL, fronted by
  CloudFront (plan section 3.2).
- **Worker:** `cd worker && npx wrangler dev` to try it locally, then `npx wrangler deploy`.
  Wrangler runs the WASM build itself (see `wrangler.toml`).
