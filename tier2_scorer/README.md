# tier2_scorer: the Tier-2 model in Rust

One crate, two scorers (plan: `docs/PROD_ARCHITECTURE.md`, build step 1):

- **AWS Lambda** (native): `src/bin/lambda.rs`, built with `--features lambda`
- **Cloudflare Worker** (WASM): `../worker/src/index.js` loads the crate built for `wasm32-unknown-unknown`

Both serve `POST /v1/score` with `{"features": [99 numbers]}` and return
`{"verdict": "KILL" | "BENIGN", "request_id": "...", "nonce": "..."}`. Every request must be signed
by a registered device key, and every reply is signed by the server (build step 2).

## Protocol (v1)

**Device requests** (`/v1/score`, `/v1/register`, `/v1/report`) carry these headers:

| Header | Value |
|---|---|
| `x-tt-device` | device id: first 32 hex chars of SHA-256(device public key, SEC1 uncompressed) |
| `x-tt-time` | Unix seconds; must be within ±300 s of the server clock |
| `x-tt-nonce` | 32 random hex chars, single use |
| `x-tt-sig` | base64 ECDSA P-256 signature, raw r‖s, over SHA-256 of the canonical string |
| `x-amz-content-sha256` | hex SHA-256 of the body; CloudFront OAC requires it on the AWS path (sent on both paths) |

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

**`POST /v1/report`** (Cloudflare only, signed like score), body
`{"name", "path", "sha256", "reason", "reasons": [..]}`: a file the user sent for review from the ask
dialog. Saved to the events table (90 days); the console's Reports view lists it.

**`POST /internal/log`** (Worker only, origin secret, unsigned): a JSON array of up to 100 log
events. The Worker batches them (every ~2 s, or at 50 events) so this runs a few times a minute rather
than once per request. Each event is one events row; verified 200s also update the IP history and the
device's `last_seen`, once per device + IP in the batch.

**`GET|POST /admin/*`** (console only: Pages Function → CloudFront, origin secret): needs **both**
the Cloudflare Access JWT (`cf-access-jwt-assertion`) and the Cognito ID token (`x-tt-admin-token`),
for the same email. Roles come from Cognito groups: `viewer` reads, `analyst` also reads reports,
`admin` also revokes/restores devices and blocks/unblocks IPs, and those POSTs need a login in the
last 5 minutes. Every action is audited. Reads: `overview`, `devices`, `devices/<id>`, `ips`,
`events`, `reports`, `audit` (those three take `?day=YYYY-MM-DD`), `licences`. Actions:
`devices/<id>/revoke|restore`, `ips/<ip>/block|unblock`.

**Cloud pages** (viewer role, plan 6.3): `metrics/aws?range=1h|6h|24h[&q=<filter pattern>]` and
`metrics/cloudflare?range=…`. The Lambda reads CloudWatch (`GetMetricStatistics`, one call per
metric, run concurrently; CloudFront metrics from us-east-1) and CloudWatch Logs (`FilterLogEvents`,
first 100 matches of `q`), or one Cloudflare GraphQL Analytics query. Each result is cached for 60 s
per Lambda container, shared by all admins. The reply has `rpm` (requests per minute with the
indexes of spikes: robust z-score > 3.5 on the median / MAD), `panels`, free-quota `quotas`, and
`tables` (Cloudflare) or `logs` (AWS). 400 for another range, 502 when the cloud API fails, 503 when
Cloudflare analytics isn't configured. `GetMetricData` is not used: it is billed from the first
metric, while `GetMetricStatistics` is inside the free tier's 1M API requests.

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
   - `EVENTS_TABLE`, key `pk` (S) + `sk` (S), TTL attribute `expires`: request log (`e#<day>`),
     reports (`r#<day>`) and audit (`a#<day>`), each row kept 90 days.
   - `INDEX_TABLE`, key `pk` (S) + `sk` (S): IP history, `d#<device>` → `ip#<ip>` and back.
   `infra/aws` creates all four within the free 25 RCU / 25 WCU. Licence keys are stored only as
   their SHA-256 hex. To add one:
   ```bash
   aws dynamodb put-item --table-name <LICENCES_TABLE> --item '{"licence_hash":{"S":"<sha256 hex of the key>"},"seats":{"N":"3"},"used":{"N":"0"}}'
   ```
4. **Lambda env** (`infra/aws` sets all of it):

   | Variable | Value |
   |---|---|
   | `DEVICES_TABLE`, `LICENCES_TABLE`, `EVENTS_TABLE`, `INDEX_TABLE` | table names |
   | `RESPONSE_SIGNING_SEED`, `ORIGIN_SECRET` | from steps 1 and 2 |
   | `CF_ACCOUNT_ID`, `CF_KV_NAMESPACE`, `CF_API_TOKEN` | KV publish; the token has *Workers KV Storage: Edit* only |
   | `CF_LIST_ID`, `CF_LISTS_TOKEN` | the `telltale_blocked` IP list; the token has *Account Filter Lists: Edit* only |
   | `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | Zero Trust team domain (`<team>.cloudflareaccess.com`) and the console's Access application audience tag |
   | `COGNITO_ISSUER`, `COGNITO_CLIENT_ID` | `https://cognito-idp.<region>.amazonaws.com/<pool id>` and the console's app client |
   | `DDB_CAPACITY` | `{"<table>": [RCU, WCU]}`: the tables the AWS page charts and their provisioned capacity |
   | `CF_ANALYTICS_TOKEN`, `CF_ZONE_ID`, `CF_WORKER_SCRIPT` | Cloudflare page; the token has *Account Analytics: Read* and *Zone Analytics: Read* only. Optional: empty turns the page off |
   | `CLOUDFRONT_DISTRIBUTION_ID`, `SQS_QUEUE` | optional panels on the AWS page; empty hides them (there is no queue today) |

   The IAM role needs `dynamodb:GetItem`, `PutItem`, `UpdateItem` and `Scan` on devices and
   licences, and `Query`, `Scan`, `PutItem` and `UpdateItem` on events and index. The Cloud pages add
   `cloudwatch:GetMetricStatistics` (no resource-level permissions, so `*`) and `logs:FilterLogEvents`
   on the function's own log group.
5. **Admins:** add the email to `admin_emails` in `infra/cloudflare` (Access), then create the
   Cognito user and give it a role:
   ```bash
   aws cognito-idp admin-create-user --user-pool-id <pool id> --username you@example.com --user-attributes Name=email,Value=you@example.com Name=email_verified,Value=true
   aws cognito-idp admin-add-user-to-group --user-pool-id <pool id> --username you@example.com --group-name admin
   ```
   On first login, set a password (14+ characters); managed login then makes you set up an
   authenticator app, and every sign-in after that needs its code (MFA is required).
6. **Agent env:** `EDR_CLOUD_ENDPOINTS=https://api.<domain>,https://<id>.cloudfront.net` (primary
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
