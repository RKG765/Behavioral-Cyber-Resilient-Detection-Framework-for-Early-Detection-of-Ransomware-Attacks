# Integration tests to run after deployment

Everything here is built and unit-tested (or compiles), but has **not run against real Cloudflare,
real AWS or a real installed agent**. Run these once the pieces are integrated; tick each one and note
the date and result.

Each item lists what to check and how. "Agent" means the service running as SYSTEM with
`EDR_CLOUD_ENDPOINTS`, `EDR_LICENCE_KEY` and `EDR_SERVER_PUBKEY` set.

## Step 1: Tier-2 scorer

- [ ] **Worker request handling in the real runtime.** `npx wrangler dev`, then POST a good body
  (200 + verdict), bad JSON (400), 98 features (400) and a wrong path (404). So far only the scoring
  code has run, as WASM in Node.
- [ ] **WASM scoring inside Workers** gives the same verdicts as `parity_check.py` (send dataset rows
  107 → KILL and 3 → BENIGN).
- [ ] **Wrangler build command** (`[build]` in `worker/wrangler.toml`) works on the deploy machine / CI.
- [ ] **Lambda arm64 build:** `cargo lambda build --release --arm64 --features lambda --bin lambda`
  succeeds, and the `bootstrap` zip starts on `provided.al2023`.
- [ ] **Real latency:** end-to-end round trip from a PC in each target region, to the Worker and to the
  CloudFront fallback (p50 / p99), plus Lambda cold-start time.

## Step 2: device identity and signing

- [ ] **Machine-scope TPM key as SYSTEM:** `DeviceKey()` (default `machine=True`) creates and reuses
  the key when the agent runs as SYSTEM. Only user scope was tested. The device id must stay the
  same across agent restarts and reboots.
- [ ] **Software-key fallback** on a PC without a TPM (or with the TPM disabled): `kind == "software"`,
  and the console shows lower trust.
- [ ] **Register end to end:** agent → Worker → CloudFront → Lambda. The licence seat is taken once
  (`used` +1), the device item is written with `first_ip`, the KV entry appears, and the reply is
  signed. Re-registering must not take another seat.
- [ ] **Licence errors:** unknown licence → 403, full licence → 403; no device item written.
- [ ] **DynamoDB conditional writes:** the `ConditionalCheckFailed` paths for the seat update and
  the device put behave as coded (needs real DynamoDB, or DynamoDB Local).
- [ ] **Cloudflare KV publish from Lambda:** the PUT to the KV API with the scoped token succeeds,
  and a failure returns 502 and is fixed by the next register.
- [ ] **Worker reads KV** (`cacheTtl: 60`): a newly registered device can score within about a
  minute everywhere.
- [ ] **Revocation:** set `status = revoked` in KV and DynamoDB → both scorers return 403 within
  about a minute; register returns 403.
- [ ] **Ed25519 in the Workers runtime:** reply signatures made by the Worker verify in the agent
  (only tested with Node's WebCrypto).
- [ ] **Signed fallback score:** the Lambda's `/v1/score` with a real device returns a signed verdict
  that the agent accepts.
- [ ] **Failover with real errors:** block the Worker hostname (or exceed the cap). The agent switches
  to CloudFront for 10 minutes, then returns to the primary. Check that Cloudflare's daily-cap error
  (1027) arrives as 429 or 5xx, which is what triggers failover.
- [ ] **Clock skew:** a PC whose clock is more than 300 s off gets 401. Decide whether the agent
  should resync or report it.
- [ ] **Replay across isolates:** confirm the impact is only a repeated verdict, until step-5 global
  nonce tracking exists.
- [ ] **TPM signing cost on slower PCs:** measured ~36 ms on the dev PC; check older hardware.

## Step 3: edge protection

- [ ] **Terraform apply** of `infra/cloudflare` and `infra/aws` on real accounts. Only
  `terraform validate` has run.
- [ ] **Cloudflare custom rule:** requests to `api.<domain>/v1/*` without the signature headers, or not
  POST, are blocked at the edge (Security events show them) and never reach the Worker.
- [ ] **Blocked-IP list:** an IP added to `telltale_blocked` gets 403 from Cloudflare within seconds.
- [ ] **Rate-limit rule:** more than the configured requests per 10 s from one IP get blocked for 10 s.
  Confirm the free plan accepts the rule as written (characteristics `cf.colo.id` + `ip.src`).
- [ ] **Free Managed Ruleset** is active on the zone (dashboard → Security → WAF → Managed rules).
- [ ] **Bot Fight Mode stays off** for the API zone, and the agent is never challenged.
- [ ] **TLS settings:** Full (strict), minimum TLS 1.2, Always Use HTTPS, HSTS. Check with an SSL test.
- [ ] **CloudFront → Lambda URL with OAC:** a direct call to the Function URL is refused (403). A call
  through CloudFront with `x-amz-content-sha256` works; without the header it fails.
- [ ] **Origin request policy** forwards the `x-tt-*` headers, `content-type`, `x-amz-content-sha256`
  and the viewer IP/country headers to the Lambda.
- [ ] **CloudFront edge filter function** runs in the real CloudFront runtime with the same results as
  `node --test infra/aws/edge_filter.test.mjs`.
- [ ] **Worker register forwarding through CloudFront:** the Worker's request (with the body hash and
  origin secret) reaches the Lambda, and the client IP header arrives.
- [ ] **Shield Standard** is listed as active for the distribution (automatic, no config).
- [ ] **Free-tier cost check:** after a week of beta traffic, the AWS bill is $0 and the Cloudflare
  usage pages are under the free limits.
