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
- [ ] **Free plan accepts the custom rule's header check.** `terraform apply` on a real free-plan zone
  must accept `any(http.request.headers.names[*] eq "x-tt-sig")`. `terraform validate` only checks
  structure, not which fields each plan allows. If it's refused, fall back to the Worker's own
  signature check (costs Worker quota under a flood).
- [ ] **Free plan accepts the rate-limit counting.** The same apply must accept counting by
  `cf.colo.id` + `ip.src` (IP plus data centre). If it's refused, adjust `infra/cloudflare/main.tf`
  to what the free plan allows.
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

## Step 4: ask mode (alert and ask, no suspension)

- [ ] **Installer:** `install_windows.ps1` (default `-Mode ask`) creates `C:\ProgramData\Telltale\alerts`
  and `decisions`, with ACLs as written: SYSTEM and Admins full; interactive users read `alerts` and
  write `decisions`. The `Telltale-Helper` logon task starts the helper unelevated for every user.
- [ ] **Dialog in a real session:** a detected threat makes the window appear on top for the
  signed-in user, with the app name, path, reasons and detection line. Only a build check has run;
  nobody has clicked it yet.
- [ ] **Buttons as SYSTEM:** Close app closes the flagged app, including an elevated one. Run anyway
  keeps it running. Send report adds a line to `reports_outbox.jsonl` and keeps the dialog open.
- [ ] **Queue and reminders:** several alerts show one at a time. A window closed with ✕ comes back
  after 10 minutes.
- [ ] **No user signed in:** alerts wait in the folder and appear at the next logon. Decide whether
  that wait is acceptable, or whether high-confidence threats need another rule.
- [ ] **Multiple users signed in (fast user switching):** each session's helper shows the alert. The
  first answer wins, and the others' answers are ignored because the alert file is already gone.
- [ ] **Packaging:** `tkinter` is included in the Nuitka build of the helper.
- [ ] **Time to decide:** measure how long real users take to answer. The app keeps running until
  then; suspension, the safer option, is not built.

## Step 5: admin SOC console

Built: the Lambda's `/v1/report`, `/internal/log` and `/admin/*`, the Worker's request log, the
console and its Pages Function, and the Terraform in `infra/` (tables, IAM, Cognito, the `/admin/*`
CloudFront behaviour, Pages, Access). Tested: Rust, Worker, agent and edge-filter unit tests,
`terraform validate` for both folders, and the console rendered against local sample data. Nothing
below has run on real accounts.

- [ ] **Terraform apply** of the step-5 resources in both folders: the two new tables, the Cognito
  pool, client, groups, domain and managed-login branding, the admin origin request policy and
  `/admin/*` behaviour, the Pages project, domain and CNAME, the Access list, policy and application.
- [ ] **DynamoDB free tier:** the four tables total 22 RCU / 23 WCU, and the account has no other
  provisioned tables in that region (the 25 / 25 allowance is per region, account-wide).
- [ ] **Write capacity under load:** every Worker request writes a log row (plus two index rows and a
  device update when verified). At 10 WCU on events, watch for throttling in a busy minute; the plan's
  SQS buffer is not built. Throttled log writes are dropped, scoring is not affected.
- [ ] **TTL:** `telltale_events` rows disappear about 90 days after `expires` (DynamoDB deletes within
  a few days of expiry). `telltale_index` rows have no TTL yet.
- [ ] **Cognito Essentials tier** is accepted, and stays at $0 for the admin user count.
- [ ] **Passkey sign-in** through managed login v2: an admin can add a passkey after the first
  password sign-in and then sign in with it. The relying party ID is the `amazoncognito.com`
  prefix domain.
- [ ] **TOTP enrolment:** with MFA set to optional (required for passkeys), confirm managed login
  lets an admin set up an authenticator app. If it doesn't, the console needs an enrolment step.
- [ ] **Password-only login:** MFA is optional, so a user without a passkey or TOTP can sign in with
  just a password, and the Lambda doesn't check how they signed in. Decide whether to require it
  (for example an `amr` / pre-token check).
- [ ] **Admin-only accounts:** the managed-login page offers no sign-up and no self-service password
  reset.
- [ ] **Token lifetimes:** ID tokens expire after 15 minutes. Step-up (`prompt=login`) gives a fresh
  `auth_time`, and admin POSTs older than 5 minutes get 401.
- [ ] **PKCE from the browser:** the console's token exchange at `<cognito domain>/oauth2/token` works
  from `admin.<domain>` (CORS) with the CSP in `console/_headers`.
- [ ] **Access in front of Pages:** `admin.<domain>`, `telltale-console.pages.dev` and preview URLs
  all ask for the Access login. Only `admin_emails` get through.
- [ ] **Access JWT reaches the Lambda:** the Pages Function receives `cf-access-jwt-assertion` and
  forwards it, the `/admin/*` behaviour passes it on with `x-tt-admin-token` and the query string,
  and the Lambda accepts it against `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD`.
- [ ] **Same person on both layers:** an Access login as A plus a Cognito login as B gets 401.
- [ ] **Roles:** `viewer` can't see reports or act, `analyst` sees reports, `admin` can revoke,
  restore, block and unblock. Each action shows up in the audit view.
- [ ] **Revoke / restore:** the device's KV entry changes, and the Worker refuses (or accepts) it
  within KV's propagation time.
- [ ] **IP block:** the IP is added to `telltale_blocked` with the `CF_LISTS_TOKEN` and gets 403 at
  Cloudflare. The AWS fallback still uses the `blocked_ips` Terraform variable.
- [ ] **Edge filter:** in the real CloudFront runtime, `/v1/report`, `/internal/log` and `/admin/*`
  pass only with the origin secret (and the body hash on POST).
- [ ] **Custom rule allows `/v1/report`:** a signed report through `api.<domain>` reaches the Worker
  (the rule and the rate limit now include it).
- [ ] **Request log:** Worker requests appear in the Events view with IP, country and status, and
  rejected floods are sampled per IP rather than logged one by one.
- [ ] **Agent reports:** Send report in the dialog reaches the Reports view, and an offline report is
  uploaded from the outbox later.
