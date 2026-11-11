# Next steps (resume here)

State on 2026-11-12, end of session.

## Fixed and live today
- **Dashboard sign-in loop:** two causes, both fixed. (1) The first Pages deploy skipped the
  `/admin/*` Function (deploy from inside `console/`). (2) The Cognito app client could read
  `email` but not `email_verified`, so Cognito refused every token (`invalid_grant`); now
  `read_attributes = ["email", "email_verified"]`, verified with a real code exchange.
- **Sign-in card** now says why a sign-in failed and offers **Start over**.
- **Per-device rate limit:** the Worker now also uses Cloudflare's rate-limiting binding
  (`DEVICE_LIMIT`, 60/60 s, shared by all isolates in a location). Live: 15 of 70 parallel
  requests refused; attack tests 25/25.
- **Lambda dependencies:** legacy rustls 0.21 / h2 0.3 removed (AWS SDK default features off),
  p256 0.14 (patched crypto-bigint). `cargo audit`: 0 vulnerabilities (1 "unmaintained" notice:
  pin-utils). Redeployed; attack tests 25/25.

## Done in code, not shipped yet
1. **Agent 0.2.1 security build** (`packaging\build.ps1` was running at the end of the session;
   check `build\build.log` ends with `exit=0`, else re-run it). Contains: Python packages
   upgraded (`pip-audit`: 0 known vulnerabilities in requirements.txt), sensor on pyo3 0.29
   (`cargo audit`: 0), and the licence key moved out of the registry into
   `C:\ProgramData\Telltale\licence.key` (SYSTEM and Administrators only). Agent tests 37/37.
2. **Publish 0.2.1:** new GitHub pre-release `v0.2.1` with the new installer (needs your OK to push
   and publish).

## Your steps
3. **Sign in** at https://haltline-console.pages.dev (Cloudflare email code, then AWS password +
   authenticator). Then check the **AWS** and **Cloudflare** pages show live numbers, and try
   **Licences → Create licence**.
4. **rajkumargupta7632@gmail.com** has never signed in: use the AWS invite email (temporary
   password) within 7 days, or add again from the Admins page.
5. **Install the exe** on this PC (key in `build\licence-this-pc.txt`) and check it appears under
   Devices with its IP.
6. **Docker Desktop error** (not caused by this project): restart Windows, or delete
   `%LOCALAPPDATA%\Docker\run\dockerInference` with Docker closed, or turn off Docker Model Runner.

## Open security items
7. **Cloudflare token for the Admins page** (optional): a token with *Zero Trust: Edit* as
   `cf_zt_token` in `infra/aws/secrets.tfvars`, then `terraform apply`, so new admins are added to
   the Access list automatically.
8. **AWS fallback path** (Lambda URL) keeps its own per-container rate limit and IP list
   (`blocked_ips` Terraform variable); fine while it is only a fallback.
9. **Burp Suite / interception:** the agent pins 13 root CAs, so a Burp CA is refused; requests are
   device-signed and replies server-signed, so edited or replayed traffic is rejected. The payload
   inside TLS is not separately encrypted (only behaviour numbers and IDs). In the admin's own
   browser, whoever controls that browser can always read their own session.

## Later (outside our control or needs money)
10. Domain (WAF + Cloudflare rate-limit rules), CloudFront once AWS verifies the account, passkeys
    once the AWS Terraform provider supports passkey MFA (#50110), real code signing (SignPath or a
    paid certificate), and the beta group (`docs/BETA.md`).
