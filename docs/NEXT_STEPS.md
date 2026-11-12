# Next steps (resume here)

State on 2026-11-13. **AWS profile:** the CLI's `default` profile belongs to another account
(352285845006); Haltline (476932321316) is the **`haltline`** profile. Prefix every AWS command:
`AWS_PROFILE=haltline` (or `--profile haltline`). Sign in again with
`aws login --profile haltline --region ap-south-1`.
**Build quirks:** `cargo lambda` lives in `%APPDATA%\Python\Python310\Scripts` and needs Zig on PATH
(`%APPDATA%\Python\Python310\site-packages\ziglang`; `python3` is the Store stub, so it can't find it
alone); add `--output-format zip`, or Terraform deploys the old `bootstrap.zip`.

## Deployed 2026-11-13 (items 1-3, 5)
Lambda + IAM (`terraform apply`: 3 changed, 0 added/destroyed), dashboard (Pages), Worker.
Live attack tests **24/25**: the second device on a full licence now gets a signed `licence: full`;
revoked devices a signed `licence: revoked` (Worker) / 403 (Lambda score). **Still failing: flood**,
70 parallel requests in 1 s all 200 (Cloudflare's rate-limit binding is eventually consistent and
let the burst through; last session it caught 15/70). Fix: a rate-limit rule on a domain, or a
Durable Object counter. **Item 4 (24h) not applied:** the Access app was made by hand in Zero Trust
(no Terraform state), so change it there: Zero Trust → Access → Applications → Haltline SOC console
→ Edit → Session duration 24 hours.
**Not checked live yet (needs your sign-in):** silent sign-in, Save seats / Delete licence, change
role / Remove admin.

## What changed (for reference)
1. **Licence CRUD** (Lambda + console): list and create already existed; now **Save seats** (never
   below the PCs already using it) and **Delete**. Delete revokes every PC registered with that key
   at the edge first (Tier 2 refuses them), then removes the licence, so the key can't register new
   PCs either. Routes: `POST /admin/licences/{hash}/seats?seats=N`, `POST /admin/licences/{hash}/delete`.
2. **Admin CRUD** (Lambda + console): invite and list already existed; now **change role** and
   **Remove** (deletes the Cognito login, and takes them off the Access list when `cf_zt_token` is
   set). Nobody can change or remove themselves. Routes: `POST /admin/admins/role?email=&role=`,
   `POST /admin/admins/remove?email=`.
3. **Fewer sign-in prompts** (console): on opening the page it asks Cognito silently
   (`prompt=none`). Still signed in to AWS → straight into the dashboard, no "Sign in as" page and
   no Sign in card. No AWS session → straight to the password + authenticator page. The card now
   only shows after an error, a Sign out, or the 15-minute idle sign-out, and explains how new
   admins get in.
4. **Cloudflare email code once a day:** Access session 8h → 24h (`infra/cloudflare/main.tf`).
5. **IAM** for 1–2 (`infra/aws/main.tf`): `dynamodb:DeleteItem` on devices/licences,
   `cognito-idp:AdminRemoveUserFromGroup` and `AdminDeleteUser` on the admin pool.

Checked: `cargo check` clean; console CRUD tried in the local demo (`console/?demo`); no console
errors. **Not checked live:** the silent sign-in (needs real Cognito) and the new routes on AWS.

### Deploy order once the Haltline AWS account is signed in
```
cd tier2_scorer && cargo lambda build --release --arm64 --features lambda --bin lambda
cd infra/aws && terraform apply -var-file=secrets.tfvars          # new zip + IAM
cd infra/cloudflare && terraform apply -var-file=cloudflare.tfvars # Access 24h (no AWS needed)
cd console && npx wrangler pages deploy . --project-name haltline-console --branch main
```
Then on https://haltline-console.pages.dev: reopen the page (should go straight in), Licences →
Save seats and Delete on a test licence, Admins → change role / Remove on a test admin.

## Agent 0.2.1
6. **Build done:** `build\Haltline-Setup-0.2.1.exe` (exit=0, test-signed), SHA-256
   `1152507A88DD3DC33C02C4D0EEE7F89717BC2198AD0FB63DA075D0D12BB7F676` (rebuilt 21:12 with the licence stop). Agent tests 38/38.
   Upgrades from 0.2.0 keep the licence key (moved from the registry to the protected file).
7. **Install on this PC:** the installer was started but not finished (no service yet). Run
   `build\Haltline-Setup-0.2.1.exe`, paste the key from `build\licence-this-pc.txt` (or create a new
   key on the Licences page; keys are shown once), then check it appears under Devices with its IP.
8. **Publish 0.2.1** after 7 works: push `prod`, GitHub pre-release `v0.2.1` with the installer and
   `build\haltline-signing.cer`, notes like 0.2.0's with the new SHA-256.
9. **Deleted/revoked licence stops the exe entirely** (decided 2026-11-12; in code, tested, needs the
   0.2.1 rebuild + Worker/Lambda deploy). The agent checks its licence at start and every 6 hours.
   On a **server-signed** refusal (`licence: revoked | invalid | full`, signed and echoing the request
   nonce) it writes `alerts\licence.status`, stops, and the service ends cleanly (Windows doesn't
   restart it); the helper shows "Haltline is no longer protecting this PC" and why. An unsigned 403,
   a forged signature or no network never stops it. Restoring the device/licence: protection comes
   back at the next restart. Worker: revoked devices get the signed refusal only after their own
   request signature checks out. Lambda `/v1/register`: signed refusal for revoked / deleted
   (invalid) / full. Console texts for Revoke, Restore and Delete licence say this.
   Tests: agent 38/38 (new t38), Worker 10/10, Lambda `cargo check` + unit tests.
   **Rebuild:** close the open 0.2.1 installer, run `packaging\build.ps1`, check `build\build.log`
   ends `exit=0`; the SHA-256 in item 6 changes. **Worker deployed** 2026-11-12 (version
   88f3119b; unknown device still 401). `tools/hardening_test.py` now expects the signed
   `licence: revoked` from the Worker; run it once the Haltline AWS account is back (it needs the
   AWS CLI).

## Your steps
10. **rajkumargupta7632@gmail.com** has never signed in: use the AWS invite email (temporary password,
    valid 1 day per `temporary_password_validity_days`), or remove and add again from the Admins page.
11. **Docker Desktop error** (not caused by this project): restart Windows, or delete
    `%LOCALAPPDATA%\Docker\run\dockerInference` with Docker closed, or turn off Docker Model Runner.

## How sign-in works for admins (answers to questions)
- **First sign-in (once):** the AWS invite email has a temporary password. Cognito forces a new
  password, then shows a **QR code and the secret key as text** for the authenticator app (scan or
  type the code). That setup happens once.
- **Every time after:** Cloudflare email code (once per 24h after deploy), then AWS password + the
  6-digit authenticator code (skipped while the AWS session is still alive), and the console signs
  you out after 15 minutes idle. Admin actions (create/delete/revoke) ask for a fresh authenticator
  check if the last one was over 5 minutes ago.
- **Authenticator-only sign-in (no password):** Cognito can't do it. Its password-free options are
  passkeys, email codes and SMS codes; an authenticator code is only allowed as the second step after
  a password. Passkeys are the way to drop the password, blocked on the Terraform provider (#50110).
- **Sign up:** not offered. The console is invite-only: an admin adds you on the Admins page. Open
  sign-up would let anyone on the Access list create a login without an admin choosing their role.

## Open security items
12. **Cloudflare token for the Admins page** (optional): a token with *Zero Trust: Edit* as
    `cf_zt_token` in `infra/aws/secrets.tfvars`, then `terraform apply`, so added/removed admins
    update the Access list automatically.
13. **AWS fallback path** (Lambda URL) keeps its own per-container rate limit and IP list
    (`blocked_ips` Terraform variable); fine while it is only a fallback.
14. **Burp Suite / interception:** the agent pins 13 root CAs, so a Burp CA is refused; requests are
    device-signed and replies server-signed, so edited or replayed traffic is rejected.

## Later (outside our control or needs money)
15. Domain (WAF + Cloudflare rate-limit rules), CloudFront once AWS verifies the account, passkeys
    once the AWS Terraform provider supports passkey MFA (#50110), real code signing (SignPath or a
    paid certificate), and the beta group (`docs/BETA.md`).
