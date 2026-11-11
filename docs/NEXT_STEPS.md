# Next steps (resume here)

State on 2026-11-12.

## Live now
- **Dashboard:** https://haltline-console.pages.dev, behind Cloudflare Access (Zero Trust team
  `foreducation`, app "Haltline SOC console", email list `haltline_admins`: rkg270954@gmail.com and
  rajkumargupta7632@gmail.com, one-time PIN login, 8 h sessions), then the Cognito login (MFA
  required). Pages secrets `AWS_API_URL` and `ORIGIN_SECRET` are set.
- **Admins:** both emails are in the Cognito `admin` group (invited: AWS emailed each a temporary
  password). The **Admins** page adds more (invite + role). Adding them to the Access list happens
  automatically only once a Cloudflare token with *Zero Trust: Edit* is in `secrets.tfvars` as
  `cf_zt_token` (then `terraform apply`); until then add the email to `haltline_admins` in Zero Trust
  by hand.
- **Licences:** the **Licences** page creates keys (shown once). Guide for testers: `docs/BETA.md`.
- **IP blocking:** the **IPs** page block button writes KV `blocked_ips`; the Worker refuses those
  IPs within a minute. The AWS fallback still uses the `blocked_ips` Terraform variable.
- **Lambda** (with Create licence, Admins, KV blocking) and **Worker** (block list) redeployed;
  live attack tests pass except the parallel flood check below.

## To do
1. **First sign-in (you):** open the dashboard, enter the Access code from your email, then the
   temporary password from the AWS email, set a new password (14+ characters) and an authenticator
   app. Then Licences → Create licence works for real.
2. **Install the exe on this PC** (licence in `build\licence-this-pc.txt`); check the PC appears
   under Devices with its IP.
3. **Release asset:** `build\Haltline-Setup-0.2.0.exe` was rebuilt with the privacy contact; the
   GitHub v0.2.0 asset is the older build until it is re-uploaded.
4. **Per-device rate limit is per Worker isolate:** 70 requests over 8 parallel connections all got
   200 in 1 s (one connection gets 429 after ~53). Fix: Cloudflare's rate-limit rule (needs the
   domain) or a Durable Object counter per device.
5. **Beta:** pick testers and follow `docs/BETA.md`.
6. **Later (outside our control or needs money):** domain (WAF + rate-limit rules), CloudFront once
   AWS verifies the account, passkeys once the AWS Terraform provider supports passkey MFA
   (hashicorp/terraform-provider-aws#50110), real code signing (SignPath or a paid certificate).
