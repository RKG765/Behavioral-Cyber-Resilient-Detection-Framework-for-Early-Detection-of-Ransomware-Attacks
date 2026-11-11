# infra: edge protection and the SOC console as code

Terraform for both clouds (plan: `docs/PROD_ARCHITECTURE.md`, build steps 3, 5 and 6). Only
`terraform validate` has run; the real-account checks are in `docs/INTEGRATION_TESTS.md`.

| Folder | What it creates |
|---|---|
| `aws/` | DynamoDB tables `haltline_devices`, `haltline_licences`, `haltline_events` (TTL `expires`) and `haltline_index` (provisioned, 22 RCU / 23 WCU of the free 25 / 25; `apply` refuses more), the Lambda (IAM-auth function URL) and its env, CloudFront with Origin Access Control plus an `/admin/*` behaviour, the edge-filter CloudFront Function, the Cognito admin pool (Essentials, MFA required: password + authenticator app, admin-created users only, groups `viewer` / `analyst` / `admin`), its public PKCE app client (15-minute tokens) and managed-login domain, a $1 budget alarm, and the Cloud pages' read-only CloudWatch / Logs permissions |
| `cloudflare/` | Zone TLS settings (Full strict, TLS 1.2+, HTTPS only, HSTS), a custom rule that drops unsigned API requests, the blocked-IP list, the one free rate-limit rule, Bot Fight Mode **off**; the `haltline-console` Pages project on `admin.<domain>`, and the Access application (also covering its `pages.dev` names) with a policy for the `admin_emails` list, plus a bypass for certificate checks |

The Worker, its KV namespace and its secrets, and the console's files and secrets, are deployed with
`wrangler`.

## Request paths

| From | Path | Through | Checks before the Lambda |
|---|---|---|---|
| Agent | `/v1/score` | Worker, or CloudFront directly (fallback) | Cloudflare custom rule / edge filter: POST + signature headers |
| Agent | `/v1/register`, `/v1/report` | Worker → CloudFront | custom rule; edge filter: origin secret + body hash |
| Worker | `/internal/log` (batched, ~2 s / 50 events) | CloudFront | edge filter: origin secret + body hash |
| Console | `/admin/*` (GET, POST) | Access → Pages Function → CloudFront | Access login; edge filter: origin secret (+ body hash on POST) |

The Lambda then checks the secret's value, device signatures, and for `/admin/*` both the Access JWT
and the Cognito ID token.

## Order

1. **Domain** on Cloudflare (the only paid item). Note its zone ID and account ID. In Zero Trust,
   pick a team name and a login method (one-time PIN, GitHub or Google).
2. **Worker:** `npx wrangler kv namespace create DEVICES`, put the id in `worker/wrangler.toml`
   along with your domain, then set the secrets (`tier2_scorer/README.md` → Setup).
3. **Cloudflare:** `cd infra/cloudflare && terraform init && terraform apply -var-file=cloudflare.tfvars`
   with `CLOUDFLARE_API_TOKEN` set (permissions at the top of `cloudflare/main.tf`).
   `cloudflare.tfvars` (git-ignored) holds `zone_id`, `account_id`, `api_hostname = "api.<domain>"`,
   `admin_hostname = "admin.<domain>"` and `admin_emails = ["you@example.com"]`.
   Note the outputs `access_aud` and `blocked_list_id`.
4. **AWS:** build the Lambda zip (top of `aws/main.tf`), then
   `cd infra/aws && terraform init && terraform apply -var-file=secrets.tfvars`.
   `secrets.tfvars` (git-ignored) holds `region`, `alert_email`, `response_signing_seed`,
   `origin_secret`, `cf_account_id`, `cf_kv_namespace`, `cf_api_token`, `admin_hostname`,
   `cognito_domain_prefix`, `access_team_domain` (`<team>.cloudflareaccess.com`), `access_aud`,
   and optionally `cf_access_list_id` + `cf_zt_token` (a token with *Zero Trust: Edit* only) so the
   console's Admins page can add emails to the Access list.
   For the Cloud → Cloudflare page also set `cf_zone_id` and `cf_analytics_token` (a token with
   *Account Analytics: Read* and *Zone Analytics: Read* only); without them the page says it isn't
   configured. For the CloudFront panel, apply once more with `cloudfront_distribution_id` set to
   the `cloudfront_distribution_id` output (the Lambda can't reference its own distribution).
5. Put the `api_url` output into the Worker's `AWS_API_URL`, then `npx wrangler deploy`.
   A new AWS account may refuse CloudFront until AWS Support verifies it. Set `cloudfront_enabled = false`
   meanwhile: the Lambda URL becomes public (every route but `/v1/score` still needs the origin secret)
   and `api_url` is the Lambda URL itself. Set it back to `true` after verification and redo step 5.
6. **Console:** put the `cognito_domain` and `cognito_client_id` outputs into `console/config.js`, then
   ```bash
   npx wrangler pages secret put AWS_API_URL --project-name haltline-console    # the api_url output
   npx wrangler pages secret put ORIGIN_SECRET --project-name haltline-console  # same as the Worker's
   cd console && npx wrangler pages deploy . --project-name haltline-console --branch main   # run inside console/, or functions/ is left out
   ```
7. **Admins:** create each Cognito user and add it to a group (`tier2_scorer/README.md` → Setup).
8. **Agent:** `EDR_CLOUD_ENDPOINTS=https://api.<domain>,<api_url>`, plus the licence and server key.

## Tests

```bash
node --test infra/aws/edge_filter.test.mjs
terraform -chdir=infra/aws validate
terraform -chdir=infra/cloudflare validate
```
