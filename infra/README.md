# infra: edge protection as code

Terraform for both clouds (plan: `docs/PROD_ARCHITECTURE.md`, build step 3). Only `terraform validate`
has run; the real-account checks are in `docs/INTEGRATION_TESTS.md`.

| Folder | What it creates |
|---|---|
| `aws/` | DynamoDB tables (provisioned, free tier), the Lambda (IAM-auth function URL), CloudFront with Origin Access Control, the edge-filter CloudFront Function, a $1 budget alarm |
| `cloudflare/` | Zone TLS settings (Full strict, TLS 1.2+, HTTPS only, HSTS), a custom rule that drops unsigned API requests, the blocked-IP list, the one free rate-limit rule, Bot Fight Mode **off** |

The Worker itself, its KV namespace and its secrets are deployed with `wrangler` (`worker/`).

## Order

1. **Domain** on Cloudflare (the only paid item). Note its zone ID and account ID.
2. **Worker:** `npx wrangler kv namespace create DEVICES`, put the id in `worker/wrangler.toml`
   along with your domain, then set the secrets (`tier2_scorer/README.md` → Setup).
3. **AWS:** build the Lambda zip (top of `aws/main.tf`), then
   `cd infra/aws && terraform init && terraform apply -var-file=secrets.tfvars`.
   `secrets.tfvars` (git-ignored) holds `region`, `alert_email`, `response_signing_seed`,
   `origin_secret`, `cf_account_id`, `cf_kv_namespace` and `cf_api_token`.
4. Put the `api_url` output into the Worker's `AWS_API_URL`, then `npx wrangler deploy`.
5. **Cloudflare:** `cd infra/cloudflare && terraform init && terraform apply -var zone_id=... -var
   account_id=... -var api_hostname=api.<domain>` with `CLOUDFLARE_API_TOKEN` set.
6. **Agent:** `EDR_CLOUD_ENDPOINTS=https://api.<domain>,<api_url>`, plus the licence and server key.

## Tests

```bash
node --test infra/aws/edge_filter.test.mjs
terraform -chdir=infra/aws validate
terraform -chdir=infra/cloudflare validate
```
