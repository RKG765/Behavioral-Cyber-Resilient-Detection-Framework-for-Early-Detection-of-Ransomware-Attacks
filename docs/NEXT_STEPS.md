# Next steps (resume here)

State on 2026-11-11. Done: build steps 1-8 (except the beta group), v0.2.0 pre-release on GitHub,
"Create licence" in the dashboard (Lambda `POST /admin/licences/new?seats=N`, Licences page form,
tested on the local demo).

## In progress
1. **Add admin (dashboard).** Admins page: list admins, add an email with a role.
   Backend: Cognito `AdminCreateUser` (AWS emails an invite) + `AdminAddUserToGroup`, then append
   the email to the Cloudflare Access email list. Started: `aws-sdk-cognitoidentityprovider` added to
   `tier2_scorer/Cargo.toml` (uncommitted, no code uses it yet). Still to do: the route, IAM
   (`cognito-idp:AdminCreateUser`, `AdminAddUserToGroup`, `ListUsersInGroup` on the pool), the page,
   and a Cloudflare token (Zero Trust: Edit) as a Lambda env var for the Access list. Without that
   token, the page tells you to add the email in Zero Trust by hand.

## To host the dashboard (Cloudflare Pages + Access, data stays on AWS)
2. **Access for `haltline-console.pages.dev`** (Zero Trust team `foreducation.cloudflareaccess.com`):
   a self-hosted app covering `haltline-console.pages.dev` and `*.haltline-console.pages.dev`, a
   policy allowing only **rkg270954@gmail.com** and **rajkumargupta7632@gmail.com** (an email list),
   session 8 h. Note its **AUD tag**. Do **not** protect the Worker `haltline-tier2`: agents call it.
3. **Lambda:** in `infra/aws/secrets.tfvars` set `access_aud` (from step 2); rebuild the zip
   (`cargo lambda build --release --arm64 --features lambda --bin lambda --output-format zip`, with
   zig on PATH) and `terraform -chdir=infra/aws apply -var-file=secrets.tfvars`.
4. **Dashboard settings:** `console/config.js` → `cognitoDomain:
   "https://haltline-admin-4769.auth.ap-south-1.amazoncognito.com"`, `clientId:
   "52tk78fm5igsbigbp3hia6e5na"`.
5. **Deploy:** `npx wrangler pages secret put AWS_API_URL --project-name haltline-console` (the
   Lambda URL), same for `ORIGIN_SECRET` (as in secrets.tfvars), then
   `npx wrangler pages deploy console --project-name haltline-console --branch main`.
   (Today the site answers 522: the project has never had a deployment.)
6. **Cognito admins:** `admin-create-user` + `admin-add-user-to-group --group-name admin` for the two
   emails (pool `ap-south-1_li7V0Qkdl`). Each gets an invite email; first sign-in sets a password and
   an authenticator app.
7. **Check end to end:** open the dashboard → Access email code → Cognito sign-in → Licences →
   Create licence → install the exe with that key on a PC → the device appears in Devices with its IP.

## Still open from earlier
8. **Install `Haltline-Setup-0.2.0.exe` on this PC** (licence key in `build\licence-this-pc.txt`;
   the admin prompt was cancelled last time).
9. **IP blocking from the dashboard:** `cf_list_id` / `CF_LISTS_TOKEN` are still placeholders.
10. **Beta group:** pick testers, make each a licence (step 7), send the release link.
11. **Privacy notice:** add a contact address to `PRIVACY.md` before the beta.
12. **Later:** domain (WAF + rate-limit rules), CloudFront once AWS verifies the account, passkeys
    once the AWS Terraform provider supports passkey MFA, real code signing.
