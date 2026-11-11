# Cloudflare side of Telltale (docs/PROD_ARCHITECTURE.md sections 3.1, 6.4 and 7): the zone's
# security settings, and the SOC console's Pages project behind Cloudflare Access (admin login layer 1).
# The Worker, its KV namespace and secrets, and the console's files and secrets are deployed with
# wrangler (worker/wrangler.toml, infra/README.md).
#
#   export CLOUDFLARE_API_TOKEN=...   # Zone: Zone Settings, Zone WAF, DNS Edit; Account: Account Filter Lists,
#                                     # Cloudflare Pages, Access: Apps and Policies, Zero Trust Edit
#   terraform init && terraform apply -var-file=cloudflare.tfvars   # git-ignored, see infra/README.md

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {}

variable "zone_id" {
  type = string
}

variable "account_id" {
  type = string
}

variable "api_hostname" {
  description = "Hostname the Worker serves, e.g. api.example.com"
  type        = string
}

variable "admin_hostname" {
  description = "Where the SOC console is served, e.g. admin.example.com"
  type        = string
}

variable "admin_emails" {
  description = "Who Cloudflare Access lets reach the console (each still needs a Cognito login)"
  type        = list(string)
}

variable "rate_limit_per_10s" {
  description = "Requests per IP per 10 s before a 10 s block (the free plan's fixed window)"
  type        = number
  default     = 20
}

# Blocked IPs. The admin console adds entries through the Lists API (step 5).
resource "cloudflare_list" "blocked" {
  account_id  = var.account_id
  name        = "haltline_blocked"
  kind        = "ip"
  description = "IPs blocked from the Haltline SOC console"
}

# Custom rules run before the Worker, so floods of junk never use the Worker's daily quota.
resource "cloudflare_ruleset" "firewall" {
  zone_id = var.zone_id
  name    = "haltline firewall"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules = [
    {
      description = "Blocked IPs (SOC console)"
      expression  = "(ip.src in $haltline_blocked)"
      action      = "block"
      enabled     = true
    },
    {
      description = "API takes only signed POSTs to /v1/score, /v1/register and /v1/report"
      expression  = "(http.host eq \"${var.api_hostname}\" and not (http.request.method eq \"POST\" and http.request.uri.path in {\"/v1/score\" \"/v1/register\" \"/v1/report\"} and any(http.request.headers.names[*] eq \"x-tt-sig\") and any(http.request.headers.names[*] eq \"x-tt-device\")))"
      action      = "block"
      enabled     = true
    },
  ]
  depends_on = [cloudflare_list.blocked]
}

# The free plan allows one rate-limiting rule: fixed 10 s window, 10 s block, counted per IP.
resource "cloudflare_ruleset" "rate_limit" {
  zone_id = var.zone_id
  name    = "haltline rate limit"
  kind    = "zone"
  phase   = "http_ratelimit"
  rules = [
    {
      description = "Per-IP limit on the API"
      expression  = "(http.request.uri.path in {\"/v1/score\" \"/v1/register\" \"/v1/report\"})"
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 10
        requests_per_period = var.rate_limit_per_10s
        mitigation_timeout  = 10
      }
    },
  ]
}

# Bot Fight Mode stays OFF: on the free plan it can challenge API clients (our agent) and
# cannot be skipped by WAF rules. The custom rule above and signatures do that job instead.
resource "cloudflare_bot_management" "api" {
  zone_id    = var.zone_id
  fight_mode = false
}

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = var.zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "min_tls" {
  zone_id    = var.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "https_only" {
  zone_id    = var.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "hsts" {
  zone_id    = var.zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      max_age            = 31536000
      include_subdomains = true
      nosniff            = true
      preload            = false
    }
  }
}

# The Cloudflare Free Managed Ruleset and unmetered DDoS protection are on by default on
# every zone; nothing to configure (checked in docs/INTEGRATION_TESTS.md).

# ───────────── SOC console (plan 6.4): Pages, admin.<domain>, Access in front ─────────────
# Direct-upload project (no Git link): `cd console && npx wrangler pages deploy . --project-name haltline-console`
# (run inside console/ so the functions/ proxy is deployed too).
resource "cloudflare_pages_project" "console" {
  account_id        = var.account_id
  name              = "haltline-console"
  production_branch = "main"
}

resource "cloudflare_pages_domain" "console" {
  account_id   = var.account_id
  project_name = cloudflare_pages_project.console.name
  name         = var.admin_hostname
}

# Through the API, a Pages custom domain needs its own CNAME (the dashboard adds it for you).
resource "cloudflare_dns_record" "console" {
  zone_id = var.zone_id
  name    = var.admin_hostname
  type    = "CNAME"
  content = cloudflare_pages_project.console.subdomain
  proxied = true
  ttl     = 1
}

resource "cloudflare_zero_trust_list" "admins" {
  account_id  = var.account_id
  name        = "haltline_admins"
  type        = "EMAIL"
  description = "Who may reach the Haltline SOC console"
  items       = [for e in var.admin_emails : { value = e }]
}

resource "cloudflare_zero_trust_access_policy" "admins" {
  account_id = var.account_id
  name       = "Haltline admins"
  decision   = "allow"
  include    = [{ email_list = { id = cloudflare_zero_trust_list.admins.id } }]
}

# The pages.dev names are covered too, so the console is never reachable around Access.
resource "cloudflare_zero_trust_access_application" "console" {
  account_id       = var.account_id
  name             = "Haltline SOC console"
  type             = "self_hosted"
  session_duration = "8h"
  destinations = [
    { type = "public", uri = var.admin_hostname },
    { type = "public", uri = cloudflare_pages_project.console.subdomain },
    { type = "public", uri = "*.${cloudflare_pages_project.console.subdomain}" }, # preview deployments
  ]
  policies = [{ id = cloudflare_zero_trust_access_policy.admins.id, precedence = 1 }]
  # Pages refuses a custom domain that Access already covers, so the domain is added first.
  depends_on = [cloudflare_pages_domain.console]
}

# Pages validates (and renews) the admin. certificate over this path, so Access must let it through.
resource "cloudflare_zero_trust_access_policy" "acme" {
  account_id = var.account_id
  name       = "Haltline console certificate checks"
  decision   = "bypass"
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_application" "acme" {
  account_id = var.account_id
  name       = "Haltline console ACME challenge"
  type       = "self_hosted"
  destinations = [
    { type = "public", uri = "${var.admin_hostname}/.well-known/acme-challenge/*" },
  ]
  policies   = [{ id = cloudflare_zero_trust_access_policy.acme.id, precedence = 1 }]
  depends_on = [cloudflare_pages_domain.console]
}

output "access_aud" {
  description = "ACCESS_AUD for the admin Lambda (infra/aws access_aud)"
  value       = cloudflare_zero_trust_access_application.console.aud
}

output "blocked_list_id" {
  description = "The zone firewall IP list (needs the domain). The console blocks IPs through KV instead (blocked_ips)"
  value       = cloudflare_list.blocked.id
}

output "console_pages_subdomain" {
  value = cloudflare_pages_project.console.subdomain
}
