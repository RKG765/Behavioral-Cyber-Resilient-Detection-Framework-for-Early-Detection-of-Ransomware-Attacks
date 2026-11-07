# Cloudflare edge protection for the Telltale API (docs/PROD_ARCHITECTURE.md sections 3.1 and 7).
# The Worker, its KV namespace and secrets are deployed with wrangler (worker/wrangler.toml);
# this file holds the zone's security settings only.
#
#   export CLOUDFLARE_API_TOKEN=...   # token with Zone: Edit (settings, WAF, rulesets) + Account: Filter Lists Edit
#   terraform init && terraform apply -var zone_id=... -var account_id=... -var api_hostname=api.example.com

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

variable "rate_limit_per_10s" {
  description = "Requests per IP per 10 s before a 10 s block (the free plan's fixed window)"
  type        = number
  default     = 20
}

# Blocked IPs. The admin console adds entries through the Lists API (step 5).
resource "cloudflare_list" "blocked" {
  account_id  = var.account_id
  name        = "telltale_blocked"
  kind        = "ip"
  description = "IPs blocked from the Telltale SOC console"
}

# Custom rules run before the Worker, so floods of junk never use the Worker's daily quota.
resource "cloudflare_ruleset" "firewall" {
  zone_id = var.zone_id
  name    = "telltale firewall"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules = [
    {
      description = "Blocked IPs (SOC console)"
      expression  = "(ip.src in $telltale_blocked)"
      action      = "block"
      enabled     = true
    },
    {
      description = "API takes only signed POSTs to /v1/score and /v1/register"
      expression  = "(http.host eq \"${var.api_hostname}\" and not (http.request.method eq \"POST\" and http.request.uri.path in {\"/v1/score\" \"/v1/register\"} and any(http.request.headers.names[*] eq \"x-tt-sig\") and any(http.request.headers.names[*] eq \"x-tt-device\")))"
      action      = "block"
      enabled     = true
    },
  ]
  depends_on = [cloudflare_list.blocked]
}

# The free plan allows one rate-limiting rule: fixed 10 s window, 10 s block, counted per IP.
resource "cloudflare_ruleset" "rate_limit" {
  zone_id = var.zone_id
  name    = "telltale rate limit"
  kind    = "zone"
  phase   = "http_ratelimit"
  rules = [
    {
      description = "Per-IP limit on the API"
      expression  = "(http.request.uri.path in {\"/v1/score\" \"/v1/register\"})"
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
