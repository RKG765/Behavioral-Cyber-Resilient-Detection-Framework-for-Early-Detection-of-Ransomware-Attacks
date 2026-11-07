# AWS side of Telltale: system of record + fallback scorer (docs/PROD_ARCHITECTURE.md 3.2 and 7)
# and the SOC console's admin API and login (section 6).
# CloudFront (Shield Standard, edge filter) -> Lambda function URL (IAM auth, CloudFront OAC only)
# -> DynamoDB (provisioned, within the always-free 25 RCU / 25 WCU). Cognito: admin login layer 2.
#
#   cargo lambda build --release --arm64 --features lambda --bin lambda --output-format zip \
#       --manifest-path ../../tier2_scorer/Cargo.toml
#   terraform init && terraform apply -var-file=secrets.tfvars   # secrets.tfvars is git-ignored

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "Closest to most users, e.g. ap-south-1"
  type        = string
}

variable "lambda_zip" {
  type    = string
  default = "../../tier2_scorer/target/lambda/lambda/bootstrap.zip"
}

variable "response_signing_seed" {
  type      = string
  sensitive = true
}

variable "origin_secret" {
  type      = string
  sensitive = true
}

variable "cf_account_id" {
  type = string
}

variable "cf_kv_namespace" {
  type = string
}

variable "cf_api_token" {
  description = "Cloudflare token with Workers KV Storage: Edit only"
  type        = string
  sensitive   = true
}

variable "blocked_ips" {
  description = "Viewer IPs the edge filter refuses (the SOC console will manage this list)"
  type        = list(string)
  default     = []
}

variable "reserved_concurrency" {
  description = "Cap on concurrent Lambdas (-1 = unreserved; new accounts have a 10 total limit anyway)"
  type        = number
  default     = -1
}

variable "price_class" {
  description = "PriceClass_All includes India / Asia edge locations"
  type        = string
  default     = "PriceClass_All"
}

variable "alert_email" {
  description = "Gets the $1 budget alarm"
  type        = string
}

variable "admin_hostname" {
  description = "Where the SOC console is served (Pages behind Access), e.g. admin.example.com"
  type        = string
}

variable "cognito_domain_prefix" {
  description = "Managed-login domain: <prefix>.auth.<region>.amazoncognito.com (globally unique)"
  type        = string
}

variable "access_team_domain" {
  description = "Cloudflare Zero Trust team domain, e.g. myteam.cloudflareaccess.com"
  type        = string
}

variable "access_aud" {
  description = "From `terraform output access_aud` in infra/cloudflare"
  type        = string
}

variable "cf_list_id" {
  description = "From `terraform output blocked_list_id` in infra/cloudflare"
  type        = string
}

variable "cf_lists_token" {
  description = "Cloudflare token with Account Filter Lists: Edit only (IP blocking from the console)"
  type        = string
  sensitive   = true
}

# Provisioned [RCU, WCU] per table. The always-free tier is 25 RCU + 25 WCU per region, in total.
locals {
  capacity = {
    devices  = [10, 5]
    licences = [2, 2]
    events   = [5, 10] # request log, reports, audit: write-heavy
    index    = [5, 6]  # IP history
  }
  rcu = sum([for c in values(local.capacity) : c[0]])
  wcu = sum([for c in values(local.capacity) : c[1]])
}

resource "aws_dynamodb_table" "devices" {
  name           = "telltale_devices"
  billing_mode   = "PROVISIONED" # on-demand is not in the free tier
  read_capacity  = local.capacity.devices[0]
  write_capacity = local.capacity.devices[1]
  hash_key       = "device_id"
  attribute {
    name = "device_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "licences" {
  name           = "telltale_licences"
  billing_mode   = "PROVISIONED"
  read_capacity  = local.capacity.licences[0]
  write_capacity = local.capacity.licences[1]
  hash_key       = "licence_hash"
  attribute {
    name = "licence_hash"
    type = "S"
  }
}

# pk = "<e|r|a>#<UTC day>" (request log, reports, audit), sk = "<ms>#<rand>"; rows expire after 90 days.
resource "aws_dynamodb_table" "events" {
  name           = "telltale_events"
  billing_mode   = "PROVISIONED"
  read_capacity  = local.capacity.events[0]
  write_capacity = local.capacity.events[1]
  hash_key       = "pk"
  range_key      = "sk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  ttl {
    attribute_name = "expires"
    enabled        = true
  }
  lifecycle {
    precondition {
      condition     = local.rcu <= 25 && local.wcu <= 25
      error_message = "Provisioned capacity is over the DynamoDB free tier (25 RCU / 25 WCU in total)."
    }
  }
}

# IP history both ways: pk = "d#<device>" / sk = "ip#<IP>", and pk = "i#<IP>" / sk = "d#<device>".
resource "aws_dynamodb_table" "index" {
  name           = "telltale_index"
  billing_mode   = "PROVISIONED"
  read_capacity  = local.capacity.index[0]
  write_capacity = local.capacity.index[1]
  hash_key       = "pk"
  range_key      = "sk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
}

resource "aws_iam_role" "api" {
  name = "telltale-api"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.api.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "tables" {
  role = aws_iam_role.api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan"] # Scan: console lists
        Resource = [aws_dynamodb_table.devices.arn, aws_dynamodb_table.licences.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.events.arn, aws_dynamodb_table.index.arn]
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/telltale-api"
  retention_in_days = 14
}

resource "aws_lambda_function" "api" {
  function_name                  = "telltale-api"
  role                           = aws_iam_role.api.arn
  runtime                        = "provided.al2023"
  handler                        = "bootstrap"
  architectures                  = ["arm64"]
  filename                       = var.lambda_zip
  source_code_hash               = filebase64sha256(var.lambda_zip)
  memory_size                    = 128
  timeout                        = 10
  reserved_concurrent_executions = var.reserved_concurrency
  environment {
    variables = {
      DEVICES_TABLE         = aws_dynamodb_table.devices.name
      LICENCES_TABLE        = aws_dynamodb_table.licences.name
      RESPONSE_SIGNING_SEED = var.response_signing_seed
      ORIGIN_SECRET         = var.origin_secret
      CF_ACCOUNT_ID         = var.cf_account_id
      CF_KV_NAMESPACE       = var.cf_kv_namespace
      CF_API_TOKEN          = var.cf_api_token
      EVENTS_TABLE          = aws_dynamodb_table.events.name
      INDEX_TABLE           = aws_dynamodb_table.index.name
      ACCESS_TEAM_DOMAIN    = var.access_team_domain
      ACCESS_AUD            = var.access_aud
      COGNITO_ISSUER        = "https://${aws_cognito_user_pool.admin.endpoint}"
      COGNITO_CLIENT_ID     = aws_cognito_user_pool_client.console.id
      CF_LIST_ID            = var.cf_list_id
      CF_LISTS_TOKEN        = var.cf_lists_token
    }
  }
  depends_on = [aws_cloudwatch_log_group.api]
}

# IAM-auth URL: only CloudFront (through OAC) can invoke it.
resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_permission" "cloudfront_url" {
  statement_id           = "cloudfront-invoke-url"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.api.function_name
  principal              = "cloudfront.amazonaws.com"
  source_arn             = aws_cloudfront_distribution.api.arn
  function_url_auth_type = "AWS_IAM"
}

# Newer function URLs also require lambda:InvokeFunction for the calling principal.
resource "aws_lambda_permission" "cloudfront_invoke" {
  statement_id  = "cloudfront-invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.api.arn
}

resource "aws_cloudfront_origin_access_control" "api" {
  name                              = "telltale-api"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "edge_filter" {
  name    = "telltale-edge-filter"
  runtime = "cloudfront-js-2.0"
  publish = true
  code = replace(file("${path.module}/edge_filter.js"), "__BLOCKED_IPS__",
  jsonencode({ for ip in var.blocked_ips : ip => true }))
}

# Forward only what the Lambda reads. Host must not be forwarded to a function-URL origin.
resource "aws_cloudfront_origin_request_policy" "api" {
  name = "telltale-api"
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "content-type", "x-amz-content-sha256", "x-tt-device", "x-tt-time", "x-tt-nonce", "x-tt-sig",
        "x-tt-origin-secret", "x-tt-client-ip", "CloudFront-Viewer-Address", "CloudFront-Viewer-Country",
      ]
    }
  }
  cookies_config {
    cookie_behavior = "none"
  }
  query_strings_config {
    query_string_behavior = "none"
  }
}

# /admin/* (from the console's Pages Function) also needs both login tokens and the query string.
# A policy of its own, because the one above is at CloudFront's 10-header limit.
resource "aws_cloudfront_origin_request_policy" "admin" {
  name = "telltale-admin"
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = ["content-type", "x-amz-content-sha256", "x-tt-origin-secret", "cf-access-jwt-assertion", "x-tt-admin-token"]
    }
  }
  cookies_config {
    cookie_behavior = "none"
  }
  query_strings_config {
    query_string_behavior = "all"
  }
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_distribution" "api" {
  enabled      = true
  comment      = "Telltale Tier-2 fallback + register origin"
  price_class  = var.price_class
  http_version = "http2and3"

  origin {
    origin_id                = "lambda"
    domain_name              = trimsuffix(trimprefix(aws_lambda_function_url.api.function_url, "https://"), "/")
    origin_access_control_id = aws_cloudfront_origin_access_control.api.id
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "lambda"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.api.id
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.edge_filter.arn
    }
  }

  ordered_cache_behavior {
    path_pattern             = "/admin/*"
    target_origin_id         = "lambda"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.admin.id
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.edge_filter.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# ───────── admin login layer 2 (plan 6.4): Cognito, Essentials tier (10,000 MAU free), MFA required ─────────
resource "aws_cognito_user_pool" "admin" {
  name                = "telltale-admins"
  user_pool_tier      = "ESSENTIALS"
  deletion_protection = "ACTIVE"
  username_attributes = ["email"]
  # Every sign-in is password + authenticator code; managed login makes new admins set one up.
  # shortcut: no passkeys yet. They need web_authn_configuration.factor_configuration =
  # MULTI_FACTOR_WITH_USER_VERIFICATION (passkeys then count as MFA), which provider 6.72 lacks
  # (hashicorp/terraform-provider-aws#50110). Add "WEB_AUTHN" below once it's supported.
  mfa_configuration = "ON"

  sign_in_policy {
    allowed_first_auth_factors = ["PASSWORD"]
  }
  software_token_mfa_configuration {
    enabled = true
  }
  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 1
  }
  admin_create_user_config {
    allow_admin_create_user_only = true
  }
  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only" # no self-service reset: an admin resets the login
      priority = 1
    }
  }
}

resource "aws_cognito_user_group" "role" {
  for_each     = toset(["viewer", "analyst", "admin"])
  name         = each.key
  user_pool_id = aws_cognito_user_pool.admin.id
}

# Public client (no secret): the console runs authorization code + PKCE in the browser.
resource "aws_cognito_user_pool_client" "console" {
  name                                 = "telltale-console"
  user_pool_id                         = aws_cognito_user_pool.admin.id
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://${var.admin_hostname}/"]
  logout_urls                          = ["https://${var.admin_hostname}/"]
  explicit_auth_flows                  = ["ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  read_attributes                      = ["email"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  id_token_validity                    = 15
  access_token_validity                = 15
  refresh_token_validity               = 60 # Cognito's minimum; the console never uses refresh tokens
  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "minutes"
  }
}

resource "aws_cognito_user_pool_domain" "admin" {
  domain                = var.cognito_domain_prefix
  user_pool_id          = aws_cognito_user_pool.admin.id
  managed_login_version = 2
}

# Managed login v2 shows an error page until the client has a style; Cognito's default is enough.
resource "aws_cognito_managed_login_branding" "console" {
  user_pool_id                = aws_cognito_user_pool.admin.id
  client_id                   = aws_cognito_user_pool_client.console.id
  use_cognito_provided_values = true
}

resource "aws_budgets_budget" "free_tier_guard" {
  name         = "telltale-free-tier-guard"
  budget_type  = "COST"
  limit_amount = "1"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 1
    threshold_type             = "ABSOLUTE_VALUE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}

output "api_url" {
  description = "Set as the Worker's AWS_API_URL and the agent's fallback endpoint"
  value       = "https://${aws_cloudfront_distribution.api.domain_name}"
}

output "cognito_domain" {
  description = "console/config.js cognitoDomain"
  value       = "https://${aws_cognito_user_pool_domain.admin.domain}.auth.${var.region}.amazoncognito.com"
}

output "cognito_client_id" {
  description = "console/config.js clientId"
  value       = aws_cognito_user_pool_client.console.id
}

output "cognito_user_pool_id" {
  description = "For aws cognito-idp admin-create-user / admin-add-user-to-group"
  value       = aws_cognito_user_pool.admin.id
}
