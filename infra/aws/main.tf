# AWS side of Telltale: system of record + fallback scorer (docs/PROD_ARCHITECTURE.md 3.2 and 7).
# CloudFront (Shield Standard, edge filter) -> Lambda function URL (IAM auth, CloudFront OAC only)
# -> DynamoDB (provisioned, within the always-free 25 RCU / 25 WCU).
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

resource "aws_dynamodb_table" "devices" {
  name           = "telltale_devices"
  billing_mode   = "PROVISIONED" # on-demand is not in the free tier
  read_capacity  = 10
  write_capacity = 5
  hash_key       = "device_id"
  attribute {
    name = "device_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "licences" {
  name           = "telltale_licences"
  billing_mode   = "PROVISIONED"
  read_capacity  = 2
  write_capacity = 2
  hash_key       = "licence_hash"
  attribute {
    name = "licence_hash"
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
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
      Resource = [aws_dynamodb_table.devices.arn, aws_dynamodb_table.licences.arn]
    }]
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

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
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
