// CloudFront viewer-request filter for the AWS fallback path (docs/PROD_ARCHITECTURE.md section 7).
// Drops requests that can't be valid before they reach, and count against, the Lambda.
// Runtime: cloudfront-js-2.0. Terraform replaces __BLOCKED_IPS__ with {"1.2.3.4": true, ...}.
var BLOCKED = __BLOCKED_IPS__;
// x-amz-content-sha256 is required by CloudFront OAC for POSTs to a Lambda function URL.
var SCORE_HEADERS = ["x-tt-device", "x-tt-time", "x-tt-nonce", "x-tt-sig", "x-amz-content-sha256"];

function deny(code) {
  return { statusCode: code, statusDescription: code === 403 ? "Forbidden" : "Not Found" };
}

function handler(event) {
  var req = event.request;
  var h = req.headers;
  if (BLOCKED[event.viewer.ip]) return deny(403);
  if (req.method !== "POST") return deny(404);
  if (req.uri === "/v1/score") {
    for (var i = 0; i < SCORE_HEADERS.length; i++) {
      if (!h[SCORE_HEADERS[i]]) return deny(403);
    }
    return req;
  }
  // Register only arrives from the Cloudflare Worker; the Lambda checks the secret's value.
  if (req.uri === "/v1/register" && h["x-tt-origin-secret"] && h["x-amz-content-sha256"]) return req;
  return deny(404);
}
