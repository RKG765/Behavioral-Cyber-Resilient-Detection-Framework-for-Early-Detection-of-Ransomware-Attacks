// Pages Function: /admin/* -> the AWS admin API (plan section 6.4).
// Cloudflare Access has already let the user in; we pass its JWT, the user's Cognito ID token and
// the Cloudflare-only origin secret. Env (Pages secrets): AWS_API_URL, ORIGIN_SECRET.
async function sha256hex(buf) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const body = request.method === "GET" ? undefined : await request.arrayBuffer();
  const headers = new Headers({
    "x-tt-origin-secret": env.ORIGIN_SECRET,
    "cf-access-jwt-assertion": request.headers.get("cf-access-jwt-assertion") ?? "",
    "x-tt-admin-token": request.headers.get("x-tt-admin-token") ?? "",
  });
  if (body) headers.set("x-amz-content-sha256", await sha256hex(body)); // CloudFront OAC needs it on POST
  return fetch(`${env.AWS_API_URL}${url.pathname}${url.search}`, { method: request.method, headers, body });
}
