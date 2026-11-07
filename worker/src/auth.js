// Request / response signing for the Tier-2 API (plan section 4.1, protocol in tier2_scorer/README.md).
// Requests carry the device's TPM-key ECDSA P-256 signature; replies are signed with the
// server's Ed25519 key so a fake server can't answer for us.

export const SKEW_S = 300; // allowed clock difference between the PC and the edge
export const RATE_PER_MIN = 60; // verified requests per device per minute

const enc = new TextEncoder();
export const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const ID = /^[0-9a-f]{32}$/;

export const canonical = (method, path, device, time, nonce, bodyHash) =>
  ["TT1", method, path, device, time, nonce, bodyHash].join("\n");

export async function deviceId(publicKey) {
  return hex(await crypto.subtle.digest("SHA-256", publicKey)).slice(0, 32);
}

// shortcut: nonces and rate counts live per isolate, so a replay can succeed on another
// isolate within SKEW_S (harmless for /v1/score: it only re-reads a verdict); global
// replay detection comes with the step-5 log pipeline.
const seen = new Map(); // nonce -> expiry (s)
const usage = new Map(); // device -> [minute, count]

function remember(nonce, now) {
  if (seen.has(nonce)) return false;
  if (seen.size > 50_000) for (const [n, exp] of seen) if (exp < now) seen.delete(n);
  seen.set(nonce, now + 2 * SKEW_S);
  return true;
}

function underLimit(device, now) {
  const minute = Math.floor(now / 60);
  const [m, n] = usage.get(device) ?? [minute, 0];
  const count = m === minute ? n + 1 : 1;
  usage.set(device, [minute, count]);
  return count <= RATE_PER_MIN;
}

/**
 * Verifies a signed request against `publicKey` (raw SEC1 P-256 bytes).
 * Returns {device, nonce} or {error, status}.
 */
export async function verifyRequest(headers, method, path, body, publicKey, now) {
  const [device, time, nonce, sig] = ["x-tt-device", "x-tt-time", "x-tt-nonce", "x-tt-sig"].map(
    (h) => headers.get(h) ?? "",
  );
  if (!ID.test(device) || !ID.test(nonce) || !(Math.abs(now - Number(time)) <= SKEW_S)) {
    return { error: "unauthorized", status: 401 };
  }
  let ok = false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const msg = canonical(method, path, device, time, nonce, hex(await crypto.subtle.digest("SHA-256", body)));
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, unb64(sig), enc.encode(msg));
  } catch {
    ok = false;
  }
  if (!ok || device !== (await deviceId(publicKey))) return { error: "unauthorized", status: 401 };
  if (!remember(nonce, now)) return { error: "unauthorized", status: 401 };
  if (!underLimit(device, now)) return { error: "rate limited", status: 429 };
  return { device, nonce };
}

const PKCS8_ED25519 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
let signingKey;

/** JSON reply signed with the Ed25519 key whose 32-byte seed is `seedB64` (Worker secret). */
export async function signedJson(body, seedB64) {
  if (!signingKey) {
    const pkcs8 = new Uint8Array([...PKCS8_ED25519, ...unb64(seedB64)]);
    signingKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  }
  const text = JSON.stringify(body);
  const sig = await crypto.subtle.sign("Ed25519", signingKey, enc.encode(text));
  return new Response(text, { headers: { "content-type": "application/json", "x-tt-resp-sig": b64(sig) } });
}
