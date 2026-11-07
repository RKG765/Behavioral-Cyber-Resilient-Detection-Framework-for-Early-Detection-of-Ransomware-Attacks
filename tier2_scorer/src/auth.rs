//! Request / response signing for the Lambda, mirroring `worker/src/auth.js`
//! (protocol in README.md).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signer;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub const SKEW_S: i64 = 300; // allowed clock difference between the PC and the server
pub const RATE_PER_MIN: u32 = 60; // verified requests per device per minute

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn canonical(method: &str, path: &str, device: &str, time: &str, nonce: &str, body_hash: &str) -> String {
    format!("TT1\n{method}\n{path}\n{device}\n{time}\n{nonce}\n{body_hash}")
}

/// Device id = first 32 hex chars of SHA-256(SEC1 public key).
pub fn device_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key))[..32].to_string()
}

pub struct SignedHeaders<'a> {
    pub device: &'a str,
    pub time: &'a str,
    pub nonce: &'a str,
    pub sig: &'a str,
}

#[derive(Debug, PartialEq)]
pub enum AuthError {
    Unauthorized,
    RateLimited,
}

/// Nonce and rate state for one Lambda container.
/// shortcut: per container, like the Worker's per-isolate maps; global replay
/// detection comes with the step-5 log pipeline.
#[derive(Default)]
pub struct Guard {
    seen: Mutex<HashMap<String, i64>>,
    usage: Mutex<HashMap<String, (i64, u32)>>,
}

impl Guard {
    pub fn verify(
        &self,
        h: &SignedHeaders,
        method: &str,
        path: &str,
        body: &[u8],
        public_key: &[u8],
        now: i64,
    ) -> Result<(), AuthError> {
        use AuthError::*;
        let time: i64 = h.time.parse().map_err(|_| Unauthorized)?;
        if !is_id(h.device) || !is_id(h.nonce) || (now - time).abs() > SKEW_S || h.device != device_id(public_key) {
            return Err(Unauthorized);
        }
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Unauthorized)?;
        let sig = B64.decode(h.sig).ok().and_then(|s| Signature::from_slice(&s).ok()).ok_or(Unauthorized)?;
        let msg = canonical(method, path, h.device, h.time, h.nonce, &hex(&Sha256::digest(body)));
        key.verify(msg.as_bytes(), &sig).map_err(|_| Unauthorized)?;

        let mut seen = self.seen.lock().unwrap();
        if seen.len() > 50_000 {
            seen.retain(|_, exp| *exp >= now);
        }
        if seen.insert(h.nonce.to_string(), now + 2 * SKEW_S).is_some() {
            return Err(Unauthorized);
        }
        drop(seen);

        let minute = now.div_euclid(60);
        let mut usage = self.usage.lock().unwrap();
        let entry = usage.entry(h.device.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        if entry.1 > RATE_PER_MIN { Err(RateLimited) } else { Ok(()) }
    }
}

/// Base64 Ed25519 signature over the exact reply body.
pub fn sign_reply(seed: &[u8; 32], body: &str) -> String {
    B64.encode(ed25519_dalek::SigningKey::from_bytes(seed).sign(body.as_bytes()).to_bytes())
}

/// Constant-time comparison for the Cloudflare-only origin secret.
pub fn secret_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    fn signed(key: &SigningKey, body: &[u8], time: i64, nonce: &str) -> (String, String, String) {
        let pk = key.verifying_key().to_encoded_point(false);
        let device = device_id(pk.as_bytes());
        let msg = canonical("POST", "/v1/score", &device, &time.to_string(), nonce, &hex(&Sha256::digest(body)));
        let sig: Signature = key.sign(msg.as_bytes());
        (device, time.to_string(), B64.encode(sig.to_bytes()))
    }

    #[test]
    fn canonical_matches_the_protocol() {
        assert_eq!(canonical("POST", "/v1/score", "d", "1", "n", "h"), "TT1\nPOST\n/v1/score\nd\n1\nn\nh");
    }

    #[test]
    fn valid_passes_and_tampered_old_replayed_or_flooded_fail() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = key.verifying_key().to_encoded_point(false);
        let guard = Guard::default();
        let now = 1_700_000_000;
        let body = br#"{"features":[1]}"#;
        let nonce = "0123456789abcdef0123456789abcdef";
        let (device, time, sig) = signed(&key, body, now, nonce);
        let h = SignedHeaders { device: &device, time: &time, nonce, sig: &sig };

        assert_eq!(guard.verify(&h, "POST", "/v1/score", body, pk.as_bytes(), now), Ok(()));
        assert_eq!(guard.verify(&h, "POST", "/v1/score", body, pk.as_bytes(), now), Err(AuthError::Unauthorized), "replay");
        let fresh = |n: u32| format!("{n:032x}");
        let n2 = fresh(2);
        let (_, t2, s2) = signed(&key, body, now, &n2);
        let h2 = SignedHeaders { device: &device, time: &t2, nonce: &n2, sig: &s2 };
        assert!(guard.verify(&h2, "POST", "/v1/score", b"{}", pk.as_bytes(), now).is_err(), "tampered body");
        assert!(guard.verify(&h2, "POST", "/v1/score", body, pk.as_bytes(), now + SKEW_S + 1).is_err(), "too old");

        let mut last = Ok(());
        for n in 10..80 {
            let nonce = fresh(n);
            let (_, t, s) = signed(&key, body, now, &nonce);
            last = guard.verify(&SignedHeaders { device: &device, time: &t, nonce: &nonce, sig: &s }, "POST", "/v1/score", body, pk.as_bytes(), now);
        }
        assert_eq!(last, Err(AuthError::RateLimited));
    }

    #[test]
    fn reply_signature_verifies() {
        let seed = [9u8; 32];
        let sig = B64.decode(sign_reply(&seed, r#"{"verdict":"BENIGN"}"#)).unwrap();
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        assert!(vk.verify_strict(br#"{"verdict":"BENIGN"}"#, &sig).is_ok());
        assert!(vk.verify_strict(br#"{"verdict":"KILL"}"#, &sig).is_err());
        assert!(secret_eq("abc", "abc") && !secret_eq("abc", "abd") && !secret_eq("abc", "ab"));
    }
}
