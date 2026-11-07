//! Admin API login checks (plan section 6.4): Cloudflare Access JWT (layer 1) and
//! Cognito ID token (layer 2), both RS256, both required, same email.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Analyst,
    Admin,
}

/// Destructive actions need a login (passkey / TOTP) this recent.
pub const STEP_UP_S: i64 = 300;

#[derive(Deserialize)]
pub struct AccessClaims {
    pub email: String,
}

#[derive(Deserialize)]
pub struct CognitoClaims {
    pub email: String,
    pub token_use: String,
    pub auth_time: i64,
    #[serde(rename = "cognito:groups", default)]
    pub groups: Vec<String>,
}

/// Highest role among the user's Cognito groups.
pub fn role_of(groups: &[String]) -> Option<Role> {
    groups
        .iter()
        .filter_map(|g| match g.as_str() {
            "viewer" => Some(Role::Viewer),
            "analyst" => Some(Role::Analyst),
            "admin" => Some(Role::Admin),
            _ => None,
        })
        .max()
}

/// Claim checks after both signatures, issuers, audiences and expiry are verified.
pub fn authorize(access_email: &str, id: &CognitoClaims, need: Role, step_up: bool, now: i64) -> Result<Role, &'static str> {
    if id.token_use != "id" {
        return Err("login");
    }
    if !id.email.eq_ignore_ascii_case(access_email) {
        return Err("identity mismatch"); // both layers must be the same person
    }
    let role = role_of(&id.groups).ok_or("forbidden")?;
    if role < need {
        return Err("forbidden");
    }
    if step_up && now - id.auth_time > STEP_UP_S {
        return Err("step_up");
    }
    Ok(role)
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

/// An issuer's signing keys, fetched over HTTPS and cached for an hour.
pub struct Jwks {
    url: String,
    issuer: String,
    audience: String,
    cache: Mutex<Option<(Instant, HashMap<String, DecodingKey>)>>,
}

impl Jwks {
    pub fn new(url: String, issuer: String, audience: String) -> Self {
        Jwks { url, issuer, audience, cache: Mutex::new(None) }
    }

    pub async fn verify<T: DeserializeOwned>(&self, http: &reqwest::Client, token: &str) -> Result<T, String> {
        let kid = decode_header(token).map_err(|e| e.to_string())?.kid.ok_or("token has no kid")?;
        let key = match self.cached(&kid) {
            Some(k) => k,
            None => {
                self.refresh(http).await?;
                self.cached(&kid).ok_or("unknown signing key")?
            }
        };
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        decode::<T>(token, &key, &v).map(|d| d.claims).map_err(|e| e.to_string())
    }

    fn cached(&self, kid: &str) -> Option<DecodingKey> {
        let cache = self.cache.lock().unwrap();
        let (at, keys) = cache.as_ref()?;
        if at.elapsed() > Duration::from_secs(3600) {
            return None;
        }
        keys.get(kid).cloned()
    }

    async fn refresh(&self, http: &reqwest::Client) -> Result<(), String> {
        let set: JwkSet = http.get(&self.url).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        let keys = set
            .keys
            .into_iter()
            .filter_map(|k| DecodingKey::from_rsa_components(&k.n, &k.e).ok().map(|d| (k.kid, d)))
            .collect();
        *self.cache.lock().unwrap() = Some((Instant::now(), keys));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(email: &str, groups: &[&str], auth_time: i64) -> CognitoClaims {
        CognitoClaims {
            email: email.into(),
            token_use: "id".into(),
            auth_time,
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn roles_steps_and_identity() {
        let now = 1_700_000_000;
        assert_eq!(role_of(&["viewer".into(), "admin".into()]), Some(Role::Admin));
        assert_eq!(role_of(&["other".into()]), None);
        let viewer = id("a@x.com", &["viewer"], now);
        let admin = id("A@X.com", &["admin"], now - 10);
        assert_eq!(authorize("a@x.com", &viewer, Role::Viewer, false, now), Ok(Role::Viewer));
        assert_eq!(authorize("a@x.com", &viewer, Role::Admin, true, now), Err("forbidden"));
        assert_eq!(authorize("a@x.com", &admin, Role::Admin, true, now), Ok(Role::Admin), "email case-insensitive");
        assert_eq!(authorize("a@x.com", &admin, Role::Admin, true, now + STEP_UP_S), Err("step_up"));
        assert_eq!(authorize("b@x.com", &admin, Role::Viewer, false, now), Err("identity mismatch"));
        assert_eq!(authorize("a@x.com", &id("a@x.com", &[], now), Role::Viewer, false, now), Err("forbidden"));
        let mut access_token = id("a@x.com", &["admin"], now);
        access_token.token_use = "access".into();
        assert_eq!(authorize("a@x.com", &access_token, Role::Viewer, false, now), Err("login"));
    }
}
