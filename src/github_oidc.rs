use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout_at},
};

use crate::optional;

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const SIGNING_KEYS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const SIGNING_KEY_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNING_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const SIGNING_KEY_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_SIGNING_KEYS_BYTES: usize = 64 * 1024;
const CLOCK_LEEWAY_SECONDS: u64 = 10;

#[derive(Clone)]
pub(crate) struct GitHubOidcConfig {
    repositories: Vec<(String, String)>,
    audience: String,
}

impl GitHubOidcConfig {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let repositories = optional("GATEWAY_GITHUB_OIDC_REPOSITORIES")?.unwrap_or_default();
        let audience = optional("GATEWAY_GITHUB_OIDC_AUDIENCE")?;
        Self::parse(&repositories, audience)
    }

    fn parse(repositories: &str, audience: Option<String>) -> Result<Option<Self>> {
        if repositories.trim().is_empty() {
            return Ok(None);
        }
        let repositories = repositories
            .split(',')
            .map(|entry| {
                let entry = entry.trim();
                let (owner, name) = entry.split_once('/')?;
                (valid_owner(owner) && (name == "*" || valid_repository_name(name)))
                    .then(|| (owner.to_ascii_lowercase(), name.to_ascii_lowercase()))
            })
            .collect::<Option<_>>()
            .context("GATEWAY_GITHUB_OIDC_REPOSITORIES must contain comma-separated <owner>/<name> or <owner>/* entries")?;
        let Some(audience) = audience
            .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        else {
            bail!(
                "GATEWAY_GITHUB_OIDC_AUDIENCE must be non-empty and contain no control characters when GitHub OIDC is enabled"
            );
        };
        Ok(Some(Self {
            repositories,
            audience,
        }))
    }

    fn sender(&self, repository: &str) -> Option<String> {
        let (owner, name) = repository.split_once('/')?;
        if !valid_owner(owner) || !valid_repository_name(name) {
            return None;
        }
        let owner = owner.to_ascii_lowercase();
        let name = name.to_ascii_lowercase();
        self.repositories
            .iter()
            .any(|(allowed_owner, allowed_name)| {
                *allowed_owner == owner && (allowed_name == "*" || *allowed_name == name)
            })
            .then(|| format!("github.com/{owner}/{name}"))
    }
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_repository_name(name: &str) -> bool {
    !matches!(name, "" | "." | "..")
        && name.len() <= 100
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(crate) fn is_compact_token(credential: &str) -> bool {
    let Some((header, rest)) = credential.split_once('.') else {
        return false;
    };
    let Some((payload, signature)) = rest.split_once('.') else {
        return false;
    };
    !header.is_empty()
        && !payload.is_empty()
        && [header, payload, signature].iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

pub(crate) struct GitHubOidc {
    config: GitHubOidcConfig,
    validation: Validation,
    client: reqwest::Client,
    signing_keys_url: String,
    signing_keys: Mutex<SigningKeys>,
}

#[derive(Default)]
struct SigningKeys {
    keys: HashMap<String, Arc<DecodingKey>>,
    expires_at: Option<Instant>,
    retry_at: Option<Instant>,
    fetch_failed: bool,
}

#[derive(Debug)]
pub(crate) enum AuthenticationError {
    Unauthorized,
    SigningKeysUnavailable,
}

#[derive(Deserialize)]
struct Claims {
    repository: String,
    iss: String,
    aud: String,
}

impl GitHubOidc {
    pub(crate) fn new(config: GitHubOidcConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(SIGNING_KEY_TIMEOUT)
            .timeout(SIGNING_KEY_TIMEOUT)
            .build()
            .context("failed to configure the GitHub OIDC signing-key client")?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[&config.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "nbf"]);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECONDS;
        Ok(Self {
            config,
            validation,
            client,
            signing_keys_url: SIGNING_KEYS_URL.into(),
            signing_keys: Mutex::default(),
        })
    }

    pub(crate) async fn authenticate(
        &self,
        token: &str,
        deadline: Instant,
    ) -> Result<String, AuthenticationError> {
        use AuthenticationError::{SigningKeysUnavailable, Unauthorized};

        let header = decode_header(token).map_err(|_| Unauthorized)?;
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty())
            .ok_or(Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(Unauthorized);
        }

        let key = timeout_at(deadline, self.signing_key(&kid))
            .await
            .map_err(|_| SigningKeysUnavailable)??;
        let claims = decode::<Claims>(token, &key, &self.validation)
            .map_err(|_| Unauthorized)?
            .claims;
        if claims.iss != ISSUER || claims.aud != self.config.audience {
            return Err(Unauthorized);
        }
        self.config.sender(&claims.repository).ok_or(Unauthorized)
    }

    async fn signing_key(&self, kid: &str) -> Result<Arc<DecodingKey>, AuthenticationError> {
        use AuthenticationError::{SigningKeysUnavailable, Unauthorized};

        // Serialize refreshes and apply the same cooldown across all key IDs.
        let mut cache = self.signing_keys.lock().await;
        let now = Instant::now();
        if cache.expires_at.is_some_and(|expires| now < expires)
            && let Some(key) = cache.keys.get(kid)
        {
            return Ok(Arc::clone(key));
        }
        if cache.retry_at.is_some_and(|retry| now < retry) {
            return Err(if cache.fetch_failed {
                SigningKeysUnavailable
            } else {
                Unauthorized
            });
        }

        cache.retry_at = Some(now + SIGNING_KEY_REFRESH_INTERVAL);
        cache.fetch_failed = true;
        cache.keys = self.fetch_keys().await.ok_or(SigningKeysUnavailable)?;
        cache.expires_at = Some(Instant::now() + SIGNING_KEY_LIFETIME);
        cache.fetch_failed = false;
        cache.keys.get(kid).cloned().ok_or(Unauthorized)
    }

    async fn fetch_keys(&self) -> Option<HashMap<String, Arc<DecodingKey>>> {
        let mut response = self.client.get(&self.signing_keys_url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if chunk.len() > MAX_SIGNING_KEYS_BYTES - body.len() {
                return None;
            }
            body.extend_from_slice(&chunk);
        }

        let mut keys = HashMap::new();
        for jwk in serde_json::from_slice::<JwkSet>(&body).ok()?.keys {
            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
                || jwk
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| *usage != PublicKeyUse::Signature)
                || jwk
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
                || jwk
                    .common
                    .key_algorithm
                    .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)
            {
                continue;
            }
            let key = DecodingKey::from_jwk(&jwk).ok()?;
            if let Some(kid) = jwk.common.key_id.filter(|kid| !kid.is_empty())
                && keys.insert(kid, Arc::new(key)).is_some()
            {
                return None;
            }
        }
        (!keys.is_empty()).then_some(keys)
    }
}

#[cfg(test)]
#[path = "../tests/github_oidc/mod.rs"]
mod tests;
