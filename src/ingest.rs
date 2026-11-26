use std::{
    collections::HashMap,
    fmt::{self, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{FromRequest, Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, RETRY_AFTER, WWW_AUTHENTICATE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use tokio::time::{Instant as Deadline, timeout_at};
use tower_http::{limit::RequestBodyLimitLayer, request_id::RequestId};

use crate::{
    Config,
    github_oidc::{self, AuthenticationError, GitHubOidc, GitHubOidcConfig},
    ledger::{AttestationReceipt, FactReceipt, Ledger, MAX_LEDGER_BODY_BYTES, Receipt},
    optional, positive,
    registration::{RegistrationKind, StrictJson},
};

const SCHEMA: &[u8] = include_bytes!("../why/contracts/ingest/attestation.schema.json");
const RELEASE_SCHEMA: &[u8] = include_bytes!("../why/contracts/ingest/release-fact.schema.json");
const DEPLOYMENT_SCHEMA: &[u8] =
    include_bytes!("../why/contracts/ingest/deployment-fact.schema.json");
const RATE_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_REQUESTS_PER_MINUTE: usize = 60;

#[derive(Clone)]
pub struct IngestConfig {
    keys: Vec<ApiKey>,
    github_oidc: Option<GitHubOidcConfig>,
    requests_per_minute: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            github_oidc: None,
            requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
        }
    }
}

impl fmt::Debug for IngestConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngestConfig")
            .field("key_count", &self.keys.len())
            .field("github_oidc_enabled", &self.github_oidc.is_some())
            .field("requests_per_minute", &self.requests_per_minute)
            .finish()
    }
}

impl IngestConfig {
    pub(crate) fn from_env() -> Result<Self> {
        let entries = optional("GATEWAY_API_KEYS")?.unwrap_or_default();
        let keys = if entries.is_empty() {
            Vec::new()
        } else {
            parse_keys(&entries)?
        };
        let requests_per_minute =
            positive("GATEWAY_RATE_LIMIT_PER_MINUTE", DEFAULT_REQUESTS_PER_MINUTE)?;
        Ok(Self {
            keys,
            github_oidc: GitHubOidcConfig::from_env()?,
            requests_per_minute,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(entries: &str, requests_per_minute: usize) -> Self {
        Self {
            keys: parse_keys(entries).expect("valid fixture API keys"),
            requests_per_minute,
            ..Self::default()
        }
    }

    pub(crate) fn github_oidc(&self) -> Result<Option<GitHubOidc>> {
        self.github_oidc.clone().map(GitHubOidc::new).transpose()
    }
}

#[derive(Clone)]
struct SenderLabel(Arc<str>);

impl SenderLabel {
    fn parse(label: &str) -> Option<Self> {
        (!label.is_empty()
            && label.len() <= 128
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        .then(|| Self(Arc::from(label)))
    }
}

#[derive(Clone)]
struct ApiKey {
    sender: SenderLabel,
    hash: [u8; 32],
}

fn parse_keys(entries: &str) -> Result<Vec<ApiKey>> {
    let mut keys: Vec<ApiKey> = Vec::new();
    for entry in entries.split(',') {
        let Some(key) = parse_key(entry) else {
            bail!(
                "GATEWAY_API_KEYS must contain comma-separated <sender>:<SHA-256 hex hash> entries"
            );
        };
        if keys
            .iter()
            .any(|other| bool::from(other.hash.ct_eq(&key.hash)))
        {
            bail!("GATEWAY_API_KEYS must not contain duplicate key hashes");
        }
        keys.push(key);
    }
    Ok(keys)
}

fn parse_key(entry: &str) -> Option<ApiKey> {
    let (label, hex) = entry.split_once(':')?;
    let sender = SenderLabel::parse(label)?;
    let mut hash = [0; 32];
    if hex.len() != hash.len() * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(ApiKey { sender, hash })
}

pub fn keygen(label: &str) -> Result<()> {
    let Some(sender) = SenderLabel::parse(label) else {
        bail!("sender must be 1 to 128 ASCII letters, digits, dots, underscores or hyphens");
    };
    let mut random = [0u8; 32];
    if OsRng.try_fill_bytes(&mut random).is_err() {
        bail!("failed to generate a key from the operating system's random source");
    }
    let mut key = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(key, "{byte:02x}").expect("writing to a String succeeds");
    }
    let hash = Sha256::digest(key.as_bytes());
    println!("Key: {key}\nGATEWAY_API_KEYS entry: {}:{hash:x}", sender.0);
    Ok(())
}

struct Ingest {
    keys: Vec<ActiveKey>,
    github_oidc: Option<GitHubOidc>,
    repository_windows: Mutex<RepositoryWindows>,
    requests_per_minute: usize,
    validator: jsonschema::Validator,
    registration_validator: jsonschema::Validator,
    rule_set_registration_validator: jsonschema::Validator,
    target_registration_validator: jsonschema::Validator,
    release_validator: jsonschema::Validator,
    deployment_validator: jsonschema::Validator,
    ledger: Ledger,
    request_timeout: Duration,
}

#[derive(Clone)]
struct Admitted {
    sender: Arc<str>,
    github_oidc: bool,
    deadline: Deadline,
}

impl Admitted {
    fn required_repository(&self) -> Option<&str> {
        self.github_oidc.then_some(&self.sender)
    }
}

struct ActiveKey {
    key: ApiKey,
    window: Mutex<Option<RateWindow>>,
}

struct RateWindow {
    start: Instant,
    used: usize,
}

impl RateWindow {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            used: 0,
        }
    }

    fn admit(&mut self, allowance: usize, now: Instant) -> Result<(), u64> {
        let mut elapsed = now.duration_since(self.start);
        if elapsed >= RATE_WINDOW {
            *self = Self::new(now);
            elapsed = Duration::ZERO;
        }
        if self.used >= allowance {
            let remaining = RATE_WINDOW - elapsed;
            return Err(remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0));
        }
        self.used += 1;
        Ok(())
    }
}

#[derive(Default)]
struct RepositoryWindows {
    windows: HashMap<Arc<str>, RateWindow>,
    next_cleanup: Option<Instant>,
}

impl RepositoryWindows {
    fn admit(&mut self, sender: &Arc<str>, allowance: usize) -> Result<(), u64> {
        let now = Instant::now();
        if self.next_cleanup.is_none_or(|cleanup| now >= cleanup) {
            self.windows
                .retain(|_, window| now.duration_since(window.start) < RATE_WINDOW);
            self.next_cleanup = Some(now + RATE_WINDOW);
        }
        self.windows
            .entry(Arc::clone(sender))
            .or_insert_with(|| RateWindow::new(now))
            .admit(allowance, now)
    }
}

impl Ingest {
    fn authenticate(&self, credential: &str) -> Option<&ActiveKey> {
        let hash = Sha256::digest(credential.as_bytes());
        let hash: [u8; 32] = hash.into();
        // Scan every configured digest and select the matching slot without an
        // early return or a branch on each comparison.
        let mut slot = 0;
        for (index, active) in self.keys.iter().enumerate() {
            slot =
                u64::conditional_select(&slot, &(index as u64 + 1), active.key.hash.ct_eq(&hash));
        }
        slot.checked_sub(1).map(|index| &self.keys[index as usize])
    }
}

fn bearer_key(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let (scheme, key) = values.next()?.to_str().ok()?.split_once(' ')?;
    let key = key.trim_start_matches(' ');
    (values.next().is_none()
        && scheme.eq_ignore_ascii_case("Bearer")
        && !key.is_empty()
        && !key.bytes().any(|byte| byte.is_ascii_whitespace()))
    .then_some(key)
}

pub(crate) fn routes(config: &Config, ledger: Ledger, github_oidc: Option<GitHubOidc>) -> Router {
    let Json(schema) = Json::from_bytes(SCHEMA).expect("bundled attestation schema is JSON");
    let validator =
        jsonschema::validator_for(&schema).expect("bundled attestation schema is valid");
    let Json(release_schema) =
        Json::from_bytes(RELEASE_SCHEMA).expect("bundled release fact schema is JSON");
    let Json(deployment_schema) =
        Json::from_bytes(DEPLOYMENT_SCHEMA).expect("bundled deployment fact schema is JSON");
    let state = Arc::new(Ingest {
        keys: config
            .ingest
            .keys
            .iter()
            .cloned()
            .map(|key| ActiveKey {
                key,
                window: Mutex::new(None),
            })
            .collect(),
        github_oidc,
        repository_windows: Mutex::default(),
        requests_per_minute: config.ingest.requests_per_minute,
        validator,
        registration_validator: RegistrationKind::Rules.validator(),
        rule_set_registration_validator: RegistrationKind::RuleSets.validator(),
        target_registration_validator: RegistrationKind::Targets.validator(),
        release_validator: jsonschema::validator_for(&release_schema)
            .expect("bundled release fact schema is valid"),
        deployment_validator: jsonschema::validator_for(&deployment_schema)
            .expect("bundled deployment fact schema is valid"),
        ledger,
        request_timeout: config.request_timeout,
    });

    let admission = middleware::from_fn_with_state(state.clone(), admit);
    let mut router = Router::new().route(
        "/v0/attestations",
        post(attest)
            .route_layer(RequestBodyLimitLayer::new(config.max_body_bytes))
            .route_layer(admission.clone()),
    );

    for kind in [
        RegistrationKind::Rules,
        RegistrationKind::RuleSets,
        RegistrationKind::Targets,
    ] {
        router = router.route(
            kind.path(),
            post(register)
                .route_layer(axum::Extension(kind))
                .route_layer(RequestBodyLimitLayer::new(
                    config.max_body_bytes.min(MAX_LEDGER_BODY_BYTES),
                ))
                .route_layer(admission.clone()),
        );
    }

    for receipt in [FactReceipt::Release, FactReceipt::Deployment] {
        router = router.route(
            receipt.path(),
            post(record_fact)
                .route_layer(axum::Extension(receipt))
                .route_layer(RequestBodyLimitLayer::new(
                    config.max_body_bytes.min(MAX_LEDGER_BODY_BYTES),
                ))
                .route_layer(admission.clone()),
        );
    }
    router.with_state(state)
}

async fn admit(State(state): State<Arc<Ingest>>, mut request: Request, next: Next) -> Response {
    let deadline = Deadline::now() + state.request_timeout;
    let Some(credential) = bearer_key(request.headers()) else {
        return unauthorized();
    };
    let (sender, github_oidc, allowance) = if let Some(oidc) = &state.github_oidc
        && github_oidc::is_compact_token(credential)
    {
        let sender = match oidc.authenticate(credential, deadline).await {
            Ok(sender) => Arc::from(sender),
            Err(AuthenticationError::Unauthorized) => return unauthorized(),
            Err(AuthenticationError::SigningKeysUnavailable) => {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };
        let allowance = state
            .repository_windows
            .lock()
            .expect("repository rate-limit counters are available")
            .admit(&sender, state.requests_per_minute);
        (sender, true, allowance)
    } else {
        let Some(active) = state.authenticate(credential) else {
            return unauthorized();
        };
        let mut window = active
            .window
            .lock()
            .expect("rate-limit counter is available");
        let now = Instant::now();
        let allowance = window
            .get_or_insert_with(|| RateWindow::new(now))
            .admit(state.requests_per_minute, now);
        (Arc::clone(&active.key.sender.0), false, allowance)
    };
    if let Err(seconds) = allowance {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, seconds.to_string())],
        )
            .into_response();
    }
    request.headers_mut().remove(AUTHORIZATION);
    request.extensions_mut().insert(Admitted {
        sender,
        github_oidc,
        deadline,
    });
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    response
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response()
}

async fn attest(
    State(state): State<Arc<Ingest>>,
    axum::Extension(admitted): axum::Extension<Admitted>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    request: Request,
) -> Response {
    let bytes = match read_body(request, admitted.deadline).await {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let Ok(Json::<serde_json::Value>(attestation)) = Json::from_bytes(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !state.validator.is_valid(&attestation) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(repository) = admitted.required_repository()
        && attestation["repository"].as_str() != Some(repository)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if Deadline::now() >= admitted.deadline {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }

    let envelope = std::collections::BTreeMap::from([
        ("sender", admitted.sender.to_string().into()),
        ("attestation", canonical_attestation(attestation)),
    ]);
    let request = state.ledger.request(&AttestationReceipt).json(&envelope);
    Ledger::deliver(request, admitted.deadline, &request_id, AttestationReceipt).await
}

// The validated public document already has the ledger's canonical field layout.
fn canonical_attestation<T>(attestation: T) -> T {
    attestation
}

async fn register(
    State(state): State<Arc<Ingest>>,
    axum::Extension(admitted): axum::Extension<Admitted>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    axum::Extension(kind): axum::Extension<RegistrationKind>,
    request: Request,
) -> Response {
    let bytes = match read_body(request, admitted.deadline).await {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let validator = match kind {
        RegistrationKind::Rules => &state.registration_validator,
        RegistrationKind::RuleSets => &state.rule_set_registration_validator,
        RegistrationKind::Targets => &state.target_registration_validator,
    };
    let (body, receipt) = match kind.envelope(
        &bytes,
        validator,
        &admitted.sender,
        admitted.required_repository(),
    ) {
        Ok(envelope) => envelope,
        Err(status) => return status.into_response(),
    };
    if Deadline::now() >= admitted.deadline {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }

    let request = state
        .ledger
        .request(&receipt)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body);
    Ledger::deliver(request, admitted.deadline, &request_id, receipt).await
}

async fn record_fact(
    State(state): State<Arc<Ingest>>,
    axum::Extension(admitted): axum::Extension<Admitted>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    axum::Extension(receipt): axum::Extension<FactReceipt>,
    request: Request,
) -> Response {
    let bytes = match read_body(request, admitted.deadline).await {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let Ok(StrictJson(mut fact)) = serde_json::from_slice(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let validator = match receipt {
        FactReceipt::Release => &state.release_validator,
        FactReceipt::Deployment => &state.deployment_validator,
    };
    if !validator.is_valid(&fact) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if matches!(receipt, FactReceipt::Release)
        && let Some(repository) = admitted.required_repository()
        && fact["repository"].as_str() != Some(repository)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if Deadline::now() >= admitted.deadline {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }

    let auth_method = if admitted.github_oidc {
        "github_oidc"
    } else {
        "api_key"
    };
    fact["sender"] = admitted.sender.as_ref().into();
    fact["auth_method"] = auth_method.into();
    let request = state.ledger.request(&receipt).json(&fact);
    Ledger::deliver(request, admitted.deadline, &request_id, receipt).await
}

async fn read_body(request: Request, deadline: Deadline) -> Result<Bytes, StatusCode> {
    match timeout_at(deadline, Bytes::from_request(request, &())).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(error.status()),
        Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
    }
}
