use std::{
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
    ledger::{AttestationReceipt, Ledger},
    optional, positive,
    registration::{self, RegistrationReceipt},
};

const SCHEMA: &[u8] = include_bytes!("../why/contracts/ingest/attestation.schema.json");
const RATE_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_REQUESTS_PER_MINUTE: usize = 60;

#[derive(Clone)]
pub struct IngestConfig {
    keys: Vec<ApiKey>,
    requests_per_minute: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
        }
    }
}

impl fmt::Debug for IngestConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngestConfig")
            .field("key_count", &self.keys.len())
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
            requests_per_minute,
        })
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
    requests_per_minute: usize,
    validator: jsonschema::Validator,
    registration_validator: jsonschema::Validator,
    ledger: Ledger,
    request_timeout: Duration,
}

#[derive(Clone)]
struct Admitted {
    sender: SenderLabel,
    deadline: Deadline,
}

struct ActiveKey {
    key: ApiKey,
    window: Mutex<Option<RateWindow>>,
}

struct RateWindow {
    start: Instant,
    used: usize,
}

impl ActiveKey {
    fn admit(&self, allowance: usize) -> Result<(), u64> {
        let mut window = self.window.lock().expect("rate-limit counter is available");
        let now = Instant::now();
        let window = window.get_or_insert(RateWindow {
            start: now,
            used: 0,
        });
        let elapsed = now.duration_since(window.start);
        if elapsed >= RATE_WINDOW {
            *window = RateWindow {
                start: now,
                used: 0,
            };
        }
        if window.used >= allowance {
            let remaining = RATE_WINDOW - elapsed;
            return Err(remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0));
        }
        window.used += 1;
        Ok(())
    }
}

impl Ingest {
    fn authenticate(&self, headers: &HeaderMap) -> Option<&ActiveKey> {
        let hash = Sha256::digest(bearer_key(headers)?.as_bytes());
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

pub(crate) fn routes(config: &Config, ledger: Ledger) -> Router {
    let Json(schema) = Json::from_bytes(SCHEMA).expect("bundled attestation schema is JSON");
    let validator =
        jsonschema::validator_for(&schema).expect("bundled attestation schema is valid");
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
        requests_per_minute: config.ingest.requests_per_minute,
        validator,
        registration_validator: registration::validator(),
        ledger,
        request_timeout: config.request_timeout,
    });

    let admission = middleware::from_fn_with_state(state.clone(), admit);
    Router::new()
        .route(
            "/v0/attestations",
            post(attest)
                .route_layer(RequestBodyLimitLayer::new(config.max_body_bytes))
                .route_layer(admission.clone()),
        )
        .route(
            "/v0/rule-registrations",
            post(register)
                .route_layer(RequestBodyLimitLayer::new(
                    config
                        .max_body_bytes
                        .min(registration::MAX_LEDGER_BODY_BYTES),
                ))
                .route_layer(admission),
        )
        .with_state(state)
}

async fn admit(State(state): State<Arc<Ingest>>, mut request: Request, next: Next) -> Response {
    let deadline = Deadline::now() + state.request_timeout;
    let Some(active) = state.authenticate(request.headers()) else {
        return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response();
    };
    if let Err(seconds) = active.admit(state.requests_per_minute) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, seconds.to_string())],
        )
            .into_response();
    }
    request.headers_mut().remove(AUTHORIZATION);
    request.extensions_mut().insert(Admitted {
        sender: active.key.sender.clone(),
        deadline,
    });
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    response
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
    let Ok(Json(attestation)) = Json::from_bytes(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !state.validator.is_valid(&attestation) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if Deadline::now() >= admitted.deadline {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }

    let envelope = std::collections::BTreeMap::from([
        ("sender", admitted.sender.0.to_string().into()),
        ("attestation", canonical_attestation(attestation)),
    ]);
    let request = state.ledger.request::<AttestationReceipt>().json(&envelope);
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
    request: Request,
) -> Response {
    let bytes = match read_body(request, admitted.deadline).await {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let (body, receipt) =
        match registration::envelope(&bytes, &state.registration_validator, &admitted.sender.0) {
            Ok(envelope) => envelope,
            Err(status) => return status.into_response(),
        };
    if Deadline::now() >= admitted.deadline {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }

    let request = state
        .ledger
        .request::<RegistrationReceipt>()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body);
    Ledger::deliver(request, admitted.deadline, &request_id, receipt).await
}

async fn read_body(request: Request, deadline: Deadline) -> Result<Bytes, StatusCode> {
    match timeout_at(deadline, Bytes::from_request(request, &())).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(error.status()),
        Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
    }
}
