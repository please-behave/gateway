//! REQ-0003, REQ-0005, REQ-0006, REQ-0007, REQ-0011, REQ-0012, REQ-0013, REQ-0014, REQ-0015, REQ-0016

use std::{sync::Mutex as StdMutex, time::Duration};

use axum::{
    Json, Router,
    extract::MatchedPath,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};

use super::*;
use crate::{Config, IngestConfig, gateway_routes, ledger::Ledger};

const AUDIENCE: &str = "gateway fixture audience";
const API_KEY: &str = "offline-fixture-api-key";
const REPOSITORY: &str = "github.com/example/project";
const ATTESTATIONS: &str = "/v0/attestations";
const REGISTRATIONS: &str = "/v0/rule-registrations";
const RULE_SETS: &str = "/v0/rule-set-registrations";
const RELEASES: &str = "/v0/facts/releases";
const TARGETS: &str = "/v0/target-registrations";
const INVALID: &str = "invalid.jwt.fixture";

struct SigningFixture {
    jwk: Value,
    key: EncodingKey,
}

impl SigningFixture {
    fn new(json: &str) -> Self {
        let fixture: Value = serde_json::from_str(json).unwrap();
        let hex: String = fixture["synthetic_signing_key_der_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap())
            .collect();
        let der: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
            .collect();
        Self {
            jwk: fixture["jwk"].clone(),
            key: EncodingKey::from_rsa_der(&der),
        }
    }

    fn first() -> Self {
        Self::new(include_str!("first.json"))
    }

    fn rotated() -> Self {
        Self::new(include_str!("rotated.json"))
    }

    fn token(&self, repository: &str) -> String {
        self.sign(claims(repository), self.jwk["kid"].as_str().unwrap())
    }

    fn sign(&self, claims: Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(&header, &claims, &self.key).unwrap()
    }
}

fn claims(repository: &str) -> Value {
    let now = get_current_timestamp();
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "nbf": now - 1,
        "repository": repository
    })
}

struct Server {
    url: String,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct KeyEndpointState {
    keys: Value,
    requests: usize,
}

async fn keys(State(state): State<Arc<StdMutex<KeyEndpointState>>>) -> Json<Value> {
    let mut state = state.lock().unwrap();
    state.requests += 1;
    Json(state.keys.clone())
}

async fn key_endpoint(fixture: &SigningFixture) -> (Server, Arc<StdMutex<KeyEndpointState>>) {
    let state = Arc::new(StdMutex::new(KeyEndpointState {
        keys: json!({"keys": [fixture.jwk]}),
        requests: 0,
    }));
    let server = Server::start(
        Router::new()
            .route("/jwks", get(keys))
            .with_state(state.clone()),
    )
    .await;
    (server, state)
}

type LedgerRequests = Arc<StdMutex<Vec<Value>>>;

async fn ledger_endpoint() -> (Server, LedgerRequests) {
    async fn attest(
        State(records): State<LedgerRequests>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        assert!(!headers.contains_key("authorization"));
        records.lock().unwrap().push(body);
        (
            StatusCode::CREATED,
            Json(json!({"id": "0198b0a7-46a8-7000-8000-000000000001"})),
        )
    }

    async fn register(
        State(records): State<LedgerRequests>,
        path: MatchedPath,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        assert!(!headers.contains_key("authorization"));
        let collection = if path.as_str() == RULE_SETS {
            "sets"
        } else {
            "rules"
        };
        let outcomes: Vec<_> = body[collection].as_array().unwrap().iter().map(|_| {
            json!({"outcome": "created", "digest": format!("v1:sha256:{}", "a".repeat(64))})
        }).collect();
        records.lock().unwrap().push(body);
        Json(json!({"outcomes": outcomes}))
    }

    async fn release(
        State(records): State<LedgerRequests>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        assert!(!headers.contains_key("authorization"));
        records.lock().unwrap().push(body);
        (StatusCode::CREATED, Json(json!({"outcome": "created"})))
    }

    async fn register_targets(
        State(records): State<LedgerRequests>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        assert!(!headers.contains_key("authorization"));
        let outcomes: Vec<_> = body["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|target| json!({"name": target["name"], "outcome": "created"}))
            .collect();
        records.lock().unwrap().push(body);
        Json(json!({"outcomes": outcomes}))
    }

    let requests = LedgerRequests::default();
    let router = Router::new()
        .route(ATTESTATIONS, post(attest))
        .route(REGISTRATIONS, post(register))
        .route(RULE_SETS, post(register))
        .route(RELEASES, post(release))
        .route(TARGETS, post(register_targets))
        .with_state(requests.clone());
    (Server::start(router).await, requests)
}

fn verifier(repositories: &str, signing_keys_url: String) -> GitHubOidc {
    let config = GitHubOidcConfig::parse(repositories, Some(AUDIENCE.into()))
        .unwrap()
        .unwrap();
    let mut oidc = GitHubOidc::new(config).unwrap();
    oidc.signing_keys_url = signing_keys_url;
    oidc
}

async fn gateway(
    oidc: GitHubOidc,
    ledger_url: &str,
    allowance: usize,
    timeout: Duration,
) -> Server {
    let keys =
        [API_KEY, INVALID].map(|key| format!("fixture:{:x}", Sha256::digest(key.as_bytes())));
    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ledger_url: ledger_url.into(),
        max_body_bytes: 8192,
        request_timeout: timeout,
        ingest: IngestConfig::for_tests(&keys.join(","), allowance),
    };
    Server::start(gateway_routes(
        &config,
        Ledger::new(&config).unwrap(),
        Some(oidc),
    ))
    .await
}

fn attestation(repository: &str) -> Value {
    json!({
        "schema_version": 1,
        "repository": repository,
        "commit": "0123456789abcdef",
        "execution_points": ["pre-push"],
        "overall": "PASS",
        "results": [{"id":"test","kind":"check","status":"WARN"}]
    })
}

fn release_fact(repository: &str) -> Value {
    json!({
        "repository": repository,
        "version": "v1",
        "commit": "0123456789abcdef0123456789abcdef01234567"
    })
}

fn registration(sources: &[&str]) -> Value {
    let rules: Vec<_> = sources.iter().enumerate().map(|(index, source)| {
        json!({
            "source": source, "path": ".", "id": format!("test-{index}"), "version": "1.0",
            "kind": "check", "name": "Test", "description": "Test rule",
            "knowledge": {
                "purpose": "Validate test data.", "problem": "Test data can be invalid.",
                "value": "Valid test data.", "placement": "A check.",
                "conditions": [{"statement": "Test data is valid.", "rationale": "Required by the test."}]
            }
        })
    }).collect();
    json!({"commit": "0123456789abcdef0123456789abcdef01234567", "rules": rules})
}

fn rule_set_registration(source: &str, member_source: &str) -> Value {
    json!({
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "sets": [{
            "source": source, "path": ".", "id": "baseline", "version": "1.0",
            "members": [{
                "source": member_source, "path": ".", "id": "verify", "version": "2.0",
                "digest": format!("v1:sha256:{}", "a".repeat(64)), "enabled": true
            }]
        }]
    })
}

async fn submit(
    gateway: &Server,
    path: &str,
    credential: &str,
    body: Value,
    status: StatusCode,
) -> HeaderMap {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .post(format!("{}{path}", gateway.url))
        .bearer_auth(credential)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), status);
    let headers = response.headers().clone();
    if status.is_client_error() || status.is_server_error() {
        assert!(response.bytes().await.unwrap().is_empty());
    }
    headers
}

#[tokio::test]
async fn verifies_github_oidc_claims_and_reuses_the_signing_keys() {
    let fixture = SigningFixture::first();
    let (endpoint, requests) = key_endpoint(&fixture).await;
    let oidc = verifier("EXAMPLE/Project,Other/*", format!("{}/jwks", endpoint.url));
    let deadline = || Instant::now() + Duration::from_secs(2);
    assert_eq!(
        oidc.authenticate(&fixture.token("Example/pRoJeCt"), deadline())
            .await
            .unwrap(),
        REPOSITORY
    );
    assert_eq!(
        oidc.authenticate(&fixture.token("oThEr/SECOND"), deadline())
            .await
            .unwrap(),
        "github.com/other/second"
    );
    assert!(matches!(
        oidc.authenticate(&fixture.token("example/other"), deadline())
            .await,
        Err(AuthenticationError::Unauthorized)
    ));

    let now = get_current_timestamp();
    for (claim, value) in [
        ("iss", json!("https://issuer.test")),
        ("iss", json!([ISSUER])),
        ("aud", json!("Gateway fixture audience")),
        ("aud", json!([AUDIENCE, "other audience"])),
        ("exp", json!(now - 60)),
        ("nbf", json!(now + 60)),
        ("nbf", Value::Null),
        ("repository", json!("other/*")),
    ] {
        let mut claims = claims("example/project");
        claims[claim] = value;
        assert!(
            matches!(
                oidc.authenticate(&fixture.sign(claims, "first"), deadline())
                    .await,
                Err(AuthenticationError::Unauthorized)
            ),
            "accepted invalid {claim}"
        );
    }

    let unknown = fixture.sign(claims("example/project"), "unknown");
    assert!(matches!(
        oidc.authenticate(&unknown, deadline()).await,
        Err(AuthenticationError::Unauthorized)
    ));
    let wrong_signature = SigningFixture::rotated().sign(claims("example/project"), "first");
    assert!(matches!(
        oidc.authenticate(&wrong_signature, deadline()).await,
        Err(AuthenticationError::Unauthorized)
    ));
    assert_eq!(requests.lock().unwrap().requests, 1);
}

#[tokio::test]
async fn refreshes_rotated_keys_and_bounds_fetches_across_unknown_key_ids() {
    let fixture = SigningFixture::first();
    let rotated = SigningFixture::rotated();
    let (endpoint, requests) = key_endpoint(&fixture).await;
    let oidc = verifier("example/*", format!("{}/jwks", endpoint.url));
    let deadline = || Instant::now() + Duration::from_secs(2);
    let first_token = fixture.token("example/project");
    assert!(oidc.authenticate(&first_token, deadline()).await.is_ok());

    requests.lock().unwrap().keys = json!({"keys": [rotated.jwk]});
    let rotated_token = rotated.token("example/project");
    assert!(matches!(
        oidc.authenticate(&rotated_token, deadline()).await,
        Err(AuthenticationError::Unauthorized)
    ));
    assert_eq!(requests.lock().unwrap().requests, 1);

    oidc.signing_keys.lock().await.retry_at = Some(Instant::now());
    assert!(oidc.authenticate(&rotated_token, deadline()).await.is_ok());
    assert!(matches!(
        oidc.authenticate(&first_token, deadline()).await,
        Err(AuthenticationError::Unauthorized)
    ));
    assert_eq!(requests.lock().unwrap().requests, 2);
}

#[tokio::test]
async fn forwards_owned_ingest_and_shares_only_the_repository_rate_allowance() {
    let fixture = SigningFixture::first();
    let (endpoint, key_requests) = key_endpoint(&fixture).await;
    let (ledger, requests) = ledger_endpoint().await;
    let oidc = verifier("example/*", format!("{}/jwks", endpoint.url));
    let gateway = gateway(oidc, &ledger.url, 5, Duration::from_secs(2)).await;

    let token = fixture.token("Example/Project");
    submit(
        &gateway,
        ATTESTATIONS,
        &token,
        attestation(REPOSITORY),
        StatusCode::CREATED,
    )
    .await;
    submit(
        &gateway,
        REGISTRATIONS,
        &token,
        registration(&[REPOSITORY]),
        StatusCode::OK,
    )
    .await;
    let other = "github.com/example/other";
    submit(
        &gateway,
        RULE_SETS,
        &token,
        rule_set_registration(REPOSITORY, other),
        StatusCode::OK,
    )
    .await;
    submit(
        &gateway,
        RELEASES,
        &token,
        release_fact(REPOSITORY),
        StatusCode::CREATED,
    )
    .await;
    let targets = json!({"targets": [{"name": "staging"}]});
    submit(&gateway, TARGETS, &token, targets, StatusCode::OK).await;
    let token = fixture.token("example/project");
    let headers = submit(
        &gateway,
        ATTESTATIONS,
        &token,
        attestation(REPOSITORY),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert!(headers.contains_key("retry-after"));
    submit(
        &gateway,
        ATTESTATIONS,
        &fixture.token("example/other"),
        attestation(other),
        StatusCode::CREATED,
    )
    .await;
    submit(
        &gateway,
        ATTESTATIONS,
        API_KEY,
        attestation(REPOSITORY),
        StatusCode::CREATED,
    )
    .await;
    submit(
        &gateway,
        REGISTRATIONS,
        API_KEY,
        registration(&[REPOSITORY, other]),
        StatusCode::OK,
    )
    .await;
    submit(
        &gateway,
        ATTESTATIONS,
        INVALID,
        attestation(REPOSITORY),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let records = requests.lock().unwrap();
    assert_eq!(records.len(), 8);
    assert_eq!(records[0]["sender"], REPOSITORY);
    assert_eq!(records[1]["sender"], REPOSITORY);
    assert_eq!(records[1]["rules"][0]["source"], REPOSITORY);
    assert_eq!(records[2]["sender"], REPOSITORY);
    assert_eq!(records[2]["sets"][0]["members"][0]["source"], other);
    assert_eq!(
        records[3],
        json!({
            "repository": REPOSITORY,
            "version": "v1",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "sender": REPOSITORY,
            "auth_method": "github_oidc"
        })
    );
    assert_eq!(
        records[4],
        json!({"sender": REPOSITORY, "targets": [{"name": "staging"}]})
    );
    assert_eq!(records[5]["sender"], other);
    assert_eq!(records[6]["sender"], "fixture");
    assert_eq!(records[7]["sender"], "fixture");
    assert_eq!(key_requests.lock().unwrap().requests, 1);
}

#[tokio::test]
async fn rejects_repository_mismatches_before_forwarding_any_ingest_request() {
    let fixture = SigningFixture::first();
    let (endpoint, _) = key_endpoint(&fixture).await;
    let (ledger, requests) = ledger_endpoint().await;
    let oidc = verifier("example/project", format!("{}/jwks", endpoint.url));
    let gateway = gateway(oidc, &ledger.url, 10, Duration::from_secs(2)).await;

    let token = fixture.token("example/project");
    let other = "github.com/example/other";
    submit(
        &gateway,
        ATTESTATIONS,
        &token,
        attestation(other),
        StatusCode::FORBIDDEN,
    )
    .await;
    submit(
        &gateway,
        REGISTRATIONS,
        &token,
        registration(&[REPOSITORY, other]),
        StatusCode::FORBIDDEN,
    )
    .await;
    let mut batch = rule_set_registration(REPOSITORY, other);
    batch["sets"]
        .as_array_mut()
        .unwrap()
        .push(rule_set_registration(other, REPOSITORY)["sets"][0].clone());
    submit(&gateway, RULE_SETS, &token, batch, StatusCode::FORBIDDEN).await;
    submit(
        &gateway,
        RELEASES,
        &token,
        release_fact(other),
        StatusCode::FORBIDDEN,
    )
    .await;
    let headers = submit(
        &gateway,
        ATTESTATIONS,
        &fixture.token("example/other"),
        attestation(other),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(headers["www-authenticate"], "Bearer");
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unavailable_signing_keys_leave_readiness_and_api_key_ingest_operational() {
    let fixture = SigningFixture::first();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    drop(listener);
    let (ledger, requests) = ledger_endpoint().await;
    let oidc = verifier("example/*", url);
    let gateway = gateway(oidc, &ledger.url, 2, Duration::from_secs(2)).await;

    let token = fixture.token("example/project");
    submit(
        &gateway,
        ATTESTATIONS,
        &token,
        attestation(REPOSITORY),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    submit(
        &gateway,
        REGISTRATIONS,
        &token,
        registration(&[REPOSITORY]),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let ready = reqwest::get(format!("{}/readyz", gateway.url))
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::NO_CONTENT);
    submit(
        &gateway,
        ATTESTATIONS,
        API_KEY,
        attestation(REPOSITORY),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn refuses_signing_key_redirects_and_applies_the_ingest_deadline() {
    let fixture = SigningFixture::first();
    let (endpoint, requests) = key_endpoint(&fixture).await;
    let target = format!("{}/jwks", endpoint.url);
    let redirects = Server::start(Router::new().route(
        "/",
        get(move || async move { (StatusCode::FOUND, [("location", target)]) }),
    ))
    .await;
    let hangs = Server::start(Router::new().route(
        "/",
        get(|| async { std::future::pending::<StatusCode>().await }),
    ))
    .await;
    let (ledger, _) = ledger_endpoint().await;
    let token = fixture.token("example/project");
    for url in [redirects.url.clone(), hangs.url.clone()] {
        let oidc = verifier("example/*", url);
        let gateway = gateway(oidc, &ledger.url, 2, Duration::from_millis(200)).await;
        submit(
            &gateway,
            ATTESTATIONS,
            &token,
            attestation(REPOSITORY),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
    }
    assert_eq!(requests.lock().unwrap().requests, 0);
}
