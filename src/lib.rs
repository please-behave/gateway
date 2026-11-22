use std::{env, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, MatchedPath, Request},
    http::{Method, StatusCode, header::ALLOW},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::any,
};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestId, MakeRequestUuid},
    timeout::TimeoutLayer,
};

mod ingest;
mod ledger;
mod registration;

pub use ingest::{IngestConfig, keygen};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;
const DEFAULT_REQUEST_TIMEOUT_MS: usize = 30_000;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub ledger_url: String,
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub ingest: IngestConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr = optional("GATEWAY_BIND_ADDR")?
            .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_owned())
            .parse()
            .context("GATEWAY_BIND_ADDR must be a socket address, for example 0.0.0.0:8080")?;
        let ledger_url = required("GATEWAY_LEDGER_URL")?;
        parse_ledger_url(&ledger_url)?;
        let max_body_bytes = positive("GATEWAY_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?;
        let request_timeout_ms =
            positive("GATEWAY_REQUEST_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS)?;

        Ok(Self {
            bind_addr,
            ledger_url,
            max_body_bytes,
            request_timeout: Duration::from_millis(request_timeout_ms as u64),
            ingest: IngestConfig::from_env()?,
        })
    }
}

pub fn app(config: &Config) -> Router {
    build_app(config).expect("valid gateway configuration and ledger client")
}

fn build_app(config: &Config) -> Result<Router> {
    let ledger = ledger::Ledger::new(config)?;
    let health_routes = Router::new()
        .route("/healthz", any(health))
        .route("/readyz", any(health))
        .layer(RequestBodyLimitLayer::new(config.max_body_bytes))
        .layer(request_timeout(config));
    Ok(log_requests(
        health_routes.merge(ingest::routes(config, ledger)),
    ))
}

pub fn with_limits(router: Router, config: &Config) -> Router {
    log_requests(
        router
            .layer(RequestBodyLimitLayer::new(config.max_body_bytes))
            .layer(request_timeout(config)),
    )
}

fn request_timeout(config: &Config) -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, config.request_timeout)
}

fn log_requests(router: Router) -> Router {
    router
        .layer(DefaultBodyLimit::disable())
        .layer(axum::middleware::from_fn(log_request))
}

pub async fn run() -> Result<()> {
    init_logging();
    let config = Config::from_env()?;
    let app = build_app(&config)?;
    #[cfg(unix)]
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register the gateway shutdown signal")?;
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind gateway to {}", config.bind_addr))?;
    let address = listener
        .local_addr()
        .context("failed to read gateway address")?;
    tracing::info!(%address, "gateway started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(
            #[cfg(unix)]
            terminate,
        ))
        .await
        .context("gateway server failed")
}

async fn health(request: Request) -> Response {
    if request.method() != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "GET")]).into_response();
    }

    // Read the bounded body so the size limit also applies to chunked requests.
    match Bytes::from_request(request, &()).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.status().into_response(),
    }
}

async fn log_request(mut request: Request, next: Next) -> Response {
    let request_id = MakeRequestUuid
        .make_request_id(&request)
        .expect("MakeRequestUuid always generates a request ID");
    let header = request_id.header_value().clone();
    request.headers_mut().insert("x-request-id", header.clone());
    request.extensions_mut().insert(request_id);
    let route = request.extensions().get::<MatchedPath>().cloned();
    let mut response = next.run(request).await;
    tracing::info!(
        request_id = header.to_str().expect("UUID is ASCII"),
        route = route.as_ref().map(MatchedPath::as_str),
        status = response.status().as_u16(),
        "request completed"
    );
    response.headers_mut().insert("x-request-id", header);
    response
}

fn init_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .with_current_span(true)
        .init();
}

async fn shutdown_signal(#[cfg(unix)] mut terminate: tokio::signal::unix::Signal) {
    #[cfg(unix)]
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("gateway shutting down");
}

fn required(name: &str) -> Result<String> {
    match optional(name)? {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => bail!("{name} must be set and non-empty"),
    }
}

fn optional(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

fn positive(name: &str, default: usize) -> Result<usize> {
    let Some(value) = optional(name)? else {
        return Ok(default);
    };
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("{name} must be a positive integer"))?;
    if parsed == 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(parsed)
}

fn parse_ledger_url(value: &str) -> Result<reqwest::Url> {
    const INVALID_URL: &str =
        "GATEWAY_LEDGER_URL must be an absolute HTTP or HTTPS URL without user information";
    let uri = value.parse::<axum::http::Uri>().context(INVALID_URL)?;
    let authority = uri.authority().context(INVALID_URL)?;
    let host = authority.host();
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || authority.as_str().contains('@')
        || host.is_empty()
        || (authority.as_str() != host && authority.port_u16().is_none())
    {
        bail!(INVALID_URL);
    }
    reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!(INVALID_URL))
}
