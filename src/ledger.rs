use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use reqwest::{Client, RequestBuilder, Url};
use tokio::time::{Instant, timeout_at};
use tower_http::request_id::RequestId;

use crate::{Config, parse_ledger_url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RECEIPT_BYTES: usize = 1024;
pub(crate) const MAX_LEDGER_BODY_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const RELEASE_PATH: &str = "/v0/facts/releases";

pub(crate) struct Ledger {
    client: Client,
    base: Url,
}

impl Ledger {
    pub(crate) fn new(config: &Config) -> Result<Self> {
        let mut base = parse_ledger_url(&config.ledger_url)?;
        base.set_query(None);
        base.set_fragment(None);
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT.min(config.request_timeout))
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .context("failed to initialize the ledger HTTP client")?;
        Ok(Self { client, base })
    }

    pub(crate) fn request(&self, receipt: &impl Receipt) -> RequestBuilder {
        let mut endpoint = self.base.clone();
        endpoint.set_path(receipt.path());
        self.client.post(endpoint)
    }

    pub(crate) async fn deliver(
        request: RequestBuilder,
        deadline: Instant,
        request_id: &RequestId,
        receipt: impl Receipt,
    ) -> Response {
        timeout_at(deadline, send(request, request_id, receipt))
            .await
            .unwrap_or_else(|_| StatusCode::GATEWAY_TIMEOUT.into_response())
    }
}

pub(crate) trait Receipt {
    const INVALID_MESSAGE: &'static str;

    fn path(&self) -> &'static str;
    fn max_bytes(&self) -> usize;
    fn accepts_status(&self, status: StatusCode) -> bool;
    fn decode(self, status: StatusCode, body: &[u8]) -> Option<Response>;
}

async fn send<R: Receipt>(request: RequestBuilder, request_id: &RequestId, receipt: R) -> Response {
    let request_id = request_id.header_value().to_str().expect("UUID is ASCII");
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) if error.is_timeout() => return StatusCode::GATEWAY_TIMEOUT.into_response(),
        Err(error) if error.is_connect() => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(_) => {
            tracing::warn!(request_id, "unreadable ledger response");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let status = response.status();
    if status.is_server_error() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if !receipt.accepts_status(status) {
        tracing::warn!(
            request_id,
            ledger_status = status.as_u16(),
            "unexpected ledger status"
        );
        return StatusCode::BAD_GATEWAY.into_response();
    }

    match read_receipt(response, receipt.max_bytes()).await {
        Ok(Some(body)) => match receipt.decode(status, &body) {
            Some(response) => response,
            None => invalid_receipt::<R>(request_id),
        },
        Err(error) if error.is_timeout() => StatusCode::GATEWAY_TIMEOUT.into_response(),
        _ => invalid_receipt::<R>(request_id),
    }
}

fn invalid_receipt<R: Receipt>(request_id: &str) -> Response {
    tracing::warn!(request_id, "{}", R::INVALID_MESSAGE);
    StatusCode::BAD_GATEWAY.into_response()
}

async fn read_receipt(
    mut response: reqwest::Response,
    limit: usize,
) -> reqwest::Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit - body.len() {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

pub(crate) struct AttestationReceipt;

impl Receipt for AttestationReceipt {
    const INVALID_MESSAGE: &'static str = "invalid ledger creation receipt";

    fn path(&self) -> &'static str {
        "/v0/attestations"
    }

    fn max_bytes(&self) -> usize {
        MAX_RECEIPT_BYTES
    }

    fn accepts_status(&self, status: StatusCode) -> bool {
        status == StatusCode::CREATED
    }

    fn decode(self, status: StatusCode, body: &[u8]) -> Option<Response> {
        let Json(mut object) = Json::<BTreeMap<String, String>>::from_bytes(body).ok()?;
        let id = object.remove("id")?;
        (object.is_empty() && is_uuid_v7(&id))
            .then(|| (status, Json(BTreeMap::from([("id", id)]))).into_response())
    }
}

pub(crate) struct ReleaseReceipt;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseOutcome {
    outcome: ReleaseOutcomeKind,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseOutcomeKind {
    Created,
    Unchanged,
    Conflict,
}

impl Receipt for ReleaseReceipt {
    const INVALID_MESSAGE: &'static str = "invalid ledger release receipt";

    fn path(&self) -> &'static str {
        RELEASE_PATH
    }

    fn max_bytes(&self) -> usize {
        MAX_RECEIPT_BYTES
    }

    fn accepts_status(&self, status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::CREATED | StatusCode::OK | StatusCode::CONFLICT
        )
    }

    fn decode(self, status: StatusCode, body: &[u8]) -> Option<Response> {
        let receipt: ReleaseOutcome = serde_json::from_slice(body).ok()?;
        let expected = match receipt.outcome {
            ReleaseOutcomeKind::Created => StatusCode::CREATED,
            ReleaseOutcomeKind::Unchanged => StatusCode::OK,
            ReleaseOutcomeKind::Conflict => StatusCode::CONFLICT,
        };
        (status == expected).then(|| (status, Json(receipt)).into_response())
    }
}

fn is_uuid_v7(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'7',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'A' | b'b' | b'B'),
            _ => byte.is_ascii_hexdigit(),
        })
}
