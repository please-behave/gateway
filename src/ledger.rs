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

pub(crate) struct Ledger {
    client: Client,
    endpoint: Url,
}

impl Ledger {
    pub(crate) fn new(config: &Config) -> Result<Self> {
        let mut endpoint = parse_ledger_url(&config.ledger_url)?;
        endpoint.set_path("/v0/attestations");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT.min(config.request_timeout))
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .context("failed to initialize the ledger HTTP client")?;
        Ok(Self { client, endpoint })
    }

    pub(crate) fn request(&self) -> RequestBuilder {
        self.client.post(self.endpoint.clone())
    }

    pub(crate) async fn deliver(
        request: RequestBuilder,
        deadline: Instant,
        request_id: &RequestId,
    ) -> Response {
        timeout_at(deadline, send(request, request_id))
            .await
            .unwrap_or_else(|_| StatusCode::GATEWAY_TIMEOUT.into_response())
    }
}

async fn send(request: RequestBuilder, request_id: &RequestId) -> Response {
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
    if status != StatusCode::CREATED {
        tracing::warn!(
            request_id,
            ledger_status = status.as_u16(),
            "unexpected ledger status"
        );
        return StatusCode::BAD_GATEWAY.into_response();
    }

    match receipt(response).await {
        Ok(Some(id)) => (StatusCode::CREATED, Json(BTreeMap::from([("id", id)]))).into_response(),
        Err(error) if error.is_timeout() => StatusCode::GATEWAY_TIMEOUT.into_response(),
        _ => {
            tracing::warn!(request_id, "invalid ledger creation receipt");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn receipt(mut response: reqwest::Response) -> reqwest::Result<Option<String>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_RECEIPT_BYTES - body.len() {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    let Ok(Json(mut object)) = Json::<BTreeMap<String, String>>::from_bytes(&body) else {
        return Ok(None);
    };
    let id = object.remove("id");
    Ok(id.filter(|id| object.is_empty() && is_uuid_v7(id)))
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
