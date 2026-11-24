use std::{collections::BTreeSet, fmt};

use axum::{
    Json,
    http::{StatusCode, uri::Authority},
    response::{IntoResponse, Response},
};
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

use crate::ledger::Receipt;

const SCHEMA: &[u8] = include_bytes!("../why/contracts/ingest/rule-registration.schema.json");
pub(crate) const MAX_LEDGER_BODY_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn validator() -> jsonschema::Validator {
    let schema = serde_json::from_slice(SCHEMA).expect("bundled registration schema is JSON");
    jsonschema::validator_for(&schema).expect("bundled registration schema is valid")
}

pub(crate) fn envelope(
    body: &[u8],
    validator: &jsonschema::Validator,
    sender: &str,
    required_source: Option<&str>,
) -> Result<(Vec<u8>, RegistrationReceipt), StatusCode> {
    let StrictJson(mut request) =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !validator.is_valid(&request) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rules = request["rules"].as_array().expect("validated rules array");
    if !rules.iter().all(|rule| {
        let source = rule["source"].as_str().expect("validated rule source");
        let (host, _) = source.split_once('/').expect("validated source separator");
        host.parse::<Authority>()
            .is_ok_and(|authority| authority.host() == host)
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(source) = required_source
        && rules
            .iter()
            .any(|rule| rule["source"].as_str() != Some(source))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let receipt = RegistrationReceipt { count: rules.len() };
    request
        .as_object_mut()
        .expect("validated registration object")
        .insert("sender".into(), sender.into());

    let body = serde_json::to_vec(&request).expect("serialize validated JSON");
    if body.len() > MAX_LEDGER_BODY_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok((body, receipt))
}

pub(crate) struct RegistrationReceipt {
    count: usize,
}

impl Receipt for RegistrationReceipt {
    const PATH: &'static str = "/v0/rule-registrations";
    const STATUS: StatusCode = StatusCode::OK;
    const MAX_BYTES: usize = 16 * 1024;
    const INVALID_MESSAGE: &'static str = "invalid ledger registration receipt";

    fn decode(self, body: &[u8]) -> Option<Response> {
        let StrictJson(receipt) = serde_json::from_slice(body).ok()?;
        let envelope = receipt.as_object()?;
        let outcomes = envelope.get("outcomes")?.as_array()?;
        (envelope.len() == 1 && outcomes.len() == self.count && outcomes.iter().all(valid_outcome))
            .then(|| (Self::STATUS, Json(receipt)).into_response())
    }
}

fn valid_outcome(value: &Value) -> bool {
    let Some(outcome) = value.as_object().filter(|object| object.len() == 2) else {
        return false;
    };
    matches!(
        outcome.get("outcome").and_then(Value::as_str),
        Some("created" | "unchanged" | "conflict")
    ) && outcome
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|digest| digest.strip_prefix("v1:sha256:"))
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

// The ledger's digest format requires unique keys even after newline normalization.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON string, boolean, array or object")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<StrictJson, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<StrictJson, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut input: S) -> Result<StrictJson, S::Error> {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = input.next_element()? {
            values.push(value);
        }
        Ok(StrictJson(values.into()))
    }

    fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<StrictJson, M::Error> {
        let mut values = Map::new();
        let mut normalized = BTreeSet::new();
        while let Some(key) = input.next_key::<String>()? {
            if !normalized.insert(key.replace("\r\n", "\n").replace('\r', "\n")) {
                return Err(M::Error::custom("duplicate JSON object key"));
            }
            let StrictJson(value) = input.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictJson(values.into()))
    }
}
