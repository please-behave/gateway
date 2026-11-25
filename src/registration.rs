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

pub(crate) const MAX_LEDGER_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum RegistrationKind {
    Rules,
    RuleSets,
}

impl RegistrationKind {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Rules => "/v0/rule-registrations",
            Self::RuleSets => "/v0/rule-set-registrations",
        }
    }

    pub(crate) fn validator(self) -> jsonschema::Validator {
        let bytes: &[u8] = match self {
            Self::Rules => include_bytes!("../why/contracts/ingest/rule-registration.schema.json"),
            Self::RuleSets => {
                include_bytes!("../why/contracts/ingest/rule-set-registration.schema.json")
            }
        };
        let schema = serde_json::from_slice(bytes).expect("bundled registration schema is JSON");
        jsonschema::validator_for(&schema).expect("bundled registration schema is valid")
    }

    pub(crate) fn envelope(
        self,
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

        let items = match self {
            Self::Rules => &request["rules"],
            Self::RuleSets => &request["sets"],
        }
        .as_array()
        .expect("validated registration array");
        if !items.iter().all(valid_source) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let receipt = match self {
            Self::Rules => RegistrationReceipt::Rules(items.len()),
            Self::RuleSets => {
                let mut member_counts = Vec::with_capacity(items.len());
                for set in items {
                    let members = set["members"].as_array().expect("validated members array");
                    if !members.iter().all(valid_source) {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    member_counts.push(members.len());
                }
                RegistrationReceipt::RuleSets(member_counts)
            }
        };

        if let Some(source) = required_source
            && items
                .iter()
                .any(|item| item["source"].as_str() != Some(source))
        {
            return Err(StatusCode::FORBIDDEN);
        }
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
}

fn valid_source(item: &Value) -> bool {
    let source = item["source"].as_str().expect("validated source");
    let (host, _) = source.split_once('/').expect("validated source separator");
    host.parse::<Authority>()
        .is_ok_and(|authority| authority.host() == host)
}

pub(crate) enum RegistrationReceipt {
    Rules(usize),
    RuleSets(Vec<usize>),
}

impl Receipt for RegistrationReceipt {
    const STATUS: StatusCode = StatusCode::OK;
    const INVALID_MESSAGE: &'static str = "invalid ledger registration receipt";

    fn path(&self) -> &'static str {
        match self {
            Self::Rules(_) => RegistrationKind::Rules.path(),
            Self::RuleSets(_) => RegistrationKind::RuleSets.path(),
        }
    }

    fn max_bytes(&self) -> usize {
        match self {
            Self::Rules(_) => 16 * 1024,
            Self::RuleSets(_) => 2 * 1024 * 1024,
        }
    }

    fn decode(self, body: &[u8]) -> Option<Response> {
        let StrictJson(receipt) = serde_json::from_slice(body).ok()?;
        let envelope = receipt.as_object().filter(|object| object.len() == 1)?;
        let outcomes = envelope.get("outcomes")?.as_array()?;
        let valid = match self {
            Self::Rules(count) => outcomes.len() == count && outcomes.iter().all(valid_outcome),
            Self::RuleSets(member_counts) => {
                outcomes.len() == member_counts.len()
                    && outcomes.iter().zip(member_counts).all(|(outcome, count)| {
                        valid_outcome(outcome) || valid_member_failures(outcome, count)
                    })
            }
        };
        valid.then(|| (Self::STATUS, Json(receipt)).into_response())
    }
}

fn valid_member_failures(value: &Value, count: usize) -> bool {
    let Some(outcome) = value.as_object().filter(|object| object.len() == 2) else {
        return false;
    };
    let Some(failures) = outcome.get("failures").and_then(Value::as_array) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    outcome.get("outcome").and_then(Value::as_str) == Some("invalid_members")
        && !failures.is_empty()
        && failures.len() <= count
        && failures.iter().all(|failure| {
            failure.as_object().is_some_and(|object| object.len() == 2)
                && matches!(
                    failure["reason"].as_str(),
                    Some("unregistered" | "digest_mismatch")
                )
                && failure["member_index"]
                    .as_u64()
                    .is_some_and(|index| index < count as u64 && seen.insert(index))
        })
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
        formatter.write_str("a JSON string, boolean, unsigned integer, array or object")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<StrictJson, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<StrictJson, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<StrictJson, E> {
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
