//! REQ-0002, REQ-0003, REQ-0005, REQ-0006, REQ-0007, REQ-0008, REQ-0009, REQ-0010, REQ-0011, REQ-0012, REQ-0013, REQ-0014

mod support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};

use axum::Json;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::http::{Gateway, request, start_gateway, unused_address};

const FIRST_KEY: &str = "fixture-ingest-key-first";
const SECOND_KEY: &str = "fixture-ingest-key-second";
const VALID: &str = r#"{"schema_version":1,"repository":"github.com/example/project","commit":"0123456789abcdef","execution_points":["pre-push"],"overall":"PASS","results":[{"id":"test","kind":"check","status":"WARN"}]}"#;
const RULE_IDENTITY: &str =
    r#""source":"github.com/example/rules","path":"rules/verify","id":"verify""#;
const RECEIPT: &str = r#"{"id":"0198b0a7-46a8-7000-8000-000000000001"}"#;
const RELEASE_PATH: &str = "/v0/facts/releases";
const RELEASE_COMMIT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const RELEASE: &str = r#"{"repository":"git.example.org/team/project","version":"  Release 1  ","commit":"0123456789ABCDEF0123456789ABCDEF01234567"}"#;

fn entry(sender: &str, key: &str) -> String {
    format!("{sender}:{:x}", Sha256::digest(key.as_bytes()))
}

fn start_ingest(keys: &str, allowance: usize, body_limit: usize) -> Gateway {
    start_with_ledger(keys, allowance, body_limit, 1000, unused_address())
}

fn start_with_ledger(
    keys: &str,
    allowance: usize,
    body_limit: usize,
    timeout_ms: usize,
    ledger_address: SocketAddr,
) -> Gateway {
    start_gateway(body_limit, timeout_ms, |command| {
        command
            .env(
                "GATEWAY_LEDGER_URL",
                format!("http://{ledger_address}/unused?configuration=ignored"),
            )
            .env("GATEWAY_API_KEYS", keys)
            .env("GATEWAY_RATE_LIMIT_PER_MINUTE", allowance.to_string());
    })
}

struct LedgerStub {
    address: SocketAddr,
    requests: Receiver<(Vec<String>, Vec<u8>)>,
    thread: Option<JoinHandle<()>>,
}

impl LedgerStub {
    fn start(
        status: u16,
        headers: String,
        body: String,
        before_headers: Duration,
        before_body: Duration,
    ) -> Self {
        Self::serve(
            status,
            headers,
            move || body.clone(),
            before_headers,
            before_body,
        )
    }

    fn serve(
        status: u16,
        headers: String,
        mut response_body: impl FnMut() -> String + Send + 'static,
        before_headers: Duration,
        before_body: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stand-in ledger");
        let address = listener.local_addr().unwrap();
        let (sender, requests) = mpsc::channel();
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept ledger connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut headers_received = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).expect("read ledger headers") == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    headers_received.push(line.trim_end().to_owned());
                }
                let length = headers_received
                    .iter()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .expect("ledger request has content length")
                    .parse()
                    .unwrap();
                let mut request_body = vec![0; length];
                reader
                    .read_exact(&mut request_body)
                    .expect("read ledger envelope");
                sender.send((headers_received, request_body)).unwrap();
                thread::sleep(before_headers);
                let body = response_body();
                let response_headers = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}\r\n",
                    body.len()
                );
                if stream.write_all(response_headers.as_bytes()).is_ok() {
                    thread::sleep(before_body);
                    let _ = stream.write_all(body.as_bytes());
                }
            }
        });
        Self {
            address,
            requests,
            thread: Some(thread),
        }
    }

    fn reply(status: u16, body: &str) -> Self {
        Self::start(
            status,
            String::new(),
            body.into(),
            Duration::ZERO,
            Duration::ZERO,
        )
    }
}

impl Drop for LedgerStub {
    fn drop(&mut self) {
        let _ = TcpStream::connect(self.address)
            .map(|stream| stream.shutdown(std::net::Shutdown::Both));
        self.thread.take().unwrap().join().unwrap();
    }
}

fn submit(gateway: &Gateway, key: Option<&str>, headers: &str, body: &str) -> String {
    post(gateway, "/v0/attestations", key, headers, body)
}

fn post(gateway: &Gateway, path: &str, key: Option<&str>, headers: &str, body: &str) -> String {
    let auth = key
        .map(|key| format!("Authorization: Bearer {key}\r\n"))
        .unwrap_or_default();
    request(
        gateway.address,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{auth}{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn expect_status(response: &str, status: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "{response}"
    );
    if status >= 400 {
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "", "{response}");
    }
    assert!(response.contains("\r\nx-request-id: "), "{response}");
}

#[test]
fn forwards_release_facts_once_and_relays_each_ledger_outcome() {
    for (status, outcome) in [(201, "created"), (200, "unchanged"), (409, "conflict")] {
        let receipt = json!({"outcome": outcome}).to_string();
        let ledger = LedgerStub::reply(status, &receipt);
        let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 1024, 1000, ledger.address);
        let body = if status == 200 {
            RELEASE.replace(RELEASE_COMMIT, &"a".repeat(64))
        } else {
            RELEASE.to_owned()
        };
        let response = post(&gateway, RELEASE_PATH, Some(FIRST_KEY), "", &body);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{response}"
        );
        assert!(response.contains("\r\ncontent-type: application/json\r\n"));
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, receipt);

        let (headers, forwarded) = ledger.requests.try_recv().unwrap();
        assert_eq!(headers[0], "POST /v0/facts/releases HTTP/1.1");
        assert!(
            !headers
                .iter()
                .any(|header| header.starts_with("authorization:"))
        );
        let mut expected: Value = serde_json::from_str(&body).unwrap();
        expected["sender"] = "build".into();
        expected["auth_method"] = "api_key".into();
        assert_eq!(
            serde_json::from_slice::<Value>(&forwarded).unwrap(),
            expected
        );
        assert!(ledger.requests.try_recv().is_err());
    }
}

#[test]
fn rejects_invalid_release_requests_and_shares_the_ingest_allowance() {
    let ledger = LedgerStub::reply(201, r#"{"outcome":"created"}"#);
    let invalid = [
        "{".to_owned(),
        RELEASE.replace(RELEASE_COMMIT, &"a".repeat(39)),
        RELEASE.replace(RELEASE_COMMIT, &"g".repeat(40)),
        RELEASE.replace(RELEASE_COMMIT, &format!(r"{RELEASE_COMMIT}\n")),
        RELEASE.replace("  Release 1  ", ""),
        RELEASE.replace("  Release 1  ", &"é".repeat(257)),
        RELEASE.replace("  Release 1  ", r"release\u0000"),
        RELEASE.replacen('{', r#"{"sender":"forged","#, 1),
        RELEASE.replacen('{', r#"{"auth_method":"github_oidc","#, 1),
        RELEASE.replacen('{', r#"{"version":"duplicate","#, 1),
        RELEASE.replace(r#""version":"  Release 1  ","#, ""),
    ];
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        invalid.len() + 1,
        1024,
        1000,
        ledger.address,
    );
    for credential in [None, Some(SECOND_KEY)] {
        let response = post(&gateway, RELEASE_PATH, credential, "", RELEASE);
        expect_status(&response, 401);
        assert!(response.contains("\r\nwww-authenticate: Bearer\r\n"));
    }
    for body in invalid {
        expect_status(
            &post(&gateway, RELEASE_PATH, Some(FIRST_KEY), "", &body),
            400,
        );
    }
    let oversized = " ".repeat(1025);
    expect_status(
        &post(&gateway, RELEASE_PATH, Some(FIRST_KEY), "", &oversized),
        413,
    );
    let limited = submit(&gateway, Some(FIRST_KEY), "", VALID);
    expect_status(&limited, 429);
    assert!(limited.contains("\r\nretry-after: "));
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn reports_release_delivery_failures_without_retrying() {
    let keys = entry("build", FIRST_KEY);
    let offline = start_ingest(&keys, 1, 1024);
    expect_status(
        &post(&offline, RELEASE_PATH, Some(FIRST_KEY), "", RELEASE),
        503,
    );

    for (ledger_status, receipt, gateway_status) in [
        (500, "failure", 503),
        (400, "unexpected rejection", 502),
        (200, r#"{"outcome":"created"}"#, 502),
        (409, r#"{"outcome":"conflict","outcome":"conflict"}"#, 502),
        (201, r#"{"outcome":"created","extra":"unexpected"}"#, 502),
    ] {
        let ledger = LedgerStub::reply(ledger_status, receipt);
        let gateway = start_with_ledger(&keys, 1, 1024, 1000, ledger.address);
        expect_status(
            &post(&gateway, RELEASE_PATH, Some(FIRST_KEY), "", RELEASE),
            gateway_status,
        );
        assert!(ledger.requests.try_recv().is_ok());
        assert!(ledger.requests.try_recv().is_err());
    }
}

#[test]
fn forwards_one_canonical_envelope_with_only_the_authenticated_sender() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 1024, 1000, ledger.address);
    let response = submit(
        &gateway,
        Some(FIRST_KEY),
        "X-Sender: impersonator\r\nForwarded: for=192.0.2.1\r\nX-Request-Id: client-id\r\nContent-Type: text/plain\r\n",
        VALID,
    );
    expect_status(&response, 201);
    assert!(response.contains("\r\ncontent-type: application/json\r\n"));
    assert_eq!(response.split_once("\r\n\r\n").unwrap().1, RECEIPT);

    let (headers, body) = ledger.requests.try_recv().unwrap();
    assert_eq!(headers[0], "POST /v0/attestations HTTP/1.1");
    for header in &headers[1..] {
        let (name, _) = header.split_once(':').unwrap();
        assert!(
            matches!(name, "host" | "content-length" | "content-type" | "accept"),
            "{header}"
        );
    }
    assert!(
        headers
            .iter()
            .any(|header| header == "content-type: application/json")
    );
    let expected = format!(r#"{{"const":{{"sender":"build","attestation":{VALID}}}}}"#);
    let Json(expected) = Json::from_bytes(expected.as_bytes()).unwrap();
    let Json(body) = Json::from_bytes(&body).unwrap();
    assert!(
        jsonschema::validator_for(&expected)
            .unwrap()
            .is_valid(&body)
    );
    assert!(ledger.requests.try_recv().is_err());
}

fn with_rule(rule: &str) -> String {
    VALID.replace(
        r#""status":"WARN""#,
        &format!(r#""status":"WARN","rule":{rule}"#),
    )
}

#[test]
fn forwards_rule_identity_and_versioned_metadata_unchanged() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 2, 1024, 1000, ledger.address);
    for rule in [
        format!("{{{RULE_IDENTITY}}}"),
        format!(r#"{{{RULE_IDENTITY},"version":"0.12","digest":"fixture-digest"}}"#),
    ] {
        let attestation = with_rule(&rule);
        expect_status(&submit(&gateway, Some(FIRST_KEY), "", &attestation), 201);

        let (_, body) = ledger.requests.try_recv().unwrap();
        let expected = format!(r#"{{"const":{{"sender":"build","attestation":{attestation}}}}}"#);
        let Json(expected) = Json::from_bytes(expected.as_bytes()).unwrap();
        let Json(body) = Json::from_bytes(&body).unwrap();
        assert!(
            jsonschema::validator_for(&expected)
                .unwrap()
                .is_valid(&body)
        );
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn rejects_invalid_rule_metadata_before_forwarding() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 20, 2048, 1000, ledger.address);
    let oversized_source = "x".repeat(257);
    let oversized_path = "x".repeat(257);
    let oversized_id = "x".repeat(129);
    let oversized_version_major = "1".repeat(63);
    let oversized_digest = "x".repeat(129);

    for rule in [
        "null".into(),
        r#"{"path":"rules/verify","id":"verify"}"#.into(),
        format!(r#"{{{RULE_IDENTITY},"extra":"unknown"}}"#),
        format!(r#"{{{RULE_IDENTITY},"version":"1.2"}}"#),
        format!(r#"{{{RULE_IDENTITY},"digest":"fixture-digest"}}"#),
        format!(r#"{{{RULE_IDENTITY},"version":"01.2","digest":"fixture-digest"}}"#),
        format!(r#"{{{RULE_IDENTITY},"version":"1.2\n","digest":"fixture-digest"}}"#),
        format!(
            r#"{{{RULE_IDENTITY},"version":"{oversized_version_major}.0","digest":"fixture-digest"}}"#
        ),
        format!(r#"{{{RULE_IDENTITY},"version":"1.2","digest":"{oversized_digest}"}}"#),
        format!(r#"{{{RULE_IDENTITY},"version":"1.2","digest":""}}"#),
        format!(r#"{{{RULE_IDENTITY},"version":"1.2","digest":"fixture\u0000digest"}}"#),
        format!(r#"{{"source":"{oversized_source}","path":"rules/verify","id":"verify"}}"#),
        format!(
            r#"{{"source":"github.com/example/rules","path":"{oversized_path}","id":"verify"}}"#
        ),
        format!(
            r#"{{"source":"github.com/example/rules","path":"rules/verify","id":"{oversized_id}"}}"#
        ),
    ] {
        let response = submit(&gateway, Some(FIRST_KEY), "", &with_rule(&rule));
        assert!(response.starts_with("HTTP/1.1 400 "), "{rule}: {response}");
        expect_status(&response, 400);
    }
    assert!(ledger.requests.try_recv().is_err());
}

fn bound_rule_set() -> Value {
    json!({
        "source": "github.com/example/rules",
        "path": "rules/verify",
        "id": "verify",
        "version": "0.12",
        "execution_points": ["check", "pre-push"],
    })
}

#[test]
fn forwards_bound_rule_sets_unchanged_when_present() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 3, 4096, 1000, ledger.address);
    let mut attestation: Value = serde_json::from_str(VALID).unwrap();
    attestation["execution_points"] = json!(["check", "pre-push"]);
    let mut local_set = bound_rule_set();
    local_set["source"] = attestation["repository"].clone();
    local_set["path"] = json!(".");
    local_set["execution_points"] = json!(["check"]);

    let mut empty = attestation.clone();
    empty["rule_sets"] = json!([]);
    let mut populated = attestation.clone();
    populated["rule_sets"] = json!([bound_rule_set(), local_set]);

    for payload in [attestation, empty, populated] {
        expect_status(
            &submit(&gateway, Some(FIRST_KEY), "", &payload.to_string()),
            201,
        );
        let (_, body) = ledger.requests.try_recv().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"sender": "build", "attestation": payload}),
        );
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn rejects_malformed_or_oversized_rule_set_bindings_before_forwarding() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        40,
        32 * 1024,
        1000,
        ledger.address,
    );
    let mut attestation: Value = serde_json::from_str(VALID).unwrap();
    let binding = bound_rule_set();
    let mut invalid_bindings = vec![json!(null)];
    for field in binding.as_object().unwrap().keys() {
        let mut incomplete = binding.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        invalid_bindings.push(incomplete);
    }
    for (field, value) in [
        ("source", json!("github.com:443/example/rules")),
        ("source", json!("https://github.com/example/rules")),
        ("source", json!(format!("github.com/{}", "x".repeat(246)))),
        ("path", json!("../rules")),
        ("path", json!("x".repeat(257))),
        ("id", json!("")),
        ("id", json!("x".repeat(129))),
        ("version", json!("01.2")),
        ("version", json!("1.2\n")),
        ("version", json!(format!("{}.0", "1".repeat(63)))),
        ("execution_points", json!([])),
        ("execution_points", json!(vec!["check"; 65])),
        ("execution_points", json!(["x".repeat(129)])),
        ("execution_points", json!([""])),
        ("execution_points", json!(["check\0"])),
        ("execution_points", json!("check")),
        ("extra", json!(true)),
    ] {
        let mut invalid = binding.clone();
        invalid[field] = value;
        invalid_bindings.push(invalid);
    }
    let mut invalid_lists = vec![json!(null), binding.clone(), json!(vec![binding; 101])];
    invalid_lists.extend(invalid_bindings.into_iter().map(|entry| json!([entry])));
    for rule_sets in invalid_lists {
        attestation["rule_sets"] = rule_sets;
        expect_status(
            &submit(&gateway, Some(FIRST_KEY), "", &attestation.to_string()),
            400,
        );
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn maps_ledger_failure_statuses_and_logs_unexpected_responses_without_documents() {
    for (ledger_status, ledger_body, gateway_status) in [
        (500, "upstream diagnostic", 503),
        (503, "upstream diagnostic", 503),
        (400, "upstream diagnostic", 502),
        (200, RECEIPT, 502),
        (0, "upstream diagnostic", 502),
        (201, "upstream diagnostic", 502),
        (201, r#"{"id":"upstream diagnostic"}"#, 502),
        (
            201,
            r#"{"id":"0198b0a7-46a8-7000-8000-000000000001","extra":"detail"}"#,
            502,
        ),
    ] {
        let ledger = LedgerStub::reply(ledger_status, ledger_body);
        let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 1024, 1000, ledger.address);
        let response = submit(&gateway, Some(FIRST_KEY), "", VALID);
        expect_status(&response, gateway_status);
        let logs = gateway.stop();
        if gateway_status == 502 {
            assert!(
                logs.contains("unexpected ledger status")
                    || logs.contains("invalid ledger creation receipt")
                    || logs.contains("unreadable ledger response"),
                "{logs}"
            );
        }
        assert!(!logs.contains("github.com/example/project"));
        assert!(!logs.contains("upstream diagnostic"));
        assert!(ledger.requests.try_recv().is_ok());
        assert!(ledger.requests.try_recv().is_err());
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        1,
        1024,
        1000,
        listener.local_addr().unwrap(),
    );
    drop(listener);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 503);
}

#[test]
fn classifies_redirects_as_unexpected_without_following_them() {
    let target = LedgerStub::reply(201, RECEIPT);
    let ledger = LedgerStub::start(
        307,
        format!("Location: http://{}/v0/attestations\r\n", target.address),
        String::new(),
        Duration::ZERO,
        Duration::ZERO,
    );
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 1024, 1000, ledger.address);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 502);
    assert!(ledger.requests.try_recv().is_ok());
    assert!(target.requests.try_recv().is_err());
}

#[test]
fn times_out_while_waiting_for_ledger_headers_or_the_creation_receipt() {
    let delay = Duration::from_millis(400);
    for (before_headers, before_body) in [(delay, Duration::ZERO), (Duration::ZERO, delay)] {
        let ledger = LedgerStub::start(
            201,
            String::new(),
            RECEIPT.into(),
            before_headers,
            before_body,
        );
        let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 1024, 150, ledger.address);
        expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 504);
        assert!(ledger.requests.try_recv().is_ok());
    }
}

#[test]
fn rejected_and_incomplete_requests_never_reach_the_ledger() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let limit = VALID.len() + 32;
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 3, limit, 150, ledger.address);
    expect_status(&submit(&gateway, None, "", VALID), 401);
    expect_status(
        &submit(&gateway, Some(FIRST_KEY), "", &"x".repeat(limit + 1)),
        413,
    );
    let impersonation = VALID.replace(
        "\"overall\":\"PASS\",",
        "\"overall\":\"PASS\",\"sender\":\"x\",",
    );
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", &impersonation), 400);
    let incomplete = request(
        gateway.address,
        &format!(
            "POST /v0/attestations HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: Bearer {FIRST_KEY}\r\nContent-Length: 3\r\n\r\n{{"
        ),
    );
    expect_status(&incomplete, 408);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 429);
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn authenticates_before_rate_and_checks_size_before_schema() {
    let keys = entry("build", FIRST_KEY);
    let gateway = start_ingest(&keys, 2, VALID.len());
    let oversized = "x".repeat(VALID.len() + 1);

    let missing = submit(&gateway, None, "", &oversized);
    expect_status(&missing, 401);
    assert!(missing.contains("\r\nwww-authenticate: Bearer\r\n"));
    expect_status(&submit(&gateway, Some(SECOND_KEY), "", "{"), 401);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", &oversized), 413);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", "{"), 400);

    for body in ["{", &oversized, VALID] {
        let limited = submit(&gateway, Some(FIRST_KEY), "", body);
        expect_status(&limited, 429);
        let seconds: u64 = limited
            .lines()
            .find_map(|line| line.strip_prefix("retry-after: "))
            .expect("rate-limit response has Retry-After")
            .parse()
            .expect("Retry-After is a whole number of seconds");
        assert!((1..=60).contains(&seconds));
    }
    expect_status(&submit(&gateway, None, "", &oversized), 401);
}

#[test]
fn accepts_both_rotation_keys_and_limits_each_key_and_instance_independently() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let keys = format!(
        "{},{}",
        entry("build", FIRST_KEY),
        entry("build", SECOND_KEY)
    );
    let gateway = start_with_ledger(&keys, 1, 1024, 1000, ledger.address);
    let peer = start_with_ledger(&keys, 1, 1024, 1000, ledger.address);
    let rotated = start_with_ledger(&entry("build", SECOND_KEY), 1, 1024, 1000, ledger.address);

    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 201);
    expect_status(
        &submit(
            &gateway,
            Some(FIRST_KEY),
            "Forwarded: for=192.0.2.1\r\nX-Forwarded-For: 192.0.2.2\r\n",
            VALID,
        ),
        429,
    );
    expect_status(&submit(&gateway, Some(SECOND_KEY), "", VALID), 201);
    expect_status(&submit(&peer, Some(FIRST_KEY), "", VALID), 201);
    expect_status(&submit(&rotated, Some(FIRST_KEY), "", VALID), 401);
    expect_status(&submit(&rotated, Some(SECOND_KEY), "", VALID), 201);
}

#[test]
fn authentication_uses_constant_time_digest_comparison_and_selection() {
    // Response timing cannot reliably distinguish how the digests are compared.
    let source = include_str!("../src/ingest.rs");
    let authentication = source
        .split_once("fn authenticate(")
        .unwrap()
        .1
        .split_once("fn bearer_key(")
        .unwrap()
        .0;
    assert!(authentication.contains("active.key.hash.ct_eq(&hash)"));
    assert!(authentication.contains("u64::conditional_select"));
}

#[test]
fn rejects_malformed_credentials_and_omits_credentials_from_output() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let keys = entry("build", FIRST_KEY);
    let gateway = start_with_ledger(&keys, 2, 1024, 1000, ledger.address);
    for auth in [
        format!("Authorization: Basic {FIRST_KEY}\r\n"),
        format!("Authorization: Bearer {FIRST_KEY}\r\nAuthorization: Bearer {SECOND_KEY}\r\n"),
        format!("Authorization: Bearer {SECOND_KEY}\r\n"),
    ] {
        let response = submit(&gateway, None, &auth, VALID);
        expect_status(&response, 401);
        assert!(!response.contains(FIRST_KEY) && !response.contains(SECOND_KEY));
    }
    let unauthenticated = submit(
        &gateway,
        None,
        &format!("X-Forwarded-Authorization: Bearer {FIRST_KEY}\r\n"),
        VALID,
    );
    expect_status(&unauthenticated, 401);
    let invalid = submit(
        &gateway,
        Some(FIRST_KEY),
        &format!("X-Request-Id: {FIRST_KEY}\r\n"),
        &format!(r#"{{"sender":"{FIRST_KEY}"}}"#),
    );
    expect_status(&invalid, 400);
    assert!(!invalid.contains(FIRST_KEY));
    let valid = submit(
        &gateway,
        None,
        &format!("Authorization: bEaReR  {FIRST_KEY}\r\n"),
        VALID,
    );
    expect_status(&valid, 201);
    assert!(!valid.contains(FIRST_KEY));
    let limited = submit(&gateway, Some(FIRST_KEY), "", VALID);
    expect_status(&limited, 429);
    assert!(!limited.contains(FIRST_KEY));
    let logs = gateway.stop().to_ascii_lowercase();
    assert!(logs.contains("request completed"));
    assert!(!logs.contains(FIRST_KEY) && !logs.contains(SECOND_KEY));
    assert!(!logs.contains(&keys));
    assert!(!logs.contains("authorization"));
}

#[test]
fn rejects_invalid_attestation_shapes_and_bounds() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        60,
        128 * 1024,
        1000,
        ledger.address,
    );
    let too_many_results = [r#"{"id":"test","kind":"check","status":"PASS"}"#; 1025].join(",");
    for invalid in [
        VALID.replacen('{', r#"{"sender":"build","#, 1),
        VALID.replace(r#""id":"test""#, r#""id":"test","details":"extra""#),
        VALID.replace(r#""schema_version":1,"#, ""),
        VALID.replace(r#""schema_version":1"#, r#""schema_version":"1""#),
        VALID.replace(r#""schema_version":1"#, r#""schema_version":2147483648"#),
        VALID.replace(r#""overall":"PASS""#, r#""overall":"WARN""#),
        VALID.replace(r#""kind":"check""#, r#""kind":"unknown""#),
        VALID.replace(r#""status":"WARN""#, r#""status":"unknown""#),
        VALID.replace(r#"["pre-push"]"#, r#""pre-push""#),
        VALID.replace(
            r#"["pre-push"]"#,
            &format!("[{}]", [r#""pre-push""#; 65].join(",")),
        ),
        VALID.replace("pre-push", &"x".repeat(129)),
        VALID.replace("github.com/example/project", &"x".repeat(2049)),
        VALID.replace("0123456789abcdef", &"x".repeat(65)),
        VALID.replace(r#""id":"test""#, &format!(r#""id":"{}""#, "x".repeat(513))),
        VALID.replace(
            r#"{"id":"test","kind":"check","status":"WARN"}"#,
            &too_many_results,
        ),
        format!("{VALID}{{}}"),
    ] {
        expect_status(&submit(&gateway, Some(FIRST_KEY), "", &invalid), 400);
    }
    for (overall, kind, status) in [
        ("PASS", "check", "PASS"),
        ("FAIL", "review", "FAIL"),
        ("ERROR", "integrity", "ERROR"),
        ("PASS", "review", "NOT_RUN"),
        ("PASS", "review", "WARN"),
    ] {
        let valid = VALID
            .replace(r#""overall":"PASS""#, &format!(r#""overall":"{overall}""#))
            .replace(r#""kind":"check""#, &format!(r#""kind":"{kind}""#))
            .replace(r#""status":"WARN""#, &format!(r#""status":"{status}""#));
        expect_status(&submit(&gateway, Some(FIRST_KEY), "", &valid), 201);
    }
}

#[test]
fn applies_the_body_limit_to_chunked_ingest_and_refuses_other_methods() {
    let gateway = start_ingest(&entry("build", FIRST_KEY), 1, 3);
    let method = request(
        gateway.address,
        "GET /v0/attestations HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    expect_status(&method, 405);
    assert!(method.contains("\r\nallow: POST\r\n"));
    let chunked = request(
        gateway.address,
        &format!(
            "POST /v0/attestations HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {FIRST_KEY}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n"
        ),
    );
    expect_status(&chunked, 413);
}

#[test]
fn invalid_ingest_configuration_fails_without_echoing_the_input() {
    let duplicate = format!(
        "{},{}",
        entry("first", FIRST_KEY),
        entry("second", FIRST_KEY)
    );
    for (variable, value) in [
        ("GATEWAY_API_KEYS", format!("build:{FIRST_KEY}")),
        ("GATEWAY_API_KEYS", format!("bad label:{}", "0".repeat(64))),
        ("GATEWAY_API_KEYS", duplicate),
        ("GATEWAY_RATE_LIMIT_PER_MINUTE", "0".to_owned()),
    ] {
        let result = support::command(env!("CARGO_BIN_EXE_gateway"))
            .env("GATEWAY_LEDGER_URL", "http://ledger.test")
            .env(variable, &value)
            .output()
            .expect("run gateway with invalid configuration");
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(error.contains(variable), "{error}");
        if variable == "GATEWAY_API_KEYS" {
            assert!(!error.contains(&value) && !error.contains(FIRST_KEY));
        }
    }
}

#[test]
fn rejects_invalid_github_oidc_configuration_before_serving() {
    let repositories_var = "GATEWAY_GITHUB_OIDC_REPOSITORIES";
    let audience_var = "GATEWAY_GITHUB_OIDC_AUDIENCE";
    for (repositories, audience, invalid) in [
        (
            "github.com/example/project",
            Some("fixture"),
            repositories_var,
        ),
        ("example/pro*", Some("fixture"), repositories_var),
        ("*/project", Some("fixture"), repositories_var),
        ("example/project,", Some("fixture"), repositories_var),
        ("example/project", None, audience_var),
        ("example/project", Some("  "), audience_var),
        ("example/project", Some("fixture\n"), audience_var),
    ] {
        let mut command = support::command(env!("CARGO_BIN_EXE_gateway"));
        command
            .env("GATEWAY_LEDGER_URL", "http://ledger.test")
            .env(repositories_var, repositories);
        if let Some(audience) = audience {
            command.env(audience_var, audience);
        }

        let result = command
            .output()
            .expect("run gateway with invalid configuration");
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(error.contains(invalid), "{error}");
        assert!(!error.contains(repositories));
    }
}

#[test]
fn github_oidc_can_be_enabled_without_api_keys_and_has_local_readiness() {
    let gateway = start_gateway(1024, 1000, |command| {
        command
            .env("GATEWAY_GITHUB_OIDC_REPOSITORIES", "Example/*")
            .env("GATEWAY_GITHUB_OIDC_AUDIENCE", "fixture");
    });
    let readiness = request(
        gateway.address,
        "GET /readyz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    expect_status(&readiness, 204);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 401);
}

#[test]
fn keygen_emits_one_random_key_and_a_usable_hash_entry() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let generate = || {
        let result = support::command(env!("CARGO_BIN_EXE_gateway"))
            .args(["keygen", "build"])
            .output()
            .expect("run keygen");
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let output = String::from_utf8(result.stdout).unwrap();
        let mut lines = output.lines();
        let key = lines.next().unwrap().strip_prefix("Key: ").unwrap();
        let config = lines
            .next()
            .unwrap()
            .strip_prefix("GATEWAY_API_KEYS entry: ")
            .unwrap();
        assert!(lines.next().is_none());
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(output.matches(key).count(), 1);
        assert_eq!(config, entry("build", key));
        (key.to_owned(), config.to_owned())
    };
    let (key, config) = generate();
    let (other_key, _) = generate();
    assert_ne!(key, other_key);
    let gateway = start_with_ledger(&config, 1, 1024, 1000, ledger.address);
    expect_status(&submit(&gateway, Some(&other_key), "", VALID), 401);
    expect_status(&submit(&gateway, Some(&key), "", VALID), 201);

    for args in [
        vec!["keygen"],
        vec!["keygen", "bad label"],
        vec!["keygen", "build", "extra"],
    ] {
        let invalid = support::command(env!("CARGO_BIN_EXE_gateway"))
            .args(args)
            .output()
            .unwrap();
        assert!(!invalid.status.success());
        assert!(invalid.stdout.is_empty());
    }
}

const REGISTRATION_PATH: &str = "/v0/rule-registrations";

fn registration() -> Value {
    json!({
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "rules": [{
            "source": "github.com/example/rules",
            "path": "rules/verify",
            "id": "verify",
            "version": "1.0",
            "kind": "check",
            "knowledge": {
                "purpose": "Make the verification repeatable.",
                "problem": "Ad hoc checks miss regressions.",
                "value": "Changes can be checked consistently.",
                "conditions": [{"statement": "Tests pass.", "rationale": "They cover the contract."}],
                "placement": "All repositories use this policy.",
                "extension": {"flag": true, "lines": ["one\r\ntwo"]}
            }
        }]
    })
}

fn outcome(kind: &str, hex: &str) -> Value {
    json!({"outcome": kind, "digest": format!("v1:sha256:{}", hex.repeat(64))})
}

#[test]
fn forwards_the_complete_batch_and_returns_the_ordered_ledger_outcomes() {
    let first = json!({"outcomes": [outcome("created", "1"), outcome("conflict", "2")]});
    let repeated = json!({"outcomes": [outcome("unchanged", "1"), outcome("conflict", "2")]});
    let mut replies = [first.to_string(), repeated.to_string()].into_iter();
    let ledger = LedgerStub::serve(
        200,
        String::new(),
        move || replies.next().unwrap(),
        Duration::ZERO,
        Duration::ZERO,
    );
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 2, 4096, 1000, ledger.address);

    let mut batch = registration();
    let mut review = batch["rules"][0].clone();
    review["kind"] = json!("review");
    review["path"] = json!(".");
    review["id"] = json!("review");
    review["blocking"] = json!(false);
    review["prompt"] = json!("Review the change.");
    batch["rules"].as_array_mut().unwrap().push(review);

    let body = batch.to_string();
    batch["sender"] = json!("build");
    for expected in [first, repeated] {
        let response = post(
            &gateway,
            REGISTRATION_PATH,
            Some(FIRST_KEY),
            "X-Sender: impersonator\r\n",
            &body,
        );
        expect_status(&response, 200);
        let receipt: Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(receipt, expected);

        let (headers, forwarded) = ledger.requests.try_recv().unwrap();
        assert_eq!(headers[0], "POST /v0/rule-registrations HTTP/1.1");
        assert!(headers.iter().all(|header| !header.contains(FIRST_KEY)));
        let forwarded: Value = serde_json::from_slice(&forwarded).unwrap();
        assert_eq!(forwarded, batch);
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn registrations_use_the_same_authentication_rate_allowance_and_body_limit() {
    let ledger = LedgerStub::reply(201, RECEIPT);
    let body = registration().to_string();
    let oversized = "x".repeat(body.len() + 1);
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        3,
        body.len(),
        1000,
        ledger.address,
    );
    let register = |key, body| post(&gateway, REGISTRATION_PATH, key, "", body);

    let missing = register(None, &oversized);
    expect_status(&missing, 401);
    assert!(missing.contains("\r\nwww-authenticate: Bearer\r\n"));
    expect_status(&register(Some(SECOND_KEY), "{"), 401);
    expect_status(&register(Some(FIRST_KEY), &oversized), 413);
    expect_status(&register(Some(FIRST_KEY), "{"), 400);
    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 201);
    let limited = register(Some(FIRST_KEY), &body);
    expect_status(&limited, 429);
    assert!(limited.contains("\r\nretry-after: "));
    assert!(ledger.requests.try_recv().is_ok());
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn rejects_the_entire_registration_batch_on_an_invalid_rule_or_envelope() {
    let ledger = LedgerStub::reply(500, "");
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        40,
        256 * 1024,
        1000,
        ledger.address,
    );
    let valid = registration();
    let mut sender = valid.clone();
    sender["sender"] = json!("impersonator");
    let mut bad_commit = valid.clone();
    bad_commit["commit"] = json!("abcdef");
    let mut empty = valid.clone();
    empty["rules"] = json!([]);
    let mut too_many = valid.clone();
    too_many["rules"] = json!(vec![valid["rules"][0].clone(); 101]);
    let mut missing_knowledge = valid.clone();
    missing_knowledge["rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("knowledge");
    let mut missing_placement = valid.clone();
    missing_placement["rules"][0]["knowledge"]
        .as_object_mut()
        .unwrap()
        .remove("placement");

    let mut invalid = [
        sender,
        bad_commit,
        empty,
        too_many,
        missing_knowledge,
        missing_placement,
    ]
    .map(|value| value.to_string())
    .to_vec();
    invalid.extend([
        valid
            .to_string()
            .replace(r#""version":"1.0""#, r#""version":"1.0","version":"1.0""#),
        valid
            .to_string()
            .replace(r#""flag":true"#, r#""line\r\n":true,"line\n":false"#),
    ]);
    for (field, value) in [
        ("sender", json!("impersonator")),
        ("source", json!("https://github.com/example/rules")),
        ("source", json!("github.com:443/example/rules")),
        ("path", json!("rules/../verify")),
        ("id", json!("bad/id")),
        ("version", json!("01.0")),
        ("version", json!("1.0\n")),
        ("kind", json!("other")),
        ("kind", json!("review")),
        ("blocking", json!(false)),
        ("prompt", json!("check prompt")),
        ("name", json!("é".repeat(81))),
        ("description", json!("x".repeat(65537))),
        ("knowledge", json!({"purpose": "incomplete"})),
    ] {
        let mut batch = valid.clone();
        let mut bad_rule = batch["rules"][0].clone();
        bad_rule[field] = value;
        batch["rules"].as_array_mut().unwrap().push(bad_rule);
        invalid.push(batch.to_string());
    }
    let mut long_knowledge = valid.clone();
    long_knowledge["rules"][0]["knowledge"]["extension"] = json!("x".repeat(65537));
    invalid.push(long_knowledge.to_string());

    for body in invalid {
        expect_status(
            &post(&gateway, REGISTRATION_PATH, Some(FIRST_KEY), "", &body),
            400,
        );
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn maps_registration_ledger_failures_and_rejects_invalid_receipts() {
    let body = registration().to_string();
    let valid_outcomes = json!({"outcomes": [outcome("created", "a")]}).to_string();
    for (status, receipt, expected) in [
        (500, "upstream diagnostic".into(), 503),
        (400, "upstream diagnostic".into(), 502),
        (201, valid_outcomes.clone(), 502),
        (200, "upstream diagnostic".into(), 502),
        (200, r#"{"outcomes":[]}"#.into(), 502),
        (
            200,
            json!({"outcomes": [outcome("unexpected", "a")]}).to_string(),
            502,
        ),
        (
            200,
            json!({"outcomes": [outcome("created", "A")]}).to_string(),
            502,
        ),
        (200, format!("{valid_outcomes:>17000}"), 502),
    ] {
        let ledger = LedgerStub::reply(status, &receipt);
        let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 4096, 1000, ledger.address);
        expect_status(
            &post(&gateway, REGISTRATION_PATH, Some(FIRST_KEY), "", &body),
            expected,
        );
        let logs = gateway.stop();
        assert!(!logs.contains("upstream diagnostic"));
        assert!(!logs.contains("github.com/example/rules"));
        assert!(ledger.requests.try_recv().is_ok());
        assert!(ledger.requests.try_recv().is_err());
    }

    let gateway = start_ingest(&entry("build", FIRST_KEY), 1, 4096);
    expect_status(
        &post(&gateway, REGISTRATION_PATH, Some(FIRST_KEY), "", &body),
        503,
    );

    let ledger = LedgerStub::start(
        200,
        String::new(),
        valid_outcomes,
        Duration::ZERO,
        Duration::from_millis(400),
    );
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 4096, 150, ledger.address);
    expect_status(
        &post(&gateway, REGISTRATION_PATH, Some(FIRST_KEY), "", &body),
        504,
    );
    assert!(ledger.requests.try_recv().is_ok());
}

const RULE_SET_PATH: &str = "/v0/rule-set-registrations";

fn rule_set_registration() -> Value {
    json!({
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "sets": [{
            "source": "github.com/example/sets",
            "path": ".",
            "id": "baseline",
            "version": "1.0",
            "name": "Baseline",
            "description": "Read this as data.\r\n<example>",
            "knowledge": {
                "purpose": "Explain the baseline.\r\nSecond line.",
                "audience": "Shared repositories",
                "commonality": "Repository conventions",
                "rules": [{"rule": "verify", "role": "Check verification."}],
                "admission": ["Checks repository conventions."],
                "execution_points": "Run during check."
            },
            "members": [{
                "source": "github.com/example/rules",
                "path": "rules/verify",
                "id": "verify",
                "version": "2.1",
                "digest": outcome("created", "a")["digest"],
                "enabled": false
            }]
        }]
    })
}

#[test]
fn forwards_rule_sets_and_returns_all_ledger_outcomes_in_order() {
    let mut batch = rule_set_registration();
    let sets = batch["sets"].as_array_mut().unwrap();
    let mut rejected = sets[0].clone();
    rejected["members"].as_array_mut().unwrap().push(json!({
        "source": "git.example.com/team/rules",
        "path": ".",
        "id": "other",
        "version": "0.1",
        "digest": outcome("created", "b")["digest"],
        "enabled": true
    }));
    for id in ["unchanged", "conflict", "invalid_members"] {
        let mut set = if id == "invalid_members" {
            rejected.clone()
        } else {
            sets[0].clone()
        };
        set["id"] = json!(id);
        set.as_object_mut().unwrap().remove("knowledge");
        sets.push(set);
    }
    let expected = json!({"outcomes": [
        outcome("created", "1"),
        outcome("unchanged", "2"),
        outcome("conflict", "3"),
        {"outcome": "invalid_members", "failures": [
            {"member_index": 0, "reason": "unregistered"},
            {"member_index": 1, "reason": "digest_mismatch"}
        ]}
    ]});
    let ledger = LedgerStub::reply(200, &expected.to_string());
    let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 8192, 1000, ledger.address);
    let response = post(
        &gateway,
        RULE_SET_PATH,
        Some(FIRST_KEY),
        "X-Sender: impersonator\r\n",
        &batch.to_string(),
    );
    expect_status(&response, 200);
    let receipt: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(receipt, expected);

    let (headers, body) = ledger.requests.try_recv().unwrap();
    assert_eq!(headers[0], "POST /v0/rule-set-registrations HTTP/1.1");
    assert!(headers.iter().all(|header| !header.contains(FIRST_KEY)));
    let forwarded: Value = serde_json::from_slice(&body).unwrap();
    batch["sender"] = json!("build");
    assert_eq!(forwarded, batch);
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn rejects_invalid_rule_set_batches_without_forwarding() {
    let ledger = LedgerStub::reply(500, "");
    let gateway = start_with_ledger(
        &entry("build", FIRST_KEY),
        30,
        128 * 1024,
        1000,
        ledger.address,
    );
    let valid = rule_set_registration();
    let mut invalid = vec![
        "{".to_string(),
        valid
            .to_string()
            .replace(r#""enabled":false"#, r#""enabled":true,"enabled":false"#),
    ];
    for (pointer, value) in [
        ("/commit", json!("abcd")),
        ("/sets", json!([])),
        ("/sets", json!(vec![valid["sets"][0].clone(); 101])),
        ("/sets/0/name", json!("é".repeat(81))),
        ("/sets/0/description", json!("a".repeat(65537))),
        ("/sets/0/knowledge", json!({"purpose": "incomplete"})),
        (
            "/sets/0/knowledge/rules/0",
            json!({"rule": "verify", "role": "Checks.", "unknown": true}),
        ),
        (
            "/sets/0/members",
            json!(vec![valid["sets"][0]["members"][0].clone(); 257]),
        ),
        (
            "/sets/0/members/0/source",
            json!("github.com:443/example/rules"),
        ),
        ("/sets/0/members/0/path", json!("rules/../verify")),
        ("/sets/0/members/0/version", json!("02.1")),
        (
            "/sets/0/members/0/digest",
            outcome("created", "A")["digest"].clone(),
        ),
        ("/sets/0/members/0/enabled", json!("false")),
    ] {
        let mut batch = valid.clone();
        *batch.pointer_mut(pointer).unwrap() = value;
        invalid.push(batch.to_string());
    }
    for pointer in ["", "/sets/0", "/sets/0/members/0"] {
        let mut batch = valid.clone();
        batch.pointer_mut(pointer).unwrap()["sender"] = json!("impersonator");
        invalid.push(batch.to_string());
    }
    for body in invalid {
        expect_status(
            &post(&gateway, RULE_SET_PATH, Some(FIRST_KEY), "", &body),
            400,
        );
    }

    for (auth, expected) in [
        (String::new(), 401),
        (format!("Authorization: Bearer {FIRST_KEY}\r\n"), 413),
    ] {
        let response = request(
            gateway.address,
            &format!(
                "POST {RULE_SET_PATH} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{auth}Content-Length: 131073\r\n\r\n"
            ),
        );
        expect_status(&response, expected);
    }
    assert!(ledger.requests.try_recv().is_err());
}

#[test]
fn rejects_invalid_rule_set_ledger_receipts() {
    let mut batch = rule_set_registration();
    let mut second = batch["sets"][0]["members"][0].clone();
    second["id"] = json!("second");
    batch["sets"][0]["members"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let body = batch.to_string();
    let failure =
        |failures| json!({"outcomes": [{"outcome": "invalid_members", "failures": failures}]});
    let member = json!({"member_index": 0, "reason": "unregistered"});
    for receipt in [
        json!({"outcomes": []}),
        failure(json!([])),
        failure(json!([{"member_index": 2, "reason": "unregistered"}])),
        failure(json!([{"member_index": 0, "reason": "unknown"}])),
        failure(json!([member, member])),
        json!({"outcomes": [{"outcome": "created", "digest": "invalid"}]}),
    ] {
        let ledger = LedgerStub::reply(200, &receipt.to_string());
        let gateway = start_with_ledger(&entry("build", FIRST_KEY), 1, 8192, 1000, ledger.address);
        expect_status(
            &post(&gateway, RULE_SET_PATH, Some(FIRST_KEY), "", &body),
            502,
        );
        assert!(ledger.requests.try_recv().is_ok());
    }
}
