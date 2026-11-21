//! REQ-0002, REQ-0003, REQ-0005, REQ-0006, REQ-0007, REQ-0008, REQ-0009, REQ-0010

mod support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};

use axum::Json;
use sha2::{Digest, Sha256};
use support::http::{Gateway, request, start_gateway, unused_address};

const FIRST_KEY: &str = "fixture-ingest-key-first";
const SECOND_KEY: &str = "fixture-ingest-key-second";
const VALID: &str = r#"{"schema_version":1,"repository":"github.com/example/project","commit":"0123456789abcdef","execution_points":["pre-push"],"overall":"PASS","results":[{"id":"test","kind":"check","status":"WARN"}]}"#;
const RECEIPT: &str = r#"{"id":"0198b0a7-46a8-7000-8000-000000000001"}"#;

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
    let auth = key
        .map(|key| format!("Authorization: Bearer {key}\r\n"))
        .unwrap_or_default();
    request(
        gateway.address,
        &format!(
            "POST /v0/attestations HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{auth}{headers}Content-Length: {}\r\n\r\n{body}",
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
