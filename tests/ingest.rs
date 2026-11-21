//! REQ-0002, REQ-0003, REQ-0005, REQ-0006, REQ-0007

mod support;

use sha2::{Digest, Sha256};
use support::http::{Gateway, request, start_gateway};

const FIRST_KEY: &str = "fixture-ingest-key-first";
const SECOND_KEY: &str = "fixture-ingest-key-second";
const VALID: &str = r#"{"schema_version":1,"repository":"github.com/example/project","commit":"0123456789abcdef","execution_points":["pre-push"],"overall":"PASS","results":[{"id":"test","kind":"check","status":"WARN"}]}"#;

fn entry(sender: &str, key: &str) -> String {
    format!("{sender}:{:x}", Sha256::digest(key.as_bytes()))
}

fn start_ingest(keys: &str, allowance: usize, body_limit: usize) -> Gateway {
    start_gateway(body_limit, 1000, |command| {
        command
            .env("GATEWAY_API_KEYS", keys)
            .env("GATEWAY_RATE_LIMIT_PER_MINUTE", allowance.to_string());
    })
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
    assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "", "{response}");
    assert!(response.contains("\r\nx-request-id: "), "{response}");
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
    let keys = format!(
        "{},{}",
        entry("build", FIRST_KEY),
        entry("build", SECOND_KEY)
    );
    let gateway = start_ingest(&keys, 1, 1024);
    let peer = start_ingest(&keys, 1, 1024);
    let rotated = start_ingest(&entry("build", SECOND_KEY), 1, 1024);

    expect_status(&submit(&gateway, Some(FIRST_KEY), "", VALID), 200);
    expect_status(
        &submit(
            &gateway,
            Some(FIRST_KEY),
            "Forwarded: for=192.0.2.1\r\nX-Forwarded-For: 192.0.2.2\r\n",
            VALID,
        ),
        429,
    );
    expect_status(&submit(&gateway, Some(SECOND_KEY), "", VALID), 200);
    expect_status(&submit(&peer, Some(FIRST_KEY), "", VALID), 200);
    expect_status(&submit(&rotated, Some(FIRST_KEY), "", VALID), 401);
    expect_status(&submit(&rotated, Some(SECOND_KEY), "", VALID), 200);
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
    let keys = entry("build", FIRST_KEY);
    let gateway = start_ingest(&keys, 2, 1024);
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
    expect_status(&valid, 200);
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
    let gateway = start_ingest(&entry("build", FIRST_KEY), 60, 128 * 1024);
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
        expect_status(&submit(&gateway, Some(FIRST_KEY), "", &valid), 200);
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
    let gateway = start_ingest(&config, 1, 1024);
    expect_status(&submit(&gateway, Some(&other_key), "", VALID), 401);
    expect_status(&submit(&gateway, Some(&key), "", VALID), 200);

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
