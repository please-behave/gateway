//! REQ-0001, REQ-0002, REQ-0003, REQ-0004

mod support;

use std::{thread, time::Duration};

use axum::{Router, routing::get};
use gateway::{Config, app, with_limits};
use support::http::{request, start_gateway, unused_address};

#[test]
fn rejects_invalid_configuration() {
    for (name, value) in [
        ("GATEWAY_LEDGER_URL", "not a URL"),
        ("GATEWAY_LEDGER_URL", "http://ledger.test:99999"),
        (
            "GATEWAY_LEDGER_URL",
            "http://user:fixture-secret@ledger.test",
        ),
        ("GATEWAY_BIND_ADDR", "not a socket address"),
        ("GATEWAY_MAX_BODY_BYTES", "0"),
        ("GATEWAY_REQUEST_TIMEOUT_MS", "-1"),
    ] {
        let output = support::command(env!("CARGO_BIN_EXE_gateway"))
            .env("GATEWAY_LEDGER_URL", "http://ledger.test")
            .env(name, value)
            .output()
            .expect("run gateway");
        let error = String::from_utf8_lossy(&output.stderr);

        assert!(!output.status.success(), "{name} accepted {value}");
        assert!(
            error.contains(name),
            "missing diagnostic for {name}: {error}"
        );
        assert!(!error.contains("fixture-secret"));
    }
}

#[test]
fn serves_health_and_refuses_unsupported_requests() {
    let gateway = start_gateway(1024, 1000, |_| {});

    let health = request(
        gateway.address,
        "GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    let ready = request(
        gateway.address,
        "GET /readyz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    let missing = request(
        gateway.address,
        "GET /missing HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    let method = request(
        gateway.address,
        "POST /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    );
    let head = request(
        gateway.address,
        "HEAD /readyz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );

    assert!(health.starts_with("HTTP/1.1 204"));
    assert!(ready.starts_with("HTTP/1.1 204"));
    assert!(missing.starts_with("HTTP/1.1 404"));
    assert!(method.starts_with("HTTP/1.1 405"));
    assert!(head.starts_with("HTTP/1.1 405"));
    assert!(head.contains("\r\nallow: GET\r\n"));
    let _ = gateway.stop();
}

#[test]
fn enforces_request_body_limit_and_redacts_authorization() {
    let secret = "fixture-secret";
    let gateway = start_gateway(3, 1000, |_| {});
    let health = request(
        gateway.address,
        &format!(
            "GET /healthz?token={secret} HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {secret}\r\nX-Request-Id: {secret}\r\nConnection: close\r\n\r\n"
        ),
    );
    let response = request(
        gateway.address,
        &format!(
            "GET /healthz HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {secret}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
        ),
    );
    let chunked = request(
        gateway.address,
        "GET /readyz HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
    );
    let missing = request(
        gateway.address,
        &format!("{secret} /{secret} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    );
    let logs = gateway.stop();

    assert!(health.starts_with("HTTP/1.1 204"));
    assert!(response.starts_with("HTTP/1.1 413"));
    assert!(chunked.starts_with("HTTP/1.1 413"), "{chunked}");
    assert!(missing.starts_with("HTTP/1.1 404"));
    assert!(!health.contains(secret));
    assert!(!logs.contains(secret));
    assert!(!logs.to_ascii_lowercase().contains("authorization"));
    let request_id = health
        .lines()
        .find_map(|line| line.strip_prefix("x-request-id: "))
        .expect("gateway sets the request ID");
    assert!(
        logs.lines().any(|line| line.starts_with('{')
            && line.contains(&format!("\"request_id\":\"{request_id}\""))),
        "logs: {logs}"
    );
}

#[test]
fn times_out_an_incomplete_request_body() {
    let gateway = start_gateway(1024, 100, |_| {});
    let response = request(
        gateway.address,
        "GET /readyz HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\nConnection: close\r\n\r\na",
    );

    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
}

#[cfg(unix)]
#[test]
fn shuts_down_gracefully_on_sigterm() {
    let mut gateway = start_gateway(1024, 1000, |_| {});
    let signal = support::command("kill")
        .args(["-TERM", &gateway.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signal.success());

    for _ in 0..100 {
        if let Some(status) = gateway.child.try_wait().expect("check gateway exit") {
            assert!(status.success(), "gateway exited with {status}");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("gateway did not exit after SIGTERM");
}

#[tokio::test]
async fn enforces_request_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let config = Config {
        bind_addr: listener.local_addr().expect("read test server address"),
        ledger_url: "http://ledger.test".to_owned(),
        max_body_bytes: 1024,
        request_timeout: Duration::from_millis(10),
        ingest: Default::default(),
    };
    let router = with_limits(
        Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                "done"
            }),
        ),
        &config,
    );
    let server = tokio::spawn(async move { axum::serve(listener, router).await });

    let response = tokio::task::spawn_blocking(move || {
        request(
            config.bind_addr,
            "GET /slow HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        )
    })
    .await
    .expect("join request");
    server.abort();

    assert!(response.starts_with("HTTP/1.1 408"));
}

#[test]
fn application_can_be_constructed_from_valid_configuration() {
    let config = Config {
        bind_addr: unused_address(),
        ledger_url: "https://ledger.test".to_owned(),
        max_body_bytes: 1024,
        request_timeout: Duration::from_secs(1),
        ingest: Default::default(),
    };
    let _ = app(&config);
}
