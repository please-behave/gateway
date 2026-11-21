# Gateway

[![build](https://github.com/please-behave/gateway/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/please-behave/gateway/actions/workflows/ci.yml) [![release](https://img.shields.io/github/v/release/please-behave/gateway?display_name=tag&sort=semver)](https://github.com/please-behave/gateway/releases) [![license](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-3949ab.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0/)

[![tests](https://christianpflugradt.github.io/badges-and-stuff/please-behave-gateway/tests.svg)](https://christianpflugradt.github.io/badges-and-stuff/) [![coverage](https://christianpflugradt.github.io/badges-and-stuff/please-behave-gateway/coverage.svg)](https://christianpflugradt.github.io/badges-and-stuff/) [![LOC](https://christianpflugradt.github.io/badges-and-stuff/please-behave-gateway/loc.svg)](https://christianpflugradt.github.io/badges-and-stuff/)

The gateway is the sender-facing entry point for the Please Behave platform. It is a service in early development.

> Please Behave is in early development and not ready for production use.

It is released as the container image `ghcr.io/please-behave/gateway`. The purpose and principles of Please Behave are in the [Why repository](https://github.com/please-behave/why).

## Configuration

The gateway is configured through environment variables. It exits before serving requests when a value is invalid.

| Variable | Required | Default | Description |
|---|---:|---|---|
| `GATEWAY_LEDGER_URL` | yes | — | Absolute `http` or `https` URL of the ledger without embedded credentials. The service does not contact it during startup or readiness checks. |
| `GATEWAY_BIND_ADDR` | no | `0.0.0.0:8080` | Socket address on which to listen. |
| `GATEWAY_MAX_BODY_BYTES` | no | `1048576` | Positive maximum request-body size in bytes. |
| `GATEWAY_REQUEST_TIMEOUT_MS` | no | `30000` | Positive maximum request duration in milliseconds. |

Later authentication key configuration will also use environment variables. The gateway writes structured JSON logs to standard error. For each request it generates an ID, logs it and returns it in the `X-Request-Id` response header. The logs omit request credentials.

## Health endpoints

`GET /healthz` reports liveness and `GET /readyz` reports whether the service completed valid configuration. Both return `204 No Content`. Readiness does not probe the ledger.
