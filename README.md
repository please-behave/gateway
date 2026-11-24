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
| `GATEWAY_LEDGER_URL` | yes | — | Absolute `http` or `https` URL whose origin serves the ledger at `/v0/attestations`. Use a URL without embedded credentials. The service does not contact it during startup or readiness checks. |
| `GATEWAY_BIND_ADDR` | no | `0.0.0.0:8080` | Socket address on which to listen. |
| `GATEWAY_MAX_BODY_BYTES` | no | `1048576` | Positive maximum request-body size in bytes. |
| `GATEWAY_REQUEST_TIMEOUT_MS` | no | `30000` | Positive maximum request duration in milliseconds, including authentication and the ledger exchange. Ledger connection establishment is also capped at five seconds. |
| `GATEWAY_API_KEYS` | no | empty | Comma-separated `<sender>:<SHA-256 hex hash>` entries. An empty or absent value disables API key authentication. |
| `GATEWAY_GITHUB_OIDC_REPOSITORIES` | no | empty | Comma-separated GitHub OIDC allowlist of `<owner>/<name>` and `<owner>/*` entries, matched case-insensitively. The wildcard covers all repositories of the organization or personal account. An empty or absent value disables GitHub OIDC. |
| `GATEWAY_GITHUB_OIDC_AUDIENCE` | with GitHub OIDC | — | Expected audience in the GitHub Actions token, compared exactly. |
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | no | `60` | Positive request allowance per API key or GitHub OIDC repository and gateway instance, shared by both ingest endpoints. Each 60-second window starts with the first request for that identity or with the first request after the previous window expires. |

The gateway writes structured JSON logs to standard error. For each request it generates an ID, logs it and returns it in the `X-Request-Id` response header. The logs omit request credentials.

## Ingest

Run `gateway keygen <sender>` to print a random bearer key once and the entry to add to `GATEWAY_API_KEYS`. A sender label can contain 1 to 128 ASCII letters, digits, dots, underscores or hyphens. Give the bearer key to the sender and deploy the same hash entries to every gateway instance. To rotate a key, add a new entry with the same label, switch the sender to the new key, then remove the old entry from all instances.

API keys and GitHub OIDC can be enabled independently. With GitHub OIDC enabled, grant the GitHub Actions job `id-token: write` and request an ID token for the configured audience. Set the request header to `Authorization: Bearer <credential>` with the API key or GitHub OIDC token. When GitHub OIDC is enabled, compact JWT credentials are reserved for that method.

For GitHub OIDC the gateway uses `github.com/<owner>/<name>` in lowercase as the sender. The attestation repository and every registration rule source must equal that sender. Write access to an allowed repository confers authority to register versions for its own source.

Send attestations to `POST /v0/attestations` and rule registrations to `POST /v0/rule-registrations`. See the [attestation contract](why/contracts/ingest/attestation.md) and [rule registration contract](why/contracts/ingest/rule-registration.md) for accepted documents and response statuses.

## Health endpoints

`GET /healthz` reports liveness and `GET /readyz` reports whether the service completed valid configuration. Both return `204 No Content`. Readiness uses local configuration only.
