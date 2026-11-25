# Submit a release fact

Send one JSON object matching the [request schema](release-fact.schema.json)
to `POST /v0/facts/releases` with `Authorization: Bearer <credential>`.
Version 0 is experimental and may change incompatibly.

The repository uses the same platform-neutral Git identity as attestations.
The version is an opaque string. The gateway preserves its whitespace and
case and forwards the full Git object ID as supplied (why:DEC-0020).

The gateway authenticates the credential, applies the shared public ingest
allowance and validates the request in that order. Missing or invalid
credentials return `401 Unauthorized` with `WWW-Authenticate: Bearer`.
An unavailable signing-key fetch needed for GitHub OIDC returns
`503 Service Unavailable`. An exhausted allowance returns
`429 Too Many Requests` with `Retry-After` in whole seconds, rounded up.
Every admitted request consumes one slot, including invalid or oversized
requests.

The body limit is the configured limit capped at 2 MiB. An oversized body
returns `413 Content Too Large`. Malformed JSON, duplicate keys or a schema
violation return `400 Bad Request`. For GitHub OIDC, the validated repository
must equal the normalized lowercase repository from the signed claims.
A mismatch returns `403 Forbidden`. API keys can report for any repository.

The gateway sends the validated fields once to the ledger's release fact
contract (ledger:CON-0015) with its authenticated `sender` and `auth_method`.
The sender is the API key label for `api_key` or the verified repository
identity for `github_oidc`. The ledger keeps the first record for each
repository and version.

| Status | JSON body | Meaning |
| --- | --- | --- |
| `201 Created` | `{"outcome":"created"}` | The ledger stored the release fact. |
| `200 OK` | `{"outcome":"unchanged"}` | The same repository and version already reference the same commit. |
| `409 Conflict` | `{"outcome":"conflict"}` | The same repository and version already reference a different commit. |

An unreachable ledger or a ledger server error returns `503 Service Unavailable`.
An unexpected status or invalid receipt returns `502 Bad Gateway`. The request
deadline covers inbound processing and the complete ledger exchange. Expiry
before forwarding returns `408 Request Timeout`. A connection timeout or
expiry during forwarding returns `504 Gateway Timeout`. Connection
establishment is capped at five seconds. These errors have empty bodies.
