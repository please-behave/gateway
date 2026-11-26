# Submit a deployment fact

Send one JSON object matching the [request schema](deployment-fact.schema.json)
to `POST /v0/facts/deployments` with `Authorization: Bearer <credential>`.
Version 0 is experimental and may change incompatibly.

Use the registered target name and the deployed software's normalized Git
repository identity (why:DEC-0010). The subject may be any repository with
either an opaque release version or a full Git object ID. The gateway
preserves the supplied values. The authenticated sender owns the target
(why:DEC-0022, why:DEC-0023).

The gateway authenticates the credential, applies the shared public ingest
allowance and validates the request in that order. Missing or invalid
credentials return `401 Unauthorized` with `WWW-Authenticate: Bearer`.
An unavailable signing-key fetch needed for GitHub OIDC returns
`503 Service Unavailable`. An exhausted allowance returns
`429 Too Many Requests` with `Retry-After` in whole seconds, rounded up.
Every admitted request consumes one slot, including invalid or oversized
requests.

The body limit is the configured limit capped at 2 MiB. An oversized body
returns `413 Content Too Large`. Malformed JSON, duplicate keys and schema
violations return an empty `400 Bad Request`. The public schema reserves
the owner, sender and authentication method for the gateway.

The gateway forwards the fact once on the same path to the ledger
(ledger:CON-0021) with the authenticated `sender` and `auth_method`.
The sender is the API key label for `api_key` or the verified lowercase
repository identity for `github_oidc`. The ledger checks target registration
using the sender and target name.

| Status | Body | Meaning |
| --- | --- | --- |
| `201 Created` | `{"outcome":"created"}` | The ledger recorded a deployment event. |
| `200 OK` | `{"outcome":"unchanged"}` | The report matches the current deployment. |
| `400 Bad Request` | Empty | The ledger rejected the validated report because the target is unregistered for the sender. |

An unreachable ledger or a ledger server error returns `503 Service Unavailable`.
An unexpected status or invalid receipt returns `502 Bad Gateway`. The request
deadline covers inbound processing and the complete ledger exchange. Expiry
before forwarding returns `408 Request Timeout`. A connection timeout or
expiry during forwarding returns `504 Gateway Timeout`. Connection
establishment is capped at five seconds. These errors have empty bodies.
