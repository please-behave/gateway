# Submit rule registrations

Send JSON matching the [request schema](rule-registration.schema.json) to
`POST /v0/rule-registrations` with `Authorization: Bearer <key>`. The
`commit` is the Git object ID of the registering revision. Rules are identified
by normalized Git host and path, repository-relative rule directory (`.` for
the root), source-local ID and owner-assigned version (why:DEC-0010 and
why:DEC-0011). The gateway checks that the source starts with a Git host
without a port. Reviews supply their effective blocking value and the prompt
before parameter substitution.

Each rule carries its complete [rule knowledge document](https://github.com/please-behave/cli/blob/main/why/contracts/rule-knowledge/rule.schema.json).
The gateway checks required fields and bounds, and forwards unfamiliar
knowledge fields that fit the ledger's digest data types. Text limits in the
schema count Unicode characters. Duplicate object members are rejected,
including keys that would collide under the ledger's newline normalization.

The gateway authenticates, rate-limits, checks the body size and validates the
whole batch in that order. Both public ingest endpoints share each key's
per-instance rate allowance. The public body limit is the lower of
`GATEWAY_MAX_BODY_BYTES` and 2 MiB. The serialized ledger request, including
the authenticated sender, must also fit the ledger's 2 MiB limit.

The gateway sends the commit and rules once with the authenticated sender to
the [ledger registration endpoint](https://github.com/please-behave/ledger/blob/main/why/contracts/ingest/rule-registration.md).
A valid ledger response yields `200 OK` and a JSON object with an `outcomes`
array in request order. Each entry has an `outcome` of `created`,
`unchanged` or `conflict` and a `digest` in the ledger's canonical
`v1:sha256:` format. Repeating the same registration reports `unchanged` for already stored
versions with the same digest. A conflict affects only the corresponding rule.

Error bodies are empty.

| Status | Meaning |
| --- | --- |
| `401 Unauthorized` | The bearer credential is missing, malformed or unknown. The response includes `WWW-Authenticate: Bearer`. |
| `429 Too Many Requests` | The key's allowance is exhausted. The response includes `Retry-After` in whole seconds, rounded up. |
| `413 Content Too Large` | The public body or the serialized ledger request exceeds its limit. |
| `400 Bad Request` | The JSON is malformed or violates the contract, including a client-supplied `sender`. |
| `408 Request Timeout` | The request deadline expired before forwarding. |
| `503 Service Unavailable` | The ledger could not be reached or returned a server error. |
| `504 Gateway Timeout` | The ledger connection or exchange, including receipt delivery, timed out. |
| `502 Bad Gateway` | The ledger returned an unexpected status or an invalid receipt. The gateway logs the failure without either document. |
