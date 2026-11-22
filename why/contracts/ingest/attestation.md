# Submit an attestation

Send a JSON document matching [the attestation schema](attestation.schema.json)
to `POST /v0/attestations` with `Authorization: Bearer <key>`. Version 0
is experimental and may change incompatibly. The URL version identifies the
API and the document's `schema_version` identifies the reported format.

An attestation carries evidence reported by the authenticated sender. Its
repository and verdict are claims made by the holder of the key. The gateway
determines the sender from the configured label for that key.

The gateway processes the request in this order. Error responses have empty bodies.

1. Authenticate the key. A missing, malformed or unknown credential returns
   `401 Unauthorized` with a `WWW-Authenticate: Bearer` challenge.
2. Apply the per-key, per-instance rate limit. Every admitted request consumes
   one slot, including requests with invalid or oversized bodies. An exhausted
   allowance returns `429 Too Many Requests` with `Retry-After` in whole
   seconds, rounded up to the next second when necessary.
3. Enforce the request body size limit and validate the JSON structure.
   An oversized body returns `413 Content Too Large`. Malformed JSON or a
   schema violation, including a client-supplied sender, returns
   `400 Bad Request`. If the request deadline expires before forwarding,
   the gateway returns `408 Request Timeout`.
4. Convert the valid attestation to the canonical ledger format and submit it
   once with the authenticated sender. The conversion currently preserves the
   attestation's fields and values.

| Status | Meaning |
| --- | --- |
| `201 Created` | The ledger confirmed creation. The JSON response contains the ledger's version 7 UUID in `id`. |
| `503 Service Unavailable` | The ledger could not be reached or returned a server error. |
| `504 Gateway Timeout` | The connection or ledger exchange exceeded its deadline, including receipt delivery. |
| `502 Bad Gateway` | The ledger returned an unexpected response, such as `400` after gateway validation or `201` without a valid creation receipt. |

The configured request deadline covers both inbound processing and the ledger
exchange. Establishing a ledger connection is also capped at five seconds.
For a `502`, the gateway logs the failure without the submitted document or
the ledger response body.

## Rule metadata

Each result keeps its run-scoped `id` and may include a `rule` object with
`source` (the normalized Git repository identity), `path` (the
repository-relative rule directory) and `id` (the rule ID within that source),
as defined by why:DEC-0010. All three are required when `rule` is present.
The source and path are each bounded to 256 characters, and the rule ID to 128.

An identity may also carry `version` and `digest`. These fields must appear
together. A version is at most 64 characters and has the form `A.B`, where
each part is a non-negative decimal integer with no leading zeros
(why:DEC-0011). The digest is a string of at most 128 characters. All fields
must be non-empty and contain no NUL characters. Unknown fields are rejected.

This optional extension retains the existing API and document format versions.
The gateway accepts attestations that omit `rule` and forwards supplied rule
metadata unchanged in the canonical ledger envelope.
