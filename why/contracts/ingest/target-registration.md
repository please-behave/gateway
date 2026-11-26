# Submit deployment target registrations

Send a JSON object matching the [request schema](target-registration.schema.json)
to `POST /v0/target-registrations` with `Authorization: Bearer <credential>`.
Version 0 is experimental and may change incompatibly.

The gateway authenticates the request, applies the shared public ingest allowance
and validates the body in that order. Missing or invalid credentials return
`401 Unauthorized` with `WWW-Authenticate: Bearer`. An unavailable signing-key
fetch needed for GitHub OIDC returns `503 Service Unavailable`. An exhausted
allowance returns `429 Too Many Requests` with `Retry-After` in whole seconds,
rounded up. Every admitted request consumes one slot, including invalid or
oversized requests.

The body limit is the configured limit capped at 2 MiB (2,097,152 bytes).
Oversized bodies return `413 Content Too Large`. Malformed JSON, duplicate keys
and schema violations return `400 Bad Request`. Send 1 to 100 targets. Names are
case sensitive, start with an ASCII letter or digit and contain up to 64 ASCII
letters, digits, dots, underscores or hyphens. An optional description contains
1 to 512 Unicode characters and cannot contain NUL. The gateway preserves
names and descriptions as supplied. The public schema forbids a caller-supplied
`sender` or `owner`.

The gateway forwards the batch once to the ledger on the same path
(ledger:CON-0020), adding the authenticated `sender` as the owner of each target.
The sender is the API key label or the verified, lowercased GitHub repository
identity (why:DEC-0022). The gateway keeps no registration records.

A valid ledger reply returns `200 OK` with an `outcomes` array containing one
entry per target in request order, including repeated names. Each entry has
the target `name` and an `outcome` of `created` or `unchanged`. The ledger
preserves the first registration for each owner and name, including its
description. A repeated registration returns `unchanged`.

An unreachable ledger or a ledger server error returns `503 Service Unavailable`.
An unexpected status or an invalid receipt returns `502 Bad Gateway`. The
request deadline covers inbound processing and the complete ledger exchange.
Expiry before forwarding returns `408 Request Timeout`. A connection timeout
or expiry during forwarding returns `504 Gateway Timeout`. Connection
establishment is capped at five seconds. Error responses have empty bodies.
