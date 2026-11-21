# Submit an attestation

Send a JSON document matching [the attestation schema](attestation.schema.json)
to `POST /v0/attestations` with `Authorization: Bearer <key>`. Version 0
is experimental and may change incompatibly. The URL version identifies the
API and the document's `schema_version` identifies the reported format.

An attestation carries evidence reported by the authenticated sender. Its
repository and verdict are claims made by the holder of the key. The gateway
determines the sender from the configured label for that key.

The gateway processes the request in this order. Responses have empty bodies.

1. Authenticate the key. A missing, malformed or unknown credential returns
   `401 Unauthorized` with a `WWW-Authenticate: Bearer` challenge.
2. Apply the per-key, per-instance rate limit. Every admitted request consumes
   one slot, including requests with invalid or oversized bodies. An exhausted
   allowance returns `429 Too Many Requests` with `Retry-After` in whole
   seconds, rounded up to the next second when necessary.
3. Enforce the request body size limit and validate the JSON structure.
   An oversized body returns `413 Content Too Large`. Malformed JSON or a
   schema violation, including a client-supplied sender, returns
   `400 Bad Request`.

A structurally valid request returns `200 OK`. The gateway currently stops
processing at this point. The configured request timeout also applies to ingest.
