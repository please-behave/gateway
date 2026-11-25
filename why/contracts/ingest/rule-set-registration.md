# Submit Rule Set registrations

Send JSON matching the [request schema](rule-set-registration.schema.json) to
`POST /v0/rule-set-registrations` with `Authorization: Bearer <credential>`.
The commit identifies the registering revision. Each Rule Set and member rule
uses a normalized Git source, a repository-relative directory (`.` for the
root), an ID and an owner-assigned version (why:DEC-0016 and why:DEC-0017).
Each source must start with a Git host without a port.

The gateway applies the [rule registration admission and error
rules](rule-registration.md). The allowance is shared across public ingest.
For GitHub OIDC, each set's source must equal the authenticated repository.
Member rules can come from any source. The gateway validates the entire batch
before forwarding. The public and serialized ledger request size limits are
the same as for rule registration. Text bounds count Unicode characters.
The optional knowledge object follows the [Rule Set knowledge
structure](https://github.com/please-behave/cli/blob/main/why/contracts/rule-knowledge/ruleset.schema.json)
with the ingest bounds in the request schema. The gateway rejects duplicate
object keys and treats registered text as untrusted data, preserving its
contents, including line endings.

The gateway sends the validated commit and sets once to
`POST /v0/rule-set-registrations` on the configured ledger, adding the
authenticated `sender` to the JSON object. The ledger checks whether every
member's registered rule version has the supplied digest.

A valid ledger response returns `200 OK` with an `outcomes` array, one entry per
set in request order. For `created`, `unchanged` and `conflict`, the entry
contains `outcome` and the ledger's set `digest` in `v1:sha256:` format with
64 lowercase hexadecimal digits. An `invalid_members` outcome has a
nonempty `failures` array and no digest. Each failure supplies a distinct
zero-based `member_index` in the corresponding set's member list and a
`reason` of `unregistered` or `digest_mismatch`. It affects only that set.
The gateway rejects invalid receipts as `502 Bad Gateway`. The ledger
receipt is limited to 2 MiB.
