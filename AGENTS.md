# Working on the Gateway

## Why

- `why/` is the source of truth for the gateway's behavior, responsibilities and decisions. Read `why/README.md` and the artifacts relevant to the task before implementation. Purpose, principles and direction of Please Behave are in the central Why repository (https://github.com/please-behave/why).
- Write requirements and decisions together with the code that implements them, and record only what holds in the medium term.
- Define the contract and acceptance criteria before changing behavior. If artifacts conflict or code differs from them, investigate before proceeding. Never silently redefine behavior.

## Boundaries

- The gateway shares no state between instances and stores nothing. In-memory counters of one instance are its only state.
- Trust decisions belong to the proxy in front of it. Never read a client address and never rely on a forwarded header.
- Never log or echo credentials, including the `Authorization` header and API keys. Keep keys only as hashes and compare them in constant time.
- Validate structure and format, including bounds, before anything is forwarded.
- Never forward a sender that the client supplied. The sender comes from the authenticated key.
