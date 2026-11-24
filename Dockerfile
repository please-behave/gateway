FROM rust:1.100.0-slim-trixie@sha256:86993c97389ebb5487eb09e88168e2a00b0de29aa08dff9ae896049b9be96ed9 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY why/contracts/ingest/attestation.schema.json ./why/contracts/ingest/attestation.schema.json
COPY why/contracts/ingest/rule-registration.schema.json ./why/contracts/ingest/rule-registration.schema.json
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
COPY --from=build /src/target/release/gateway /usr/local/bin/gateway
USER nonroot
ENTRYPOINT ["/usr/local/bin/gateway"]
