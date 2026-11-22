FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY why/contracts/ingest/attestation.schema.json ./why/contracts/ingest/attestation.schema.json
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
COPY --from=build /src/target/release/gateway /usr/local/bin/gateway
USER nonroot
ENTRYPOINT ["/usr/local/bin/gateway"]
