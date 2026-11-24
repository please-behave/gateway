FROM rust:1.100.0-slim-trixie@sha256:51fdc80ccc3fb83bf14481f2cd8d0d11703eeb9f416ab47476c32a793a822307 AS build
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
