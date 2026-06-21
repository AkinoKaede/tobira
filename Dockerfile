FROM rust:1-slim-trixie AS builder

WORKDIR /build

COPY . .

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/tobira /usr/bin/tobira

ENTRYPOINT ["/usr/bin/tobira"]

CMD ["--config", "/etc/tobira/config.toml"]
