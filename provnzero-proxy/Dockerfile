FROM rust:1.85-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/provnzero-proxy /app/

ENV RUST_LOG=error
ENV LOG_LEVEL=disabled
ENV RUST_BACKTRACE=0

EXPOSE 3000

CMD ["/app/provnzero-proxy"]
