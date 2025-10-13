FROM rust:1.90 as builder

WORKDIR /usr/src/hightower-cnet

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    wireguard-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/hightower-cnet/target/release/hightower-cnet /usr/local/bin/hightower-cnet

ENV HT_GATEWAY_URL=http://127.0.0.1:8008 \
    HT_HEALTH_CHECK_INTERVAL=30

CMD ["hightower-cnet"]
