FROM alpine

WORKDIR /app

COPY target/aarch64-unknown-linux-musl/release/log-rate-limit log-rate-limit

CMD ["./og-rate-limit"]
