
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y musl-tools musl-dev build-essential libssl-dev pkg-config

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release
EXPOSE 8443
CMD ["/app/target/release/charizhard-otp"]