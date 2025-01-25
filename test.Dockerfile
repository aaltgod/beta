FROM rust:1-alpine3.19 as builder

ENV RUSTFLAGS="-C target-feature=-crt-static"

RUN apk add --no-cache musl-dev

WORKDIR /beta

COPY ./src /beta/src
COPY ./Cargo.toml /beta/Cargo.toml
COPY ./Cargo.lock /beta/Cargo.lock
COPY ./config.yaml /beta/config.yaml
COPY ./.env /beta/.env

RUN cargo build --release
RUN strip target/release/beta

FROM alpine:3.19

RUN apk add --no-cache libgcc iptables

COPY --from=builder /beta/target/release/beta .

ENV RUST_LOG=debug

ENTRYPOINT ["sh", "-c", "iptables -t nat -A PREROUTING -p tcp --dport 5000 -j REDIRECT --to-port 29220 && exec ./beta"]
