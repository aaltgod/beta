FROM rust:1-alpine3.19 as builder

ENV RUSTFLAGS="-C target-feature=-crt-static"

RUN apk add --no-cache musl-dev

WORKDIR /beta

COPY . .

RUN cargo build --release
RUN strip target/release/beta

FROM alpine:3.19

RUN apk add --no-cache libgcc

COPY --from=builder /beta/target/release/beta .

ENV RUST_LOG=debug

ENTRYPOINT ["/beta"]
