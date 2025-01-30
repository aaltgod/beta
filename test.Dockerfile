FROM rust:latest

WORKDIR /beta

COPY ./src /beta/src
COPY ./Cargo.toml /beta/Cargo.toml
COPY ./Cargo.lock /beta/Cargo.lock
COPY ./config.yaml /beta/config.yaml
COPY ./.env /beta/.env

COPY ./e2e/config.toml $HOME/.cargo/config.toml

RUN cargo build --profile profiling
# RUN strip target/release/beta   



RUN apt-get update && apt-get install -y libgcc-11-dev iptables curl
RUN curl --proto '=https' --tlsv1.2 -LsSf https://github.com/mstange/samply/releases/download/samply-v0.12.0/samply-installer.sh | sh
RUN echo '1' > /proc/sys/kernel/perf_event_paranoid || true

ENV RUST_LOG=debug

ENTRYPOINT ["sh", "-c", "iptables -t nat -A PREROUTING -p tcp --dport 5000 -j REDIRECT --to-port 29220 && samply record --save-only -o prof.json -- ./target/profiling/beta"]
