FROM rust AS builder

WORKDIR /netto
COPY . .

# Dependencies
RUN rustup component add rustfmt
RUN cargo install wasm-pack
RUN apt update && apt install -y libelf-dev clang

# Build
RUN cargo build -p netto --release
RUN wasm-pack build --no-typescript --target web --out-dir ../www/pkg web-frontend

FROM ubuntu:22.04

WORKDIR /netto
COPY --from=builder /netto/target/release/netto .
COPY --from=builder /netto/www www/
RUN apt update && apt install -y libelf1 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGINT
ENTRYPOINT ["/netto/netto"]
