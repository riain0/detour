FROM rust:slim AS chef
RUN cargo install cargo-chef --locked

FROM chef AS planner
WORKDIR /workspace
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /workspace
COPY --from=planner /workspace/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --package detour-broker
COPY . .
RUN cargo build --release --package detour-broker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/detour-broker /usr/local/bin/
ENV DETOUR_AUTH_MODE=session-id
CMD ["detour-broker"]
