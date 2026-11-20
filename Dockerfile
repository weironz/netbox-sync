FROM rust:1.98-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --target x86_64-unknown-linux-musl

FROM prom/prometheus@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac AS prometheus

FROM scratch
COPY --from=prometheus /bin/promtool /bin/promtool
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/netbox-sync /netbox-sync
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/netbox-sync"]
