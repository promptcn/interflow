# syntax=docker/dockerfile:1.7
# Multi-stage build: compile the rust workspace → run on distroless.
#
# Builds `interflow-mesh` by default (site-to-site hub/agent). For `interflow-expose`:
#   docker build --build-arg BINARY=interflow-expose -t interflow-expose:latest .
#
# Run the mesh hub (mount config and certificates; relative paths inside
# the config resolve against the config file's directory, i.e.
# /etc/interflow/certs — no WORKDIR gymnastics needed):
#   docker run -d \
#     -p 6666:6666 \
#     -v $PWD/crates/mesh/examples/hub.toml:/etc/interflow/hub.toml:ro \
#     -v $PWD/crates/mesh/examples/certs:/etc/interflow/certs:ro \
#     interflow:latest
#
# Run the mesh agent:
#   docker run -d \
#     -v $PWD/agent.toml:/etc/interflow/agent.toml:ro \
#     -v $PWD/certs:/etc/interflow/certs:ro \
#     interflow:latest agent --config /etc/interflow/agent.toml
#
# Run the expose edge (public entry point):
#   docker run -d \
#     -p 8443:8443 \
#     -v $PWD/routes.toml:/etc/interflow/routes.toml:ro \
#     interflow-expose:latest edge --listen 0.0.0.0:8443 --routes /etc/interflow/routes.toml --token $TOKEN

ARG BINARY=interflow-mesh

# -------- builder stage --------
FROM rust:1.97-slim AS builder

ARG BINARY

WORKDIR /src

# Copy manifests + all crate sources first (leverages the BuildKit cache to speed up dependency compilation)
COPY Cargo.toml Cargo.lock ./
COPY crates crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin ${BINARY} && \
    cp target/release/${BINARY} /app

# -------- runtime stage --------
FROM gcr.io/distroless/cc-debian12:nonroot

ARG BINARY

# Non-root, minimal image, no shell — reduces the attack surface
COPY --from=builder /app /usr/local/bin/app

# mesh hub defaults to 6666; expose edge defaults to 8443
EXPOSE 6666 8443 9100

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/app"]
