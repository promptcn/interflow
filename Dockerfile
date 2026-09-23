# syntax=docker/dockerfile:1.7
# Multi-stage build: compile the rust workspace → run on distroless.
#
# Builds `interflow-mesh` by default (site-to-site hub/agent). For the
# unified CLI (ingress/agent from Credential Packs):
#   docker build --build-arg BINARY=interflow -t interflow:latest .
#
# Run the mesh hub (mount config and certificates; relative paths inside
# the config resolve against the config file's directory, i.e.
# /etc/interflow/certs — no WORKDIR gymnastics needed):
#   docker run -d \
#     -p 6666:6666 \
#     -v $PWD/examples/site-to-site/hub.toml:/etc/interflow/hub.toml:ro \
#     -v $PWD/examples/site-to-site/certs:/etc/interflow/certs:ro \
#     interflow:latest
#
# Run the mesh agent:
#   docker run -d \
#     -v $PWD/agent.toml:/etc/interflow/agent.toml:ro \
#     -v $PWD/certs:/etc/interflow/certs:ro \
#     interflow:latest agent --config /etc/interflow/agent.toml
#
# Run the ingress from its Credential Pack (issue it on an operator machine
# with `interflow plan apply`; the pack directory carries identity + trust):
#   docker run -d \
#     -p 8443:8443 -p 16666:16666 \
#     -v $PWD/dist/packs/ingress-edge:/etc/interflow/pack:ro \
#     interflow:latest ingress run --pack /etc/interflow/pack

ARG BINARY=interflow-mesh

# -------- builder stage --------
FROM rust:1.97-slim AS builder

ARG BINARY

WORKDIR /src

# Copy manifests + all crate sources first (leverages the BuildKit cache to speed up dependency compilation).
# src-tauri is a workspace member so its manifest must be present for cargo to
# load the workspace; the --bin selection below keeps the GUI itself (and its
# webkit2gtk dependency tree) out of the image build.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src-tauri src-tauri

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin ${BINARY} && \
    cp target/release/${BINARY} /app

# -------- runtime stage --------
FROM gcr.io/distroless/cc-debian12:nonroot

ARG BINARY

# Non-root, minimal image, no shell — reduces the attack surface
COPY --from=builder /app /usr/local/bin/app

# mesh hub defaults to 6666; the ingress listener defaults to 8443
EXPOSE 6666 8443 9100

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/app"]
