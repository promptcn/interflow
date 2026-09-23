# Interflow examples

The product scenario, runnable end to end:

| Goal | Example | Entry point |
|---|---|---|
| Reach a LAN service through a public domain | [`public-domain-to-lan/`](public-domain-to-lan/README.md) | `interflow` (identity-first: manifest → Credential Packs) |

The example is self-contained and uses neutral names:

- workspace: `demo`
- reserved DNS names such as `app.example.com`
- local listeners and services on loopback

The scenario README contains material generation, a single-machine smoke
test, and a real multi-host deployment checklist. Generated `certs/` and
`dist/` directories are intentionally ignored by Git; never commit private
keys, issuer stores, or Credential Packs.

Engine-level scenarios (site-to-site with hand-managed X.509 material) are
expert examples and live beside the engine in `crates/mesh/dev-examples/`.

Environment-specific configurations live outside `examples/` in the private
`deployments/` tree and are not part of the public source export.
