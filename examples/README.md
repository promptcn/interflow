# Interflow examples

Choose the scenario that matches your goal:

| Goal | Example | Binary |
|---|---|---|
| Reach a LAN service through a public domain | [`public-domain-to-lan/`](public-domain-to-lan/README.md) | `interflow-expose` |
| Interconnect two private networks | [`site-to-site/`](site-to-site/README.md) | `interflow-mesh` |

Both examples are self-contained and use neutral names:

- tenant: `demo`
- reserved DNS names such as `app.example.com` / `hub.example.com`
- local listeners and services on loopback

Each scenario README contains certificate generation, a single-machine smoke test,
and a real multi-host deployment checklist. Generated `certs/` directories are
intentionally ignored by Git; never commit private keys or CA material.

Environment-specific configurations live outside `examples/` in the private
`deployments/` tree and are not part of the public source export.
