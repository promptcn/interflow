# Site-to-site private networks

This `interflow-mesh` example connects a client on LAN A to a service on LAN B
through a public hub. Both agents use the same tenant CA for hub mTLS and establish
an additional TLS 1.3 layer for TCP payload, so the hub routes ciphertext without
terminating the agent-to-agent payload protection.

```text
LAN A client ─► lan-a :3001 ─► hub :6666 ─► lan-b ─► 127.0.0.1:3000
                              (mTLS + routing)
```

## Files

- `generate-certs.sh` — issue the local, git-ignored certificate set
- `start-hub.sh` — run the public relay
- `start-agent-lan-a.sh` — run the LAN A ingress agent
- `start-agent-lan-b.sh` — run the LAN B egress agent
- `hub.toml`, `agent-lan-a.toml`, `agent-lan-b.toml` — scenario configuration

All IDs use tenant `demo`. Certificate CNs must equal the corresponding
`[agent].id`: `lan-a` and `lan-b`.

## Local smoke test

Build the binary, then from this directory generate certificates:

```bash
cargo build --release --bin interflow-mesh
INTERFLOW_MESH_BIN=../../target/release/interflow-mesh ./generate-certs.sh
```

Terminal 1 — hub:

```bash
INTERFLOW_MESH_BIN=../../target/release/interflow-mesh ./start-hub.sh
```

Terminal 2 — service and LAN B agent (run the service in a second shell if you
want long-lived command history):

```bash
python3 -m http.server 3000
INTERFLOW_MESH_BIN=../../target/release/interflow-mesh ./start-agent-lan-b.sh
```

Terminal 3 — LAN A agent:

```bash
INTERFLOW_MESH_BIN=../../target/release/interflow-mesh ./start-agent-lan-a.sh
```

Terminal 4 — access LAN B through LAN A:

```bash
curl --fail http://127.0.0.1:3001/
```

The agents' E2E handshake succeeds before LAN B dials the target service. A
failed or missing inner TLS handshake closes the stream instead of falling back
to plaintext.

## Real deployment

1. Issue certificates with the hub name agents will dial:

   ```bash
   ./generate-certs.sh --hub-dns hub.example.com
   ```

2. Distribute the minimum material:

   | Host | Config | Public certificates | Private key |
   |---|---|---|---|
   | Public hub | `hub.toml` | `certs/hub.crt`, `certs/tenants/demo-ca.crt` | `certs/hub.key` |
   | LAN A | `agent-lan-a.toml` | `certs/tenants/demo-ca.crt`, `certs/agents/lan-a.crt` | `certs/agents/lan-a.key` |
   | LAN B | `agent-lan-b.toml` | `certs/tenants/demo-ca.crt`, `certs/agents/lan-b.crt` | `certs/agents/lan-b.key` |
   | Operator | — | — | keep `certs/tenants/demo-ca.key` offline |

3. Change the following fields together:
   - both agents' `[agent].hub_url` to `https://hub.example.com:6666`
   - LAN A ingress `remote_addr` to the service address as reachable from LAN B
   - LAN B `security.allowed_targets` to include exactly that service address

4. Open TCP port `6666` on the hub firewall and start the three scripts on their
   respective hosts.

Relative certificate paths in every TOML are anchored to that TOML file. Keep the
`certs/...` layout when copying files, or replace the paths with absolute paths.

## UDP forwarding (advanced)

TCP is intentionally kept in the minimal quickstart. To forward UDP, add a UDP
ingress rule on LAN A and allow the same target on LAN B. For example, forward
local DNS port `5353` to a resolver at `127.0.0.1:53` on LAN B:

```toml
# agent-lan-a.toml
[[ingress]]
name = "dns-to-lan-b"
listen_addr = "127.0.0.1:5353"
listen_protocol = "udp"
target_agent = "lan-b"
remote_addr = "127.0.0.1:53"
idle_timeout_secs = 60
udp_per_ip_pps = 50
udp_per_ip_bytes_per_sec = 10240
udp_egress_bytes_per_sec = 262144
```

```toml
# agent-lan-b.toml
[security]
allowed_targets = ["127.0.0.1:3000", "127.0.0.1:53"]
```

UDP datagram boundaries are preserved. The current E2E layer covers TCP only;
UDP retains agent-to-hub TLS, not agent-to-agent inner TLS.
