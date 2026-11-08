//! Rendered deployment artifacts: systemd units, nginx fragments and the
//! server bootstrap script — all pure functions of the manifest
//!
//! `plan apply` writes them next to the packs (`--out`); `node install`
//! re-derives the unit on the server from the pack itself. Every unit has
//! exactly one writer: `install.sh` is machine bootstrap only and installs
//! no units — node units belong to `node install` (keyed on the pack
//! landing, which is what binds a node to a machine), the registrar unit
//! to the operator bootstrap its header records. All share the
//! install-layout convention:
//!
//! - binaries  `/usr/local/bin/{interflow-cli,interflow-mesh,interflow-registrar}`
//! - packs     `<root>/packs/<kind>-<node>` (`root` defaults to /srv/interflow)
//! - registrar `<root>/registrar/{issuer,tls}` (registrar deployments only)
//!
//! Units are compile products of the manifest — users never hand-write them.
//! nginx is never taken over either: only self-contained fragments are
//! rendered, and hooking them into the user's nginx stays an explicit
//! one-line include per context.

use interflow_buildinfo::BUILD_TAG;
use interflow_identity::manifest::{IngressConfig, Manifest, PublicTlsMode, RouteConfig};
use interflow_identity::pack::PackKind;
use std::fmt::Write as _;
use std::path::Path;

/// Default server-side install root (`node install --root` overrides it).
pub const DEFAULT_INSTALL_ROOT: &str = "/srv/interflow";
/// System user/group every interflow unit runs as.
pub const INSTALL_USER: &str = "interflow";
/// Loopback port where nginx terminates public TLS after the stream fragment
/// dispatches the public 443 by SNI (frontend-proxy topology).
pub const NGINX_INTERNAL_HTTPS_LISTEN: &str = "127.0.0.1:9443";
/// Loopback listener the rendered registrar unit serves on (fronted by the
/// nginx stream fragment when the deployment converges on a single 443).
pub const REGISTRAR_LISTEN: &str = "127.0.0.1:18666";

/// Server-side install path of a node pack.
pub fn installed_pack_dir(root: &str, kind: PackKind, node: &str) -> String {
    format!("{root}/packs/{}-{node}", kind.as_str())
}

/// The command line a node runs: the pack's kind (+ mesh role) selects the
/// binary. The single source for unit ExecStart lines and doctor hints.
pub fn node_exec_start(kind: PackKind, mesh_role: bool, pack: &str) -> String {
    let bin = node_engine_binary(kind, mesh_role);
    match (kind, mesh_role) {
        (PackKind::Hub, _) => format!("{bin} hub --pack {pack}"),
        (PackKind::Agent, true) => format!("{bin} agent --pack {pack}"),
        (PackKind::Agent, false) | (PackKind::Ingress, _) => {
            format!("{bin} {} run --pack {pack}", kind.as_str())
        }
    }
}

/// Where `install.sh` places the engine binaries. Unit `ExecStart` lines
/// resolve against it, and `node install`'s pre-flight check confirms the
/// file is actually there (both through this one constant).
pub const ENGINE_BIN_DIR: &str = "/usr/local/bin";

/// The engine binary a node of this kind (+ mesh role) runs — the first
/// token of every [`node_exec_start`] line. `node install` checks the same
/// name for existence before swapping anything in.
pub const fn node_engine_binary(kind: PackKind, mesh_role: bool) -> &'static str {
    match (kind, mesh_role) {
        (PackKind::Hub, _) | (PackKind::Agent, true) => "interflow-mesh",
        (PackKind::Agent, false) | (PackKind::Ingress, _) => "interflow-cli",
    }
}

// ---------------------------------------------------------------------------
// Vintage — every rendered artifact says which build rendered it, from
// which declaration
// ---------------------------------------------------------------------------
//
// Rendered artifacts had no provenance: the nginx fragments on the server
// did not say which build's renderer produced them, so "is this the
// current fragment?" was answerable only by re-rendering and diffing
// Every artifact now carries a one-line self-description — an operator
// `head -2` on the deployed fragment reads the build tag and the manifest
// digest; `plan stage` compares its own fresh render against dist's bytes
// and names any gap. One format, one source: the snapshot and stage tests
// build their expected lines from these functions, so the wording cannot
// drift between renderer and tests.

/// The provenance comment every manifest-derived artifact carries right
/// under its description line.
///
/// Which build rendered it, from which declaration (the sha256 of the
/// manifest file's exact bytes — the same input `plan apply`/`plan stage`
/// rendered from).
pub fn vintage_comment(manifest_sha256: &str) -> String {
    format!("# rendered by interflow-cli {BUILD_TAG} from manifest sha256:{manifest_sha256}\n")
}

/// The build-only provenance line for artifacts rendered without manifest
/// bytes at hand — `node install` re-derives units from the pack, and the
/// build tag is the whole vintage that path owns.
pub fn build_vintage_comment() -> String {
    format!("# rendered by interflow-cli {BUILD_TAG}\n")
}

/// systemd unit for a node pack — a pure function of the manifest fields.
///
/// `Type=notify`: the engine binaries signal `READY=1` (`sd_notify`, see
/// `interflow-util`'s `systemd` module) once every listener they serve is
/// bound — hub/ingress at their readiness barriers, agents at their local
/// ingress surface. systemd therefore knows readiness exactly; start jobs
/// (and `node install` behind them) block until READY or `TimeoutStartSec`
/// (30s, the same budget the removed TCP probes used). No hardening
/// directive blocks the notify path (`NotifyAccess` defaults to `main`,
/// the ExecStart process itself).
pub fn node_unit(root: &str, kind: PackKind, node: &str, mesh_role: bool) -> String {
    let kind_arg = kind.as_str();
    let pack = installed_pack_dir(root, kind, node);
    let exec_start = node_exec_start(kind, mesh_role, &pack);
    format!(
        "{}[Unit]\nDescription=Interflow {kind_arg} node {node}\nAfter=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\nType=notify\nTimeoutStartSec=30s\n\
         ExecStart={ENGINE_BIN_DIR}/{exec_start}\nRestart=always\nRestartSec=5\n\
         User={INSTALL_USER}\nGroup={INSTALL_USER}\nNoNewPrivileges=true\n\
         ProtectSystem=strict\nReadWritePaths={pack}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        build_vintage_comment(),
    )
}

/// Whether this deployment runs an independent registrar.
pub const fn has_registrar(manifest: &Manifest) -> bool {
    !manifest.registrar.endpoint.is_empty()
}

/// systemd unit for the independent registrar service.
///
/// No pack ever lands for the registrar — its unit is bound to its host by
/// the operator's one-time bootstrap, which the unit header records in
/// full: install the unit, copy the issuer store, mint the endpoint
/// certificate, enable. install.sh deliberately installs none of this.
pub fn registrar_unit(manifest: &Manifest, root: &str, manifest_sha256: &str) -> String {
    let endpoint = &manifest.registrar.endpoint;
    let leaf_ttl = manifest
        .identity
        .leaf_ttl
        .clone()
        .unwrap_or_else(|| "24h".to_owned());
    let mut hub_flags = String::new();
    for (node, cfg) in &manifest.mesh.hub {
        write!(hub_flags, " \\\n  --hub-endpoint {node}={}", cfg.endpoint)
            .expect("writing to a String cannot fail");
    }
    format!(
        "{vintage}\
         # One-time bootstrap (operator, on the registrar server):\n\
         #   0. install -m 0644 interflow-registrar.service /etc/systemd/system/ \\\n\
         #      && systemctl daemon-reload\n\
         #   1. copy the issuer store to {root}/registrar/issuer (keep it 0600)\n\
         #   2. interflow-registrar certificate \\\n\
         #        --issuer {root}/registrar/issuer \\\n\
         #        --realm {realm} --node registrar --endpoint {endpoint} \\\n\
         #        --out-cert {root}/registrar/tls/registrar.crt \\\n\
         #        --out-key {root}/registrar/tls/registrar.key\n\
         #   3. systemctl enable --now interflow-registrar\n\
         [Unit]\n\
         Description=Interflow registrar (independent identity issuer)\n\
         After=network-online.target\nWants=network-online.target\n\n\
         [Service]\n\
         ExecStart=/usr/local/bin/interflow-registrar serve \\\n\
         \x20 --issuer {root}/registrar/issuer \\\n\
         \x20 --listen {REGISTRAR_LISTEN} \\\n\
         \x20 --endpoint {endpoint} \\\n\
         \x20 --tls-cert {root}/registrar/tls/registrar.crt \\\n\
         \x20 --tls-key {root}/registrar/tls/registrar.key \\\n\
         \x20 --leaf-ttl {leaf_ttl} \\\n\
         \x20 --control-endpoint {control_endpoint}{hub_flags}\n\
         Restart=always\nRestartSec=5\nUser={INSTALL_USER}\nGroup={INSTALL_USER}\n\
         NoNewPrivileges=true\nProtectSystem=strict\nReadWritePaths={root}/registrar\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        realm = manifest.realm.id,
        control_endpoint = manifest.realm.control_endpoint,
        vintage = vintage_comment(manifest_sha256),
    )
}

/// Hostname of an endpoint (`host:port`, `https://host`, or bare `host`) —
/// parsed through the shared authority parser so an IPv6 literal arrives
/// bracket-free and whole instead of truncated at the first colon (a
/// hand-rolled `split_once(':')` keyed `[` into the SNI map). The endpoints
/// reaching here parsed at issuance already; a parse failure is a broken
/// invariant, surfaced loudly rather than rendered into nginx.
fn endpoint_host(endpoint: &str) -> interflow_core::error::Result<String> {
    interflow_util::parse_endpoint(endpoint)
        .map(|parsed| parsed.host)
        .map_err(|e| {
            interflow_core::error::InterflowError::config(format!(
                "rendering the nginx stream map from endpoint {endpoint:?}"
            ))
            .with_source(e)
        })
}

/// Loopback dial target for a listen address (`0.0.0.0:` binds become
/// `127.0.0.1:` — the nginx stream fragment dials loopback).
fn loopback_target(listen: &str) -> String {
    if let Some(port) = listen.rsplit_once(':').map(|(_, p)| p) {
        format!("127.0.0.1:{port}")
    } else {
        listen.to_owned()
    }
}

/// `nginx/stream/interflow-stream.conf` — SNI dispatch on the single public
/// port.
///
/// Business TLS terminates on the internal https listener, control and
/// registrar server names pass through so their mTLS stays end-to-end.
pub fn nginx_stream_fragment(
    manifest: &Manifest,
    manifest_sha256: &str,
) -> interflow_core::error::Result<String> {
    let mut entries = Vec::new();
    if !manifest.realm.control_endpoint.is_empty()
        && let Some((_, ingress)) = manifest.ingress.iter().next()
    {
        entries.push((
            endpoint_host(&manifest.realm.control_endpoint)?,
            loopback_target(&ingress.control_listen),
            "control endpoint (mTLS passthrough)",
        ));
    }
    if has_registrar(manifest) {
        entries.push((
            endpoint_host(&manifest.registrar.endpoint)?,
            REGISTRAR_LISTEN.to_owned(),
            "registrar (mTLS passthrough)",
        ));
    }
    let width = entries
        .iter()
        .map(|(host, _, _)| host.len())
        .max()
        .unwrap_or(0);
    let mut map = String::new();
    for (host, target, note) in &entries {
        writeln!(map, "    {host:<width$}  {target};   # {note}")
            .expect("writing to a String cannot fail");
    }
    Ok(format!(
        "# Generated by interflow-cli — single public port: 443 SNI dispatch.\n{vintage}\
         #\n\
         # Add once at the TOP LEVEL of nginx.conf (outside http {{}}):\n\
         #   stream {{ include /etc/nginx/interflow/stream/*.conf; }}\n\
         #\n\
         # Business TLS terminates on the internal listener; control and\n\
         # registrar server names pass through so their mTLS stays end-to-end.\n\
         # Point [realm].control_endpoint at `<host>:443` and [registrar].endpoint\n\
         # at `https://<host>`, then close 16666/18666 in the firewall — the\n\
         # public surface is just 443.\n\
         #\n\
         # proxy_protocol on emits a v1 preamble (nginx >= 1.9.2; v2 needs the\n\
         # 1.31+ `v2` parameter — distro nginx stays the baseline) on every map\n\
         # target, restoring the real client IP after 127.0.0.1-fronted\n\
         # connections collapsed per-IP limits into one shared bucket. Three\n\
         # consumers, all tolerant of both versions and of headerless\n\
         # connections: the internal https listener (its `listen ... proxy_protocol`\n\
         # parameter, nginx >= 1.13.11, see nginx/http/interflow-shared.conf),\n\
         # the ingress control endpoint and the registrar (both consume the\n\
         # preamble before their TLS handshake).\n\
         map $ssl_preread_server_name $interflow_backend {{\n\
         \x20   hostnames;\n\
         \x20   default                 {NGINX_INTERNAL_HTTPS_LISTEN};   # business → internal TLS termination\n\
         {map}}}\n\
         \nserver {{\n\
         \x20   listen 443;\n\
         \x20   ssl_preread on;\n\
         \x20   proxy_protocol on;\n\
         \x20   proxy_pass $interflow_backend;\n\
         \x20   proxy_connect_timeout 5s;\n\
         }}\n",
        vintage = vintage_comment(manifest_sha256),
    ))
}

/// `nginx/http/interflow-shared.conf` — frontend-proxy primitives shared by
/// the vhost fragments (real-IP restoration + rate limiting + WebSocket
/// upgrade mapping).
pub fn nginx_shared_fragment(manifest_sha256: &str) -> String {
    format!(
        "# Generated by interflow-cli — shared frontend-proxy primitives.\n{vintage}\
         # Include from the http context together with the vhost fragments:\n\
         #   include /etc/nginx/interflow/http/*.conf;\n\
         \n\
         # Real client IP: the stream layer fronts this listener with PROXY\n\
         # protocol (see nginx/stream/interflow-stream.conf). Requires the realip\n\
         # module (included in distro and nginx.org builds).\n\
         set_real_ip_from 127.0.0.1;\n\
         set_real_ip_from ::1;\n\
         real_ip_header proxy_protocol;\n\
         \n\
         # Rate limiting: 30 requests/s per client IP (real IP post-realip),\n\
         # burst 60 — SPA first-loads fan out dozens of asset requests.\n\
         limit_req_zone $binary_remote_addr zone=interflow_req:10m rate=30r/s;\n\
         # Concurrency: at most 50 connections per client IP.\n\
         limit_conn_zone $binary_remote_addr zone=interflow_conn:10m;\n\
         # Distinguish throttle denials (429) from gateway failures (502/503).\n\
         limit_req_status 429;\n\
         limit_conn_status 429;\n\
         \n\
     # WebSocket upgrade mapping.\n\
     map $http_upgrade $connection_upgrade {{\n\
     \x20   default upgrade;\n\
     \x20   ''      close;\n\
     }}\n",
        vintage = vintage_comment(manifest_sha256),
    )
}

/// `nginx/http/interflow-http.conf` — port 80: ACME challenges + redirect.
pub fn nginx_http_fragment(routes: &[RouteConfig], manifest_sha256: &str) -> String {
    let hosts: Vec<&str> = routes.iter().map(|r| r.host.as_str()).collect();
    format!(
        "# Generated by interflow-cli — port 80: ACME challenges + redirect.\n{vintage}\
         server {{\n\
         \x20   listen 80;\n\
         \x20   server_name {hosts};\n\
         \n\
         \x20   # Let's Encrypt HTTP-01 challenges (certbot --webroot -w /var/www/certbot);\n\
         \x20   # drop this block if you renew certificates another way.\n\
         \x20   location /.well-known/acme-challenge/ {{\n\
         \x20       root /var/www/certbot;\n\
         \x20   }}\n\
         \n\
         \x20   location / {{\n\
         \x20       return 301 https://$host$request_uri;\n\
         \x20   }}\n\
         }}\n",
        hosts = hosts.join(" "),
        vintage = vintage_comment(manifest_sha256),
    )
}

/// `nginx/http/interflow-vhost-<ingress>.conf` — the business vhosts for one
/// ingress: TLS termination on the internal listener, XFF restoration,
/// unbuffered streaming and WebSocket upgrade.
pub fn nginx_vhost_fragment(
    node: &str,
    cfg: &IngressConfig,
    routes: &[RouteConfig],
    manifest_sha256: &str,
) -> String {
    let port = cfg
        .listen
        .rsplit_once(':')
        .map_or_else(|| "8443".to_owned(), |(_, p)| p.to_owned());
    let mut servers = String::new();
    for route in routes {
        let host = &route.host;
        write!(
            servers,
            "server {{\n\
             \x20   listen {NGINX_INTERNAL_HTTPS_LISTEN} ssl http2 proxy_protocol;\n\
             \x20   server_name {host};\n\
             \n\
             \x20   # Fill in your public certificate (e.g. certbot's\n\
             \x20   # /etc/letsencrypt/live/<domain>/fullchain.pem).\n\
             \x20   ssl_certificate     /etc/nginx/certs/{host}.crt;\n\
             \x20   ssl_certificate_key /etc/nginx/certs/{host}.key;\n\
             \x20   ssl_protocols TLSv1.3;\n\
             \n\
             \x20   location / {{\n\
             \x20       limit_req zone=interflow_req burst=60 nodelay;\n\
             \x20       limit_conn interflow_conn 50;\n\
             \n\
             \x20       proxy_pass http://127.0.0.1:{port};\n\
             \x20       proxy_http_version 1.1;\n\
             \x20       proxy_set_header Host $host;\n\
             \x20       proxy_set_header X-Real-IP $remote_addr;\n\
             \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
             \x20       proxy_set_header X-Forwarded-Proto https;\n\
             \n\
             \x20       # Token streaming (SSE) must not be buffered by the proxy.\n\
             \x20       proxy_buffering off;\n\
             \n\
             \x20       # WebSocket upgrade.\n\
             \x20       proxy_set_header Upgrade $http_upgrade;\n\
             \x20       proxy_set_header Connection $connection_upgrade;\n\
             \n\
             \x20       proxy_read_timeout 600s;\n\
             \x20       proxy_send_timeout 600s;\n\
             \x20   }}\n\
             \n\
             \x20   # Throttle denials carry Retry-After so well-behaved\n\
             \x20   # clients back off cleanly (same contract as the edge's\n\
             \x20   # own 429s).\n\
             \x20   error_page 429 = @interflow_rate_limited;\n\
             \x20   location @interflow_rate_limited {{\n\
             \x20       add_header Retry-After 1 always;\n\
             \x20       return 429;\n\
             \x20   }}\n\
             }}\n\n",
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        "# Generated by interflow-cli — frontend-proxy vhosts for ingress {node}.\n{vintage}\
         # The public 443 arrives via nginx/stream/interflow-stream.conf SNI dispatch;\n\
         # TLS terminates here on the internal listener. The ingress enables\n\
         # X-Forwarded-For restoration automatically in this topology.\n\n{servers}",
        vintage = vintage_comment(manifest_sha256),
    )
}

/// `install.sh` — idempotent machine bootstrap.
///
/// System user, directories and the `bin/` payload — nothing else. It
/// installs no units and calls no systemctl: node units are written and
/// enabled by `node install --pack` (the pack landing is what binds a node
/// to a machine), and the registrar unit follows its own header's bootstrap
/// sequence. nginx and the registrar's issuer material are likewise out of
/// scope: fragments are hooked in by the operator, secret material by hand.
///
/// Three properties are load-bearing, not conveniences (the 2026-10/11
/// staging incidents, (internal design notes)):
/// every path resolves next to the script itself, never the CWD (running
/// from elsewhere used to resolve `bin/` against the wrong directory and
/// silently skip the binaries); `bin/` is mandatory — missing or empty
/// fails loudly, because a tree without binaries is a partial copy or a
/// hand-assembled one; and a `stage-manifest.json` written by
/// `plan stage` is verified before anything is installed
/// (`install.sh --verify-staging` runs the same check alone, no root
/// needed) — the transfer itself is gated, using system tools only.
pub fn install_sh(manifest: &Manifest, manifest_sha256: &str) -> String {
    let registrar_hint = if has_registrar(manifest) {
        "\n# The registrar unit is not installed here either: follow the\n\
         # bootstrap sequence in systemd/interflow-registrar.service.\n"
    } else {
        ""
    };
    let registrar_dirs = if has_registrar(manifest) {
        "\n# Registrar data layout (content is operator-copied; see\n\
         # systemd/interflow-registrar.service for the bootstrap commands).\n\
         install -d -o \"$INTERFLOW_USER\" -g \"$INTERFLOW_GROUP\" -m 0750 \\\n\
         \x20 \"$SRV_ROOT/registrar\" \"$SRV_ROOT/registrar/issuer\" \\\n\
         \x20 \"$SRV_ROOT/registrar/tls\"\n"
    } else {
        ""
    };
    format!(
        r#"#!/usr/bin/env bash
# Generated by interflow-cli — bootstrap a server for interflow nodes.
{vintage}# Machine-scope only: user, dirs, bin/ — no units are installed here and no
# service is touched; re-running never duplicates the user. The tree this
# ships in is produced by `interflow-cli plan stage --host <kind>/<node>`
# (bin/ + the node's pack + nginx/ fragments + stage-manifest.json).
# Run as root, from anywhere — paths resolve next to the script:
#   sudo bash install.sh
# Self-contained layout (containers, tests — no system user, everything
# under one root, the same contract `node install --root` offers):
#   bash install.sh --root <dir>
# Pre-check a transferred tree without touching the machine:
#   bash install.sh --verify-staging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

sha256_file() {{
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}}

# The transfer-integrity gate: every file stage-manifest.json lists must
# exist and match its sha256, and the tree must hold no unlisted file — a
# partial or modified copy fails here, before anything is installed. The
# verifier uses system tools only; it never executes what it verifies.
# Entries are emitted one per line by `plan stage`:
#   {{"path": "...", "sha256": "...", "bytes": N}}
verify_staging() {{
  local manifest="$SCRIPT_DIR/stage-manifest.json"
  if [[ ! -f "$manifest" ]]; then
    echo "verify-staging: stage-manifest.json not found next to install.sh" >&2
    exit 1
  fi
  local failures=0 listed=0 path want got in_manifest in_tree
  while IFS= read -r entry; do
    path="$(printf '%s' "$entry" | sed -e 's/^.*"path": "//' -e 's/".*$//')"
    want="$(printf '%s' "$entry" | sed -e 's/^.*"sha256": "//' -e 's/".*$//')"
    if [[ ! -f "$SCRIPT_DIR/$path" ]]; then
      echo "verify-staging: $path is listed but missing from the tree" >&2
      failures=$((failures + 1))
      continue
    fi
    got="$(sha256_file "$SCRIPT_DIR/$path")"
    if [[ "$got" != "$want" ]]; then
      echo "verify-staging: $path does not match stage-manifest.json (expected $want, got $got)" >&2
      failures=$((failures + 1))
    fi
    listed=$((listed + 1))
  done < <(grep -oE '"path": "[^"]+", "sha256": "[0-9a-f]{{64}}"' "$manifest")
  if [[ $listed -eq 0 ]]; then
    echo "verify-staging: stage-manifest.json lists no files — it is not a plan stage manifest" >&2
    exit 1
  fi
  in_manifest="$(grep -oE '"path": "[^"]+"' "$manifest" | sed -e 's/^"path": "//' -e 's/"$//' | sort)"
  in_tree="$(cd "$SCRIPT_DIR" && find . -type f ! -path './stage-manifest.json' | sed 's|^\./||' | sort)"
  if [[ "$in_manifest" != "$in_tree" ]]; then
    echo "verify-staging: the tree does not match the manifest's file list (missing or extra files):" >&2
    diff <(printf '%s\n' "$in_manifest") <(printf '%s\n' "$in_tree") >&2 || true
    failures=$((failures + 1))
  fi
  if [[ $failures -gt 0 ]]; then
    echo "verify-staging: FAILED ($failures problem(s)) — re-copy the staging tree from the operator machine" >&2
    exit 1
  fi
  echo "verify-staging: OK — $listed files match stage-manifest.json"
}}

if [[ "${{1:-}}" == "--verify-staging" ]]; then
  verify_staging
  exit 0
fi

# Self-contained layout (--root <dir>): everything lands under the given
# root and no system user is managed — the same contract `node install
# --root` offers, for containers and tests. The default path is the machine
# scope: system user, /srv/interflow, /usr/local/bin.
SELF_ROOT=""
if [[ "${{1:-}}" == "--root" ]]; then
  if [[ -z "${{2:-}}" ]]; then
    echo "install.sh: --root needs a directory argument" >&2
    exit 1
  fi
  SELF_ROOT="$2"
elif [[ -n "${{1:-}}" ]]; then
  echo "install.sh: unknown argument $1 (use --verify-staging or --root <dir>)" >&2
  exit 1
fi

if [[ -z "$SELF_ROOT" && $EUID -ne 0 ]]; then
  echo "install.sh must run as root (sudo bash install.sh), or pass --root <dir> for a" >&2
  echo "self-contained layout (no system user, no /usr/local/bin)" >&2
  exit 1
fi

INTERFLOW_USER={INSTALL_USER}
INTERFLOW_GROUP={INSTALL_USER}
if [[ -n "$SELF_ROOT" ]]; then
  SRV_ROOT="$SELF_ROOT"
  BIN_DIR="$SELF_ROOT/bin"
  install -d -m 0755 "$SRV_ROOT" "$SRV_ROOT/packs"{registrar_dirs}
else
  SRV_ROOT={DEFAULT_INSTALL_ROOT}
  BIN_DIR=/usr/local/bin

  if ! getent group "$INTERFLOW_GROUP" >/dev/null; then
    groupadd --system "$INTERFLOW_GROUP"
  fi
  if ! id "$INTERFLOW_USER" >/dev/null 2>&1; then
    useradd --system --gid "$INTERFLOW_GROUP" --home-dir "$SRV_ROOT" \
      --shell /usr/sbin/nologin "$INTERFLOW_USER"
    echo "created system user $INTERFLOW_USER"
  fi

  install -d -o "$INTERFLOW_USER" -g "$INTERFLOW_GROUP" -m 0750 \
    "$SRV_ROOT" "$SRV_ROOT/packs"{registrar_dirs}
fi

# A staging manifest, when present, gates the transfer itself: the same
# check `--verify-staging` runs, before anything is installed.
if [[ -f "$SCRIPT_DIR/stage-manifest.json" ]]; then
  verify_staging
fi

# bin/ carries the engine binaries every interflow host needs. Missing or
# empty means the tree was copied partially or assembled by hand — fail
# loudly instead of preparing half a machine. Produce the tree with:
#   interflow-cli plan stage --host <kind>/<node>
if [[ ! -d "$SCRIPT_DIR/bin" ]] || [[ -z "$(ls -A "$SCRIPT_DIR/bin" 2>/dev/null)" ]]; then
  echo "install.sh: bin/ is missing or empty at $SCRIPT_DIR/bin — the tree was" >&2
  echo "copied partially or assembled by hand; produce it with:" >&2
  echo "  interflow-cli plan stage --host <kind>/<node>" >&2
  exit 1
fi

# Copy with byte-identical skip: a second realm's install.sh on the same
# machine must not replace binaries whose bytes did not change — every
# replacement breaks the inode under running processes and arms the
# disk-swap detection against nodes running the very same build
#.
install_bins() {{
  local f name
  install -d "$BIN_DIR"
  for f in "$SCRIPT_DIR"/bin/*; do
    name="$(basename "$f")"
    if [[ -f "$BIN_DIR/$name" ]] && cmp -s "$f" "$BIN_DIR/$name"; then
      echo "install.sh: bin/$name unchanged (skipped)"
    else
      install -m 0755 "$f" "$BIN_DIR/$name"
    fi
  done
}}
install_bins

# Units are not installed here. Node units are written and enabled by
# `interflow-cli node install --pack packs/<kind>-<node>` — the pack is the
# node's only entry point: a machine gets a unit exactly when that
# node's pack lands on it.{registrar_hint}
echo "machine prepared — per node: interflow-cli node install --pack packs/<kind>-<node>"
"#,
        vintage = vintage_comment(manifest_sha256),
    )
}

fn write_fragment(path: &Path, body: &str) -> interflow_core::error::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, body)?;
    Ok(())
}

/// Writes `systemd/interflow-<kind>-<node>.service`.
pub fn write_node_unit(
    out_root: &Path,
    kind: PackKind,
    node: &str,
    mesh_role: bool,
    root: &str,
) -> interflow_core::error::Result<()> {
    let path = out_root
        .join("systemd")
        .join(format!("interflow-{}-{node}.service", kind.as_str()));
    write_fragment(&path, &node_unit(root, kind, node, mesh_role))
}

/// Writes `systemd/interflow-registrar.service` (registrar deployments).
pub fn write_registrar_unit(
    out_root: &Path,
    manifest: &Manifest,
    root: &str,
    manifest_sha256: &str,
) -> interflow_core::error::Result<()> {
    let path = out_root.join("systemd").join("interflow-registrar.service");
    write_fragment(&path, &registrar_unit(manifest, root, manifest_sha256))
}

/// One rendered nginx fragment: its tree-relative path and its full body.
pub struct RenderedFragment {
    pub rel: String,
    pub body: String,
}

/// The nginx fragment set — the single composition `plan apply` (whole
/// fleet) and `plan stage` (one host's minimal face) both render from.
///
/// `ingress_nodes = None` renders every declared ingress's vhost (the
/// dist face); `Some(&[nodes])` renders the shared set plus exactly those
/// ingresses' vhosts (a staged host tree never carries another ingress's
/// vhost; undeclared names render nothing — the callers gate declaration
/// before composing). The set is a pure function of the manifest: same
/// declaration + same build ⇒ same bytes, which is what makes stage's
/// fresh render byte-comparable with the dist copies.
fn fragment(rel: &str, body: String) -> RenderedFragment {
    RenderedFragment {
        rel: rel.to_owned(),
        body,
    }
}

pub fn nginx_fragment_set(
    manifest: &Manifest,
    manifest_sha256: &str,
    ingress_nodes: Option<&[String]>,
) -> interflow_core::error::Result<Vec<RenderedFragment>> {
    let mut fragments = vec![
        fragment(
            "nginx/stream/interflow-stream.conf",
            nginx_stream_fragment(manifest, manifest_sha256)?,
        ),
        fragment(
            "nginx/http/interflow-shared.conf",
            nginx_shared_fragment(manifest_sha256),
        ),
        fragment(
            "nginx/http/interflow-http.conf",
            nginx_http_fragment(&manifest.route, manifest_sha256),
        ),
    ];
    let nodes: Vec<(&String, &IngressConfig)> = match ingress_nodes {
        None => manifest.ingress.iter().collect(),
        Some(wanted) => wanted
            .iter()
            .filter_map(|node| manifest.ingress.get(node).map(|cfg| (node, cfg)))
            .collect(),
    };
    for (node, cfg) in nodes {
        fragments.push(fragment(
            &format!("nginx/http/interflow-vhost-{node}.conf"),
            nginx_vhost_fragment(node, cfg, &manifest.route, manifest_sha256),
        ));
    }
    Ok(fragments)
}

/// A deployed directory the nginx fragment set composes into: the staging
/// tree (`nginx/<dir>/…`) and the deployed root
/// (`/etc/nginx/interflow/<dir>/…`) share this one name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FragmentDir {
    Http,
    Stream,
}

impl FragmentDir {
    /// Every directory of the deployed layout, in reconciliation order.
    pub const ALL: [Self; 2] = [Self::Http, Self::Stream];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Stream => "stream",
        }
    }
}

impl std::fmt::Display for FragmentDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One fragment of the render set, file-name half: the deployed directory
/// it belongs to, and its file name there.
///
/// Membership is carried by the type from this single source — never
/// re-derived downstream from a string prefix or the file name (the
/// reconciliation's cross-directory false positives were exactly such a
/// re-derivation;
/// (internal design notes)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragmentRel {
    pub dir: FragmentDir,
    pub file: String,
}

impl FragmentRel {
    /// The staging-tree-relative path (`nginx/http/…` / `nginx/stream/…`) —
    /// the spelling [`nginx_fragment_set`] writes and the reconciliation's
    /// verdict lines quote.
    pub fn tree_rel(&self) -> String {
        format!("nginx/{}/{}", self.dir.as_str(), self.file)
    }
}

/// The fragment file names one host's render produces for the given
/// ingress nodes, each typed with the deployed directory it belongs to.
///
/// The FILE-NAME half of [`nginx_fragment_set`] as its own single source:
/// the deployed-directory reconciliation (`doctor ingress --nginx-dir`)
/// compares against what the renderer actually names, never a re-typed
/// list. The lockstep with `nginx_fragment_set` is test-asserted below.
pub fn nginx_fragment_rel_paths(ingress_nodes: &[String]) -> Vec<FragmentRel> {
    let mut rels = vec![
        FragmentRel {
            dir: FragmentDir::Stream,
            file: "interflow-stream.conf".to_owned(),
        },
        FragmentRel {
            dir: FragmentDir::Http,
            file: "interflow-shared.conf".to_owned(),
        },
        FragmentRel {
            dir: FragmentDir::Http,
            file: "interflow-http.conf".to_owned(),
        },
    ];
    rels.extend(ingress_nodes.iter().map(|node| FragmentRel {
        dir: FragmentDir::Http,
        file: format!("interflow-vhost-{node}.conf"),
    }));
    rels
}

/// Writes a rendered fragment set under `out_root` at each fragment's own
/// relative path.
pub fn write_fragments(
    out_root: &Path,
    fragments: &[RenderedFragment],
) -> interflow_core::error::Result<()> {
    for piece in fragments {
        write_fragment(&out_root.join(&piece.rel), &piece.body)?;
    }
    Ok(())
}

/// Writes the `nginx/` fragment set for frontend-proxy deployments.
pub fn write_nginx_fragments(
    out_root: &Path,
    manifest: &Manifest,
    manifest_sha256: &str,
) -> interflow_core::error::Result<()> {
    if manifest.public_tls.mode != PublicTlsMode::FrontendProxy {
        return Ok(());
    }
    write_fragments(
        out_root,
        &nginx_fragment_set(manifest, manifest_sha256, None)?,
    )
}

/// Writes `install.sh` at the dist root.
pub fn write_install_sh(
    out_root: &Path,
    manifest: &Manifest,
    manifest_sha256: &str,
) -> interflow_core::error::Result<()> {
    write_fragment(
        &out_root.join("install.sh"),
        &install_sh(manifest, manifest_sha256),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_MANIFEST: &str = r#"
        [realm]
        id = "promptcn"

        [identity]
        mode = "offline"

        [mesh.hub.promptcn]
        listen = "0.0.0.0:6666"
        endpoint = "hub.example.com:6666"

        [workspace.main]

        [agent.alpha]
        workspace = "main"

        [[agent.alpha.mesh_egress]]
        name = "svc"
        target_addr = "127.0.0.1:80"
    "#;

    /// The staging incidents' guards, locked at the template level (the
    /// execution-level gates live in the plan_stage integration tests):
    /// paths anchor next to the script, `bin/` is mandatory, and the
    /// staging manifest gate is present. The old fail-open shape
    /// (`if [[ -d bin ]]` … silent skip) must stay dead.
    /// The file-name single source: `nginx_fragment_rel_paths` must stay in
    /// lockstep with what `nginx_fragment_set` actually renders — the
    /// deployed-directory reconciliation compares against it, and a re-typed
    /// list here is how a renamed fragment would slip past the check.
    #[test]
    fn fragment_rel_paths_stay_in_lockstep_with_the_render_set() {
        let manifest = Manifest::parse(
            r#"
[realm]
id = "promptcn"
control_endpoint = "127.0.0.1:26666"
[public_tls]
mode = "frontend-proxy"
[identity]
mode = "offline"
[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:18443"
[ingress.second]
workspaces = ["default"]
listen = "127.0.0.1:18444"
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:18080"
[[route]]
host = "asr.example.com"
service = "default/desktop/asr"
"#,
        )
        .expect("two-ingress manifest parses");
        let sha = interflow_util::sha256_hex(b"lockstep".as_slice());
        for nodes in [
            None,
            Some(vec!["edge".to_owned()]),
            Some(vec!["edge".to_owned(), "second".to_owned()]),
        ] {
            let rendered: Vec<String> = nginx_fragment_set(&manifest, &sha, nodes.as_deref())
                .unwrap()
                .into_iter()
                .map(|f| f.rel)
                .collect();
            let expected: Vec<String> = match &nodes {
                None => manifest.ingress.keys().cloned().collect(),
                Some(wanted) => wanted.clone(),
            };
            assert_eq!(
                rendered,
                nginx_fragment_rel_paths(&expected)
                    .iter()
                    .map(FragmentRel::tree_rel)
                    .collect::<Vec<_>>(),
                "the rel-path list IS the render set's file names"
            );
        }
    }

    /// The set's directory shape, as an invariant of the source itself:
    /// the stream half is exactly one file and every vhost lands in http —
    /// whatever the node names look like. Directory membership is a
    /// property the rel paths are BORN with here, never a guess a consumer
    /// makes from the file name (the retired `contains("vhost")` guard
    /// died on exactly that guess;
    /// (internal design notes)).
    #[test]
    fn fragment_directory_membership_is_carried_by_the_source() {
        let rels = nginx_fragment_rel_paths(&[
            "edge".to_owned(),
            "stream-ha".to_owned(),
            "vhost-old".to_owned(),
        ]);
        let stream: Vec<&str> = rels
            .iter()
            .filter(|rel| rel.dir == FragmentDir::Stream)
            .map(|rel| rel.file.as_str())
            .collect();
        assert_eq!(
            stream,
            ["interflow-stream.conf"],
            "the stream half is exactly one file"
        );
        for rel in &rels {
            if rel.file != "interflow-stream.conf" {
                assert_eq!(rel.dir, FragmentDir::Http, "{} belongs in http", rel.file);
            }
        }
        // The tree spellings the staging tree and verdict lines quote.
        assert_eq!(
            rels.iter().map(FragmentRel::tree_rel).collect::<Vec<_>>(),
            [
                "nginx/stream/interflow-stream.conf",
                "nginx/http/interflow-shared.conf",
                "nginx/http/interflow-http.conf",
                "nginx/http/interflow-vhost-edge.conf",
                "nginx/http/interflow-vhost-stream-ha.conf",
                "nginx/http/interflow-vhost-vhost-old.conf",
            ]
        );
    }

    #[test]
    fn install_sh_is_stage_shaped() {
        let manifest = Manifest::parse(MINIMAL_MANIFEST).expect("minimal manifest parses");
        let sha = interflow_util::sha256_hex(MINIMAL_MANIFEST.as_bytes());
        let sh = install_sh(&manifest, &sha);
        assert!(
            sh.contains("SCRIPT_DIR="),
            "every path must anchor next to the script, never the CWD"
        );
        assert!(
            sh.contains("--verify-staging"),
            "the transfer-integrity gate must ship in the script"
        );
        assert!(
            sh.contains("stage-manifest.json"),
            "the staging manifest is verified before anything installs"
        );
        assert!(
            !sh.contains("if [[ -d bin ]]"),
            "the fail-open silent skip of bin/ must stay dead (2026-11-01 incident)"
        );
        assert!(
            sh.contains("bin/ is missing or empty"),
            "a missing or empty bin/ must fail loudly (2026-10-18/2026-11-01 incidents)"
        );
        // The byte-identical skip: re-running install.sh must never replace
        // binaries whose bytes did not change
        assert!(
            sh.contains("install_bins()"),
            "bin/ lands through the skipping copier"
        );
        assert!(
            sh.contains("cmp -s"),
            "the skip decision is a byte comparison"
        );
        assert!(
            sh.contains("unchanged (skipped)"),
            "a skipped binary says so"
        );
        assert!(
            !sh.contains("bin/* /usr/local/bin"),
            "the unconditional whole-directory copy is dead"
        );
        // The self-contained layout mirrors `node install --root`.
        assert!(
            sh.contains("--root"),
            "the self-contained layout flag ships in the script"
        );
    }

    /// The SNI map keys parse through the shared authority parser: an IPv6
    /// control endpoint keys the map on the whole bracket-free address, not
    /// `[` truncated at the first colon (the hand-rolled splitter's bug).
    #[test]
    fn endpoint_host_handles_ipv6_and_schemes() {
        assert_eq!(
            endpoint_host("example.com:16666").expect("authority parses"),
            "example.com"
        );
        assert_eq!(
            endpoint_host("https://relay.example.com").expect("endpoint parses"),
            "relay.example.com"
        );
        assert_eq!(
            endpoint_host("[2001:db8::1]:443").expect("bracketed authority parses"),
            "2001:db8::1"
        );
        assert_eq!(
            endpoint_host("https://[2001:db8::1]:443").expect("bracketed endpoint parses"),
            "2001:db8::1"
        );
        assert!(
            endpoint_host("relay example.com").is_err(),
            "garbage must fail closed, never render into the map"
        );

        // And the map itself: an IPv6 control endpoint lands whole.
        let manifest = Manifest::parse(FRONTEND_MANIFEST).expect("frontend manifest parses");
        let sha = interflow_util::sha256_hex(FRONTEND_MANIFEST.as_bytes());
        let stream = nginx_stream_fragment(&manifest, &sha).expect("stream fragment renders");
        assert!(
            stream.contains("example.com  127.0.0.1:16666"),
            "the SNI map keys on the endpoint's host: {stream}"
        );
    }

    const FRONTEND_MANIFEST: &str = r#"
        [realm]
        id = "promptcn"
        control_endpoint = "example.com:16666"

        [public_tls]
        mode = "frontend-proxy"

        [identity]
        mode = "offline"

        [ingress.edge]
        workspaces = ["main"]
        listen = "0.0.0.0:8443"
        control_listen = "127.0.0.1:16666"

        [workspace.main]

        [agent.desktop]
        workspace = "main"

        [[agent.desktop.services]]
        id = "app"
        address = "127.0.0.1:8080"

        [[route]]
        host = "app.example.com"
        service = "main/desktop/app"
    "#;

    const TWO_INGRESS_MANIFEST: &str = r#"
        [realm]
        id = "promptcn"
        control_endpoint = "example.com:16666"

        [public_tls]
        mode = "frontend-proxy"

        [identity]
        mode = "offline"

        [ingress.backup]
        workspaces = ["main"]
        listen = "0.0.0.0:8444"
        control_listen = "127.0.0.1:16667"

        [ingress.edge]
        workspaces = ["main"]
        listen = "0.0.0.0:8443"
        control_listen = "127.0.0.1:16666"

        [workspace.main]

        [agent.desktop]
        workspace = "main"

        [[agent.desktop.services]]
        id = "app"
        address = "127.0.0.1:8080"

        [[route]]
        host = "app.example.com"
        service = "main/desktop/app"
    "#;

    /// Every manifest-derived artifact carries the vintage line built by
    /// the very function the snapshot and stage tests build their
    /// expectations from — the format cannot drift between renderer and
    /// tests. The unit (rendered from a pack by `node install`, no
    /// manifest bytes at hand) carries the build-only line.
    #[test]
    fn rendered_artifacts_carry_the_vintage_line() {
        let manifest = Manifest::parse(FRONTEND_MANIFEST).expect("manifest parses");
        let sha = interflow_util::sha256_hex(FRONTEND_MANIFEST.as_bytes());
        let vintage = vintage_comment(&sha);
        for piece in nginx_fragment_set(&manifest, &sha, None).expect("fragment set renders") {
            assert!(
                piece.body.contains(&vintage),
                "{} must carry the vintage line",
                piece.rel
            );
        }
        assert!(
            install_sh(&manifest, &sha).contains(&vintage),
            "install.sh carries the vintage line"
        );
        assert!(
            registrar_unit(&manifest, DEFAULT_INSTALL_ROOT, &sha).contains(&vintage),
            "the registrar unit carries the vintage line"
        );
        let unit = node_unit(DEFAULT_INSTALL_ROOT, PackKind::Ingress, "edge", false);
        assert!(
            unit.starts_with(&build_vintage_comment()),
            "the node unit leads with the build-only vintage line"
        );
        assert!(!unit.contains(&vintage));
    }

    /// The host-filtered set is the minimal face: the shared three plus
    /// exactly the named ingresses' vhosts — a staged tree never carries
    /// another ingress's vhost, and the shared bytes are identical
    /// filtered or not (one source, no per-host variants).
    #[test]
    fn host_filtered_set_is_the_minimal_face() {
        let manifest = Manifest::parse(TWO_INGRESS_MANIFEST).expect("manifest parses");
        let sha = interflow_util::sha256_hex(TWO_INGRESS_MANIFEST.as_bytes());
        let full = nginx_fragment_set(&manifest, &sha, None).expect("fragment set renders");
        assert_eq!(full.len(), 5, "shared three + both vhosts");
        let edge_only = nginx_fragment_set(&manifest, &sha, Some(&["edge".to_owned()]))
            .expect("fragment set renders");
        let rels: Vec<&str> = edge_only.iter().map(|p| p.rel.as_str()).collect();
        assert_eq!(
            rels,
            vec![
                "nginx/stream/interflow-stream.conf",
                "nginx/http/interflow-shared.conf",
                "nginx/http/interflow-http.conf",
                "nginx/http/interflow-vhost-edge.conf",
            ]
        );
        for piece in &full {
            if let Some(same) = edge_only.iter().find(|p| p.rel == piece.rel) {
                assert_eq!(piece.body, same.body, "{}", piece.rel);
            }
        }
    }
}
