//! Rendered deployment artifacts: systemd units, nginx fragments and the
//! server bootstrap script — all pure functions of the manifest
//!.
//!
//! `plan apply` writes them next to the packs (`--out`); `node install`
//! re-derives the unit on the server from the pack itself. Every unit has
//! exactly one writer: `install.sh` is machine bootstrap only and installs
//! no units — node units belong to `node install` (keyed on the pack
//! landing, which is what binds a node to a machine), the registrar unit
//! to the operator bootstrap its header records. All share the
//! install-layout convention:
//!
//! - binaries  `/usr/local/bin/{interflow,interflow-mesh,interflow-registrar}`
//! - packs     `<root>/packs/<kind>-<node>` (`root` defaults to /srv/interflow)
//! - registrar `<root>/registrar/{issuer,tls}` (registrar deployments only)
//!
//! Units are compile products of the manifest — users never hand-write them.
//! nginx is never taken over either: only self-contained fragments are
//! rendered, and hooking them into the user's nginx stays an explicit
//! one-line include per context.

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
    match (kind, mesh_role) {
        (PackKind::Hub, _) => format!("interflow-mesh hub --pack {pack}"),
        (PackKind::Agent, true) => format!("interflow-mesh agent --pack {pack}"),
        (PackKind::Agent, false) | (PackKind::Ingress, _) => {
            format!("interflow {} run --pack {pack}", kind.as_str())
        }
    }
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
        "[Unit]\nDescription=Interflow {kind_arg} node {node}\nAfter=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\nType=notify\nTimeoutStartSec=30s\n\
         ExecStart=/usr/local/bin/{exec_start}\nRestart=always\nRestartSec=5\n\
         User={INSTALL_USER}\nGroup={INSTALL_USER}\nNoNewPrivileges=true\n\
         ProtectSystem=strict\nReadWritePaths={pack}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
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
pub fn registrar_unit(manifest: &Manifest, root: &str) -> String {
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
        "# One-time bootstrap (operator, on the registrar server):\n\
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
    )
}

/// Hostname of an endpoint (`host:port`, `https://host`, or bare `host`).
fn endpoint_host(endpoint: &str) -> &str {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    rest.split_once(':').map_or(rest, |(host, _)| host)
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
pub fn nginx_stream_fragment(manifest: &Manifest) -> String {
    let mut entries = Vec::new();
    if !manifest.realm.control_endpoint.is_empty()
        && let Some((_, ingress)) = manifest.ingress.iter().next()
    {
        entries.push((
            endpoint_host(&manifest.realm.control_endpoint).to_owned(),
            loopback_target(&ingress.control_listen),
            "control endpoint (mTLS passthrough)",
        ));
    }
    if has_registrar(manifest) {
        entries.push((
            endpoint_host(&manifest.registrar.endpoint).to_owned(),
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
    format!(
        "# Generated by interflow plan apply — single public port: 443 SNI dispatch.\n\
         #\n\
         # Add once at the TOP LEVEL of nginx.conf (outside http {{}}):\n\
         #   stream {{ include /etc/nginx/interflow/stream/*.conf; }}\n\
         #\n\
         # Business TLS terminates on the internal listener; the entries below\n\
         # pass through untouched, so their mTLS stays end-to-end. Point\n\
         # [realm].control_endpoint at `<host>:443` and [registrar].endpoint at\n\
         # `https://<host>`, then close 16666/18666 in the firewall — the public\n\
         # surface is just 443.\n\
         map $ssl_preread_server_name $interflow_backend {{\n\
         \x20   hostnames;\n\
         \x20   default                 {NGINX_INTERNAL_HTTPS_LISTEN};   # business → internal TLS termination\n\
         {map}}}\n\
         \nserver {{\n\
         \x20   listen 443;\n\
         \x20   ssl_preread on;\n\
         \x20   proxy_pass $interflow_backend;\n\
         \x20   proxy_connect_timeout 5s;\n\
         }}\n",
    )
}

/// `nginx/http/interflow-shared.conf` — frontend-proxy primitives shared by
/// the vhost fragments (rate limiting + WebSocket upgrade mapping).
pub fn nginx_shared_fragment() -> String {
    "# Generated by interflow plan apply — shared frontend-proxy primitives.\n\
     # Include from the http context together with the vhost fragments:\n\
     #   include /etc/nginx/interflow/http/*.conf;\n\
     \n\
     # Rate limiting: 10 requests/s per client IP, burst 20.\n\
     limit_req_zone $binary_remote_addr zone=interflow_req:10m rate=10r/s;\n\
     # Concurrency: at most 20 connections per client IP.\n\
     limit_conn_zone $binary_remote_addr zone=interflow_conn:10m;\n\
     \n\
     # WebSocket upgrade mapping.\n\
     map $http_upgrade $connection_upgrade {\n\
     \x20   default upgrade;\n\
     \x20   ''      close;\n\
     }\n"
    .to_owned()
}

/// `nginx/http/interflow-http.conf` — port 80: ACME challenges + redirect.
pub fn nginx_http_fragment(routes: &[RouteConfig]) -> String {
    let hosts: Vec<&str> = routes.iter().map(|r| r.host.as_str()).collect();
    format!(
        "# Generated by interflow plan apply — port 80: ACME challenges + redirect.\n\
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
    )
}

/// `nginx/http/interflow-vhost-<ingress>.conf` — the business vhosts for one
/// ingress: TLS termination on the internal listener, XFF restoration,
/// unbuffered streaming and WebSocket upgrade.
pub fn nginx_vhost_fragment(node: &str, cfg: &IngressConfig, routes: &[RouteConfig]) -> String {
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
             \x20   listen {NGINX_INTERNAL_HTTPS_LISTEN} ssl http2;\n\
             \x20   server_name {host};\n\
             \n\
             \x20   # Fill in your public certificate (e.g. certbot's\n\
             \x20   # /etc/letsencrypt/live/<domain>/fullchain.pem).\n\
             \x20   ssl_certificate     /etc/nginx/certs/{host}.crt;\n\
             \x20   ssl_certificate_key /etc/nginx/certs/{host}.key;\n\
             \x20   ssl_protocols TLSv1.3;\n\
             \n\
             \x20   location / {{\n\
             \x20       limit_req zone=interflow_req burst=20 nodelay;\n\
             \x20       limit_conn interflow_conn 20;\n\
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
             }}\n\n",
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        "# Generated by interflow plan apply — frontend-proxy vhosts for ingress {node}.\n\
         # The public 443 arrives via nginx/stream/interflow-stream.conf SNI dispatch;\n\
         # TLS terminates here on the internal listener. The ingress enables\n\
         # X-Forwarded-For restoration automatically in this topology.\n\n{servers}"
    )
}

/// `install.sh` — idempotent machine bootstrap.
///
/// System user, directories and optional `bin/` payloads — nothing else.
/// It installs no units and calls no systemctl: node units are written and
/// enabled by `node install --pack` (the pack landing is what binds a node
/// to a machine), and the registrar unit follows its own header's bootstrap
/// sequence. nginx and the registrar's issuer material are likewise out of
/// scope: fragments are hooked in by the operator, secret material by hand.
pub fn install_sh(manifest: &Manifest) -> String {
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
        "#!/usr/bin/env bash\n\
         # Generated by interflow plan apply — bootstrap a server for interflow nodes.\n\
         # Machine-scope only: user, dirs, optional bin/ — no units are installed\n\
         # here and no service is touched; re-running never duplicates the user.\n\
         # Run as root from the dist root: sudo bash install.sh\n\
         set -euo pipefail\n\
         \n\
         if [[ $EUID -ne 0 ]]; then\n\
         \x20 echo \"install.sh must run as root (sudo bash install.sh)\" >&2\n\
         \x20 exit 1\n\
         fi\n\
         \n\
         INTERFLOW_USER={INSTALL_USER}\n\
         INTERFLOW_GROUP={INSTALL_USER}\n\
         SRV_ROOT={DEFAULT_INSTALL_ROOT}\n\
         \n\
         if ! getent group \"$INTERFLOW_GROUP\" >/dev/null; then\n\
         \x20 groupadd --system \"$INTERFLOW_GROUP\"\n\
         fi\n\
         if ! id \"$INTERFLOW_USER\" >/dev/null 2>&1; then\n\
         \x20 useradd --system --gid \"$INTERFLOW_GROUP\" --home-dir \"$SRV_ROOT\" \\\n\
         \x20   --shell /usr/sbin/nologin \"$INTERFLOW_USER\"\n\
         \x20 echo \"created system user $INTERFLOW_USER\"\n\
         fi\n\
         \n\
         install -d -o \"$INTERFLOW_USER\" -g \"$INTERFLOW_GROUP\" -m 0750 \\\n\
         \x20 \"$SRV_ROOT\" \"$SRV_ROOT/packs\"\n{registrar_dirs}\
         \n\
         # Optional: ship binaries in bin/ next to this script and they get installed.\n\
         if [[ -d bin ]]; then\n\
         \x20 install -m 0755 bin/* /usr/local/bin/\n\
         fi\n\
         \n\
         # Units are not installed here. Node units are written and enabled by\n\
         # `interflow node install --pack packs/<kind>-<node>` — the pack is the\n\
         # node's only entry point: a machine gets a unit exactly when that\n\
         # node's pack lands on it.\n{registrar_hint}\
         echo \"machine prepared — per node: interflow node install --pack packs/<kind>-<node>\"\n",
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
) -> interflow_core::error::Result<()> {
    let path = out_root.join("systemd").join("interflow-registrar.service");
    write_fragment(&path, &registrar_unit(manifest, root))
}

/// Writes the `nginx/` fragment set for frontend-proxy deployments.
pub fn write_nginx_fragments(
    out_root: &Path,
    manifest: &Manifest,
) -> interflow_core::error::Result<()> {
    if manifest.public_tls.mode != PublicTlsMode::FrontendProxy {
        return Ok(());
    }
    write_fragment(
        &out_root.join("nginx/stream/interflow-stream.conf"),
        &nginx_stream_fragment(manifest),
    )?;
    write_fragment(
        &out_root.join("nginx/http/interflow-shared.conf"),
        &nginx_shared_fragment(),
    )?;
    write_fragment(
        &out_root.join("nginx/http/interflow-http.conf"),
        &nginx_http_fragment(&manifest.route),
    )?;
    for (node, cfg) in &manifest.ingress {
        write_fragment(
            &out_root
                .join("nginx/http")
                .join(format!("interflow-vhost-{node}.conf")),
            &nginx_vhost_fragment(node, cfg, &manifest.route),
        )?;
    }
    Ok(())
}

/// Writes `install.sh` at the dist root.
pub fn write_install_sh(out_root: &Path, manifest: &Manifest) -> interflow_core::error::Result<()> {
    write_fragment(&out_root.join("install.sh"), &install_sh(manifest))?;
    Ok(())
}
