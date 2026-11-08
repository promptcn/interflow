//! `interflow-cli doctor link` — the three-layer link diagnostic
//!
//! The deployment handbook's §8 troubleshooting order — authentication
//! layer (DNS/TCP-UDP split stack/mTLS/clock), authorization layer
//! (policy watermarks, CRL), data plane (one real request) — used to live
//! only in the operator's head. This module is its executor: every check
//! carries its reading ("what this result means / what to probe next"),
//! worded from the handbook's accumulated judgments (timeout ≠ reset, the
//! all-QUIC ping=0 formation, the fake-ip signature, the UDP
//! security-group gap, watermark inversion as the lineage-deadlock
//! shape). The doctor only reads: no state is ever changed.
//!
//! Three faces:
//! - `--to <host:port>` — the agent-side three-layer probe from THIS
//!   machine (run it on the leg that cannot connect);
//! - `--hub` — the hub-side fleet reading (per-leg rows, same-build
//!   check, lineage, inversions) off the `GET /snapshot` face;
//! - `--upgrade-check` — the upgrade acceptance: snapshot before/after,
//!   the 0s/+60s/+180s probe triple across the 30-40s death window, and
//!   the verdicts (same string + zero dirty, steady evictions, online
//!   stability, generation continuity).
//!
//! Every network interaction sits behind the [`LinkProbe`] trait — fault
//! injection is a test double, not a deployed VM.

use crate::status;
use clap::Args;
use interflow_cli::outln;
use interflow_mesh::hub::snapshot::{FleetSnapshotDoc, ServingSource};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct LinkArgs {
    /// Agent-side three-layer probe: dial `host:port` (the hub endpoint)
    /// through DNS → TCP/UDP → mTLS → watermarks → one data-plane request.
    #[arg(long, conflicts_with_all = ["hub", "upgrade_check"])]
    pub to: Option<String>,
    /// Hub-side fleet reading: per-leg rows, same-build check, serving
    /// lineage, watermark inversions.
    #[arg(long, conflicts_with_all = ["to", "upgrade_check"])]
    pub hub: bool,
    /// The upgrade acceptance: snapshot → probe triple (0s/+60s/+180s)
    /// → snapshot → verdicts.
    #[arg(long, conflicts_with_all = ["to", "hub"])]
    pub upgrade_check: bool,
    /// Credential pack of THIS leg (agent side): enables the mTLS
    /// handshake probe and the CRL membership check.
    #[arg(long)]
    pub pack: Option<PathBuf>,
    /// Manifest describing the deployment (names the hub endpoint for the
    /// hub-side and watermark layers).
    #[arg(long, default_value = "interflow.toml")]
    pub manifest: PathBuf,
    /// Issuer store directory (operator machine only).
    #[arg(long, default_value = "issuer")]
    pub issuer: PathBuf,
    /// One real data-plane request (e.g. `http://127.0.0.1:11434/api/version`)
    /// — green cards and listening sockets prove nothing.
    #[arg(long)]
    pub probe_url: Option<String>,
    /// Baseline snapshot captured BEFORE the upgrade (`status snapshot
    /// --out …`): adds the before→after continuity reading.
    #[arg(long, requires = "upgrade_check")]
    pub baseline: Option<PathBuf>,
    /// Directory to persist the two snapshots `--upgrade-check` captures
    /// (upgrade-before.json / upgrade-after.json — the upgrade log's
    /// machine-readable attachment).
    #[arg(long, requires = "upgrade_check")]
    pub snapshot_out: Option<PathBuf>,
}

impl LinkArgs {
    pub fn run(self) -> interflow_core::error::Result<()> {
        match (self.to.as_deref(), self.hub, self.upgrade_check) {
            (Some(target), false, false) => run_to(target, &self),
            (None, true, false) => run_hub_side(&self),
            (None, false, true) => run_upgrade_check(&self),
            _ => Err(interflow_core::error::InterflowError::config(
                "doctor link needs exactly one of --to <host:port> / --hub / --upgrade-check",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Probe plumbing: verdicts + the injectable trait
// ---------------------------------------------------------------------------

/// The resolver reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsVerdict {
    Resolved(Vec<IpAddr>),
    Failed(String),
}

/// One TCP dial reading. The distinction is the handbook's core judgment:
/// a REFUSAL proves the path works and the far end answered no; a TIMEOUT
/// proves nothing got through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpVerdict {
    Open,
    Refused,
    Unreachable,
}

/// One UDP dial reading, via a QUIC version-negotiation trigger (an
/// unknown-version long header the server MUST answer with Version
/// Negotiation — silence on a TCP-open port is the security-group gap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpVerdict {
    /// A version-negotiation (or any) answer came back.
    Answered,
    /// Nothing came back within the window — the classic dropped-UDP
    /// shape (TCP rules do not cover UDP).
    Silent,
    /// ICMP port unreachable surfaced on the connected socket.
    Refused,
    /// Local socket failure (bind/permission).
    Error(String),
}

/// One mTLS handshake reading (client material from the local pack).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsVerdict {
    /// Handshake complete; the peer leaf's validity window as unix
    /// seconds (the clock-skew judgment's input).
    HandshakeOk {
        not_before: i64,
        not_after: i64,
    },
    Failed(String),
}

/// One HTTP data-plane probe reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpVerdict {
    Answered(String),
    Refused,
    Timeout,
    Error(String),
}

/// Every network interaction of the agent-side probe behind one trait:
/// the system implementation for production, doubles for fault injection.
pub trait LinkProbe {
    fn resolve(&self, host: &str) -> DnsVerdict;
    fn tcp(&self, addr: SocketAddr) -> TcpVerdict;
    fn udp(&self, addr: SocketAddr) -> UdpVerdict;
    fn mtls(&self, addr: SocketAddr, host: &str, pack: Option<&Path>) -> TlsVerdict;
}

/// The production probe: the real resolver, real sockets, real rustls.
pub struct SystemProbe {
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
}

impl Default for SystemProbe {
    fn default() -> Self {
        Self {
            tcp_timeout: Duration::from_secs(5),
            udp_timeout: Duration::from_secs(2),
        }
    }
}

impl LinkProbe for SystemProbe {
    fn resolve(&self, host: &str) -> DnsVerdict {
        use std::net::ToSocketAddrs;
        match (host, 0u16).to_socket_addrs() {
            Ok(iter) => {
                let addrs: Vec<IpAddr> = iter.map(|a| a.ip()).collect();
                if addrs.is_empty() {
                    DnsVerdict::Failed("resolved to nothing".to_owned())
                } else {
                    DnsVerdict::Resolved(addrs)
                }
            }
            Err(e) => DnsVerdict::Failed(e.to_string()),
        }
    }

    fn tcp(&self, addr: SocketAddr) -> TcpVerdict {
        match std::net::TcpStream::connect_timeout(&addr, self.tcp_timeout) {
            Ok(_) => TcpVerdict::Open,
            // ConnectionRefused is the one distinguishable answer; every
            // other failure shape (timeout, unreachable, odd errno) is the
            // path-broken reading.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => TcpVerdict::Refused,
            Err(_) => TcpVerdict::Unreachable,
        }
    }

    fn udp(&self, addr: SocketAddr) -> UdpVerdict {
        let socket = match std::net::UdpSocket::bind(if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }) {
            Ok(s) => s,
            Err(e) => return UdpVerdict::Error(e.to_string()),
        };
        if let Err(e) = socket.connect(addr) {
            return UdpVerdict::Error(e.to_string());
        }
        // Any nonzero DCID works for the probe; the CSPRNG token is right
        // here (and zero is not a valid DCID anyway).
        let dcid = interflow_core::protocol::CircuitToken::random().map_or_else(
            |_| [0x5a; 16],
            interflow_core::protocol::CircuitToken::to_bytes,
        );
        let packet = version_negotiation_trigger(&dcid[..8]);
        if let Err(e) = socket.send(&packet) {
            return UdpVerdict::Error(e.to_string());
        }
        let _ = socket.set_read_timeout(Some(self.udp_timeout));
        let mut buf = [0u8; 128];
        match socket.recv(&mut buf) {
            Ok(n) if looks_like_version_negotiation(&buf[..n]) => UdpVerdict::Answered,
            // Any answer at all still proves the datagram path (some
            // middleboxes mangle VN packets); silence stays the signal.
            Ok(_) => UdpVerdict::Answered,
            // ConnectionRefused on a connected UDP socket is the ICMP
            // port-unreachable surface; everything else reads as silence.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => UdpVerdict::Refused,
            Err(_) => UdpVerdict::Silent,
        }
    }

    fn mtls(&self, addr: SocketAddr, host: &str, pack: Option<&Path>) -> TlsVerdict {
        let Some(pack_dir) = pack else {
            return TlsVerdict::Failed("no --pack given".to_owned());
        };
        let pack = match interflow_identity::pack::CredentialPack::load_runtime(pack_dir) {
            Ok(p) => p,
            Err(e) => {
                return TlsVerdict::Failed(format!(
                    "local pack failed validation: {e} — diagnose with `interflow-cli doctor \
                     ingress|agent|hub --pack {}`",
                    pack_dir.display()
                ));
            }
        };
        let active =
            match interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack) {
                Ok(a) => a,
                Err(e) => return TlsVerdict::Failed(format!("active credential load: {e}")),
            };
        let Some(entry) = active.entries.values().next() else {
            return TlsVerdict::Failed("the pack carries no active credential".to_owned());
        };
        // The verifying anchors: every issuer PEM the pack's trust bundle
        // carries (whichever chain the hub presents, its root is in here).
        let ca_pem = pack
            .trust
            .issuers
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let temp = {
            let dir =
                std::env::temp_dir().join(format!("interflow-doctor-link-{}", std::process::id()));
            if let Err(e) = std::fs::create_dir_all(&dir) {
                return TlsVerdict::Failed(e.to_string());
            }
            dir
        };
        let cleanup = |d: &Path| {
            let _ = std::fs::remove_dir_all(d);
        };
        let (ca, crt, key) = (
            temp.join("ca.pem"),
            temp.join("client.crt"),
            temp.join("client.key"),
        );
        if let Err(e) = std::fs::write(&ca, &ca_pem)
            .and_then(|()| std::fs::write(&crt, &entry.cert_pem))
            .and_then(|()| std::fs::write(&key, &entry.key_pem))
        {
            cleanup(&temp);
            return TlsVerdict::Failed(e.to_string());
        }
        let verdict = (|| -> TlsVerdict {
            let config = match interflow_core::tls::client::build_client_config(
                None,
                Some(&ca.display().to_string()),
                Some(&crt.display().to_string()),
                Some(&key.display().to_string()),
                &["h2"],
            ) {
                Ok(c) => c,
                Err(e) => return TlsVerdict::Failed(format!("client config: {e}")),
            };
            let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_owned()) else {
                return TlsVerdict::Failed(format!("invalid server name {host:?}"));
            };
            let Ok(mut conn) = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
            else {
                return TlsVerdict::Failed("client setup".to_owned());
            };
            let Ok(mut sock) = std::net::TcpStream::connect_timeout(&addr, self.tcp_timeout) else {
                return TlsVerdict::Failed("TCP failed before TLS".to_owned());
            };
            let _ = sock.set_read_timeout(Some(self.tcp_timeout));
            let _ = sock.set_write_timeout(Some(self.tcp_timeout));
            // Drive the handshake to completion synchronously.
            while conn.is_handshaking() {
                if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
                    return TlsVerdict::Failed("handshake write failed".to_owned());
                }
                if conn.wants_read() && conn.read_tls(&mut sock).is_err() {
                    return TlsVerdict::Failed(
                        "handshake read failed — the peer closed on us or timed out".to_owned(),
                    );
                }
                if let Err(e) = conn.process_new_packets() {
                    return TlsVerdict::Failed(format!("TLS alert: {e}"));
                }
            }
            // Flush the final flight (TLS 1.3: the client's Finished
            // carries its certificate — without this the server never sees
            // the credentials and every dial would vacuously "succeed").
            if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
                return TlsVerdict::Failed("final flight write failed".to_owned());
            }
            // TLS 1.3 verdict: the server judges the client certificate
            // only after the client's half of the handshake completes —
            // the rejection arrives as a post-handshake alert or an
            // immediate close. An idle open connection is the pass; a
            // revoked credential reads HERE as an authentication failure.
            let mut verdict = [0u8; 256];
            match std::io::Read::read(&mut sock, &mut verdict) {
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    return TlsVerdict::Failed(format!("post-handshake read failed: {e}"));
                }
                Ok(0) => {
                    return TlsVerdict::Failed(
                        "the peer closed the connection right after the handshake — a revoked \
                         credential is the prime suspect (the CRL check below)"
                            .to_owned(),
                    );
                }
                Ok(n) => {
                    let processed = (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
                        conn.read_tls(&mut &verdict[..n])?;
                        conn.process_new_packets()?;
                        Ok(())
                    })();
                    if let Err(e) = processed {
                        return TlsVerdict::Failed(format!("TLS alert: {e}"));
                    }
                }
            }
            let Some(chain) = conn.peer_certificates() else {
                return TlsVerdict::Failed(
                    "handshake completed without a peer certificate".to_owned(),
                );
            };
            match interflow_core::tls::extract_leaf_validity_from_chain(chain) {
                Some((not_before, not_after)) => TlsVerdict::HandshakeOk {
                    not_before,
                    not_after,
                },
                None => TlsVerdict::Failed("peer certificate did not parse".to_owned()),
            }
        })();
        cleanup(&temp);
        verdict
    }
}

// ---------------------------------------------------------------------------
// QUIC version-negotiation trigger (RFC 9000 §6/§17.2.1)
// ---------------------------------------------------------------------------

/// A long-header packet with an unknown version: the server MUST answer
/// with a Version Negotiation packet — but only if the datagram is at
/// least the QUIC minimum datagram size (RFC 9000 §5.2.2 lets servers
/// drop smaller unsupported-version packets, and quinn-proto 0.11.18+
/// does, so an unpadded probe reads silence instead of a dead path).
/// DCID carried for the response's correlation (any nonzero value works
/// for the probe); everything past the header is padding the server never
/// reads before answering VN.
pub fn version_negotiation_trigger(dcid: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1200);
    packet.extend_from_slice(&[0xc0]); // long header, type bits zeroed
    packet.extend_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]); // unknown version
    packet.push(u8::try_from(dcid.len()).unwrap_or(8)); // DCID length
    packet.extend_from_slice(dcid);
    packet.push(0); // empty SCID
    packet.resize(1200, 0);
    packet
}

/// Version Negotiation packets carry version 0x00000000 in the version
/// field (bytes 1..5 of a long-header packet).
pub const fn looks_like_version_negotiation(packet: &[u8]) -> bool {
    packet.len() >= 5
        && packet[0] & 0x80 != 0
        && packet[1] == 0
        && packet[2] == 0
        && packet[3] == 0
        && packet[4] == 0
}

/// The ClashX/fake-ip benchmark range (198.18.0.0/15) — a resolver answer
/// inside it means DNS went through the local proxy stack, not the network.
pub const fn is_fake_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 198 && (o[1] == 18 || o[1] == 19)
        }
        IpAddr::V6(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Agent-side three-layer probe (`--to`)
// ---------------------------------------------------------------------------

/// The diagnostic layers, in handbook §8 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    Dns,
    Tcp,
    Udp,
    Tls,
    Watermark,
    Crl,
    DataPlane,
}

impl LinkLayer {
    /// The operator-facing name (the "which layer is broken" answer).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dns | Self::Tcp | Self::Udp | Self::Tls => "authentication",
            Self::Watermark | Self::Crl => "authorization",
            Self::DataPlane => "data plane",
        }
    }
}

/// One layer's outcome: `ok=false` marks the break; `skipped` marks a
/// layer that had no input (a `·`, never a fake green).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerResult {
    pub layer: LinkLayer,
    pub ok: bool,
    pub skipped: bool,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkReport {
    pub results: Vec<LayerResult>,
}

impl LinkReport {
    pub fn first_broken(&self) -> Option<&LayerResult> {
        self.results.iter().find(|r| !r.ok && !r.skipped)
    }
}

/// The probe's inputs, split so tests inject everything: the network
/// behind [`LinkProbe`], the hub picture and clock as plain values.
pub struct ToProbe<'a> {
    pub target: &'a str,
    pub pack: Option<&'a Path>,
    /// Pre-fetched hub snapshot for the watermark layer (`None` = skip).
    pub hub_snapshot: Option<&'a FleetSnapshotDoc>,
    /// Probe URL for the data-plane layer (`None` = skip).
    pub probe_url: Option<&'a str>,
    /// Now, in unix seconds (the clock-skew judgment's reference).
    pub now_unix: i64,
    /// The hosts-file text for the pinning note (`None` = do not read).
    pub hosts_file: Option<&'a str>,
    /// The operator's issuer-side CRL material (label → PEM), pre-read by
    /// the command face — the AUTHORITATIVE membership source. `None` = no
    /// issuer CRLs in hand; the CRL layer then falls back to the pack's
    /// carried snapshot and says so honestly instead of vouching for it
    /// (a carried snapshot predates any later revocation by construction:
    /// (internal design notes)).
    pub issuer_crls: Option<&'a [(String, String)]>,
}

/// Runs the three-layer probe and returns the structured report. Pure
/// with respect to everything injected — printing is the caller's.
pub fn probe_to(probe: &dyn LinkProbe, input: &ToProbe<'_>) -> LinkReport {
    let mut results = Vec::new();
    let mut push = |layer, ok, skipped, line: String| {
        results.push(LayerResult {
            layer,
            ok,
            skipped,
            line,
        });
    };

    // --- Layer 1: authentication -------------------------------------
    let Some((host, port)) = split_host_port(input.target) else {
        push(
            LinkLayer::Dns,
            false,
            false,
            format!(
                "target {:?} is not `host:port` — nothing to dial",
                input.target
            ),
        );
        return LinkReport { results };
    };

    let addrs = match probe.resolve(host) {
        DnsVerdict::Resolved(addrs) => {
            if let Some(fake) = addrs.iter().find(|a| is_fake_ip(a)) {
                push(
                    LinkLayer::Dns,
                    false,
                    false,
                    format!(
                        "{host} resolves into the fake-ip range ({fake} in 198.18.0.0/15) — \
                         DNS is going through the local proxy stack (ClashX TUN). The \
                         handbook signature is agent logs dialing 198.18.x.x. Fix: pin the \
                         hub host in /etc/hosts — and remember the contract: after an EIP \
                         change the hosts lines must be updated or QUIC silently dials the \
                         OLD address"
                    ),
                );
                return LinkReport { results };
            }
            let pins = input
                .hosts_file
                .is_some_and(|text| hosts_pins_host(text, host));
            let pin_note = if pins {
                "  (pinned in /etc/hosts — after an EIP change, update the hosts lines)"
            } else {
                ""
            };
            push(
                LinkLayer::Dns,
                true,
                false,
                format!("{host} → {}{pin_note}", join_ips(&addrs)),
            );
            addrs
        }
        DnsVerdict::Failed(reason) => {
            push(
                LinkLayer::Dns,
                false,
                false,
                format!(
                    "{host} does not resolve ({reason}). Split the question: `dig +short \
                     {host}` (the system resolver) vs `dig +short {host} @223.5.5.5` (a \
                     public resolver) — both failing = DNS itself; only the system resolver \
                     failing = the local proxy stack's DNS is wedged (the ClashX core-DNS \
                     failure mode)"
                ),
            );
            return LinkReport { results };
        }
    };

    let addr = SocketAddr::new(addrs[0], port);
    match probe.tcp(addr) {
        TcpVerdict::Open => push(LinkLayer::Tcp, true, false, format!("TCP {addr} open")),
        TcpVerdict::Refused => {
            push(
                LinkLayer::Tcp,
                false,
                false,
                format!(
                    "TCP {addr} refused — the path WORKS, the far end said no: the service is \
                 stopped or the port is wrong. timeout ≠ reset: a reset/refusal is an \
                 answer, start at the far-end service before suspecting the mesh",
                ),
            );
            return LinkReport { results };
        }
        TcpVerdict::Unreachable => {
            push(
                LinkLayer::Tcp,
                false,
                false,
                format!(
                    "TCP {addr} timed out — nothing got through: firewall / security group / \
                 routing. timeout ≠ reset: this is a PATH failure, not a service failure — \
                 check the security group and firewall before the far-end service",
                ),
            );
            return LinkReport { results };
        }
    }

    match probe.udp(addr) {
        UdpVerdict::Answered => push(
            LinkLayer::Udp,
            true,
            false,
            format!("UDP {port} answered (QUIC version negotiation) — the datagram path works"),
        ),
        UdpVerdict::Refused => push(
            LinkLayer::Udp,
            false,
            false,
            format!(
                "UDP {port} answered ICMP port-unreachable — UDP is routed but nothing listens \
             on it; the hub's QUIC listener is down or it is an h2-only deployment",
            ),
        ),
        UdpVerdict::Silent => push(
            LinkLayer::Udp,
            false,
            false,
            format!(
                "UDP {port} is SILENT while TCP is open — either the security-group gap (TCP \
                 rules do not cover UDP; handbook symptom: the agent loops on 15s QUIC \
                 connect/register timeouts — fix: allow {port}/udp in the security group and \
                 firewall), or this deployment runs h2-only (no quic_listen in the manifest), \
                 in which case UDP silence is expected and not a fault",
            ),
        ),
        UdpVerdict::Error(e) => push(LinkLayer::Udp, false, true, format!("UDP probe error: {e}")),
    }

    if input.pack.is_none() {
        push(
            LinkLayer::Tls,
            true,
            true,
            "mTLS handshake not probed — pass --pack <dir> to dial with this leg's credential \
             and read the certificate window (clock skew masquerades as TLS errors)"
                .to_owned(),
        );
    } else {
        match probe.mtls(addr, host, input.pack) {
            TlsVerdict::HandshakeOk {
                not_before,
                not_after,
            } => {
                let skew = not_before.saturating_sub(input.now_unix);
                if skew > 300 {
                    push(
                        LinkLayer::Tls,
                        false,
                        false,
                        format!(
                            "mTLS handshake OK, but the peer certificate is not valid for \
                         another {skew}s — this machine's clock is BEHIND (clock drift \
                         masquerades as certificate errors at the mTLS layer). Fix: sync \
                         the clock (the handshake itself already succeeded here, but the \
                         hub will reject drifted clients)",
                        ),
                    );
                } else {
                    push(
                        LinkLayer::Tls,
                        true,
                        false,
                        format!(
                            "mTLS handshake OK — peer certificate valid [{not_before}, \
                         {not_after}] (unix seconds)",
                        ),
                    );
                }
            }
            TlsVerdict::Failed(reason) => push(
                LinkLayer::Tls,
                false,
                false,
                format!(
                    "mTLS handshake failed: {reason}. Authentication-layer candidates: the two \
                 ends from different builds (compare build strings — \
                 `interflow-cli doctor link --hub` reads every leg's), an untrusted/expired \
                 chain, or a revoked credential (the CRL check below)",
                ),
            ),
        }
    }

    // --- Layer 2: authorization ---------------------------------------
    match input.hub_snapshot {
        None => push(
            LinkLayer::Watermark,
            true,
            true,
            "watermarks not compared — pass --manifest/--issuer (operator machine) to read \
             the hub's serving generation against every leg's pulled watermark"
                .to_owned(),
        ),
        Some(doc) => {
            let serving = doc.hub.serving_generation;
            let inversions: Vec<&str> = doc
                .agents
                .iter()
                .filter_map(|a| match (a.seen_generation, serving) {
                    (Some(seen), Some(serving)) if seen > serving => Some(a.agent.as_str()),
                    _ => None,
                })
                .collect();
            match (inversions.is_empty(), serving) {
                (true, Some(serving)) => push(
                    LinkLayer::Watermark,
                    true,
                    false,
                    format!(
                        "every reported watermark is at or below the serving generation \
                     {serving}",
                    ),
                ),
                (true, None) => push(
                    LinkLayer::Watermark,
                    true,
                    true,
                    "the hub reports no servable bundle — nothing to compare watermarks \
                     against"
                        .to_owned(),
                ),
                (false, _) => push(
                    LinkLayer::Watermark,
                    false,
                    false,
                    format!(
                        "watermark inversion: {} above the hub's serving generation — the \
                     lineage-deadlock shape (a node frozen ABOVE this hub's lineage: every \
                     future policy below its watermark is dead on arrival there). Fix: \
                     re-publish above the highest watermark (the plan-apply gate aligns to \
                     the floor automatically)",
                        inversions
                            .iter()
                            .map(|a| format!("{a} holds a higher generation"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ),
            }
        }
    }

    if let Some(pack_dir) = input.pack {
        match crl_membership_reading(pack_dir, input.issuer_crls) {
            CrlReading::IssuerRevokes(hits) => push(
                LinkLayer::Crl,
                false,
                false,
                format!(
                    "REVOKED: {} — the issuer's current CRL revokes this pack's credential \
                     (this reading is independent of what the hub admits right now). Fix: \
                     rotate the node (`interflow-cli rotate …`) and re-register",
                    hits.join("; "),
                ),
            ),
            CrlReading::IssuerClean => push(
                LinkLayer::Crl,
                true,
                false,
                "no issuer CRL revokes this pack's active serials (checked the issuer's \
                 current CRLs, not the pack's carried snapshot)"
                    .to_owned(),
            ),
            CrlReading::CarriedRevokes(hits) => push(
                LinkLayer::Crl,
                false,
                false,
                format!(
                    "REVOKED: {} — the credential is on a deny list the pack itself \
                     carries. Fix: rotate the node (`interflow-cli rotate …`) and re-register",
                    hits.join("; "),
                ),
            ),
            // The downgraded reading: a carried snapshot is structurally
            // incapable of witnessing its own pack's revocation (the
            // post-revoke CRL only ever lands in the issuer store and
            // freshly rendered packs), so "no hit" is NOT a green — it is
            // "cannot judge from here".
            CrlReading::CarriedClean => push(
                LinkLayer::Crl,
                true,
                true,
                "carried CRL snapshot contains no revocation for this pack's serials — a \
                 snapshot predates any later revocation by construction (a pack cannot \
                 witness its own revoking); pass --issuer <dir> for the authoritative check"
                    .to_owned(),
            ),
            CrlReading::NoMaterial => push(
                LinkLayer::Crl,
                true,
                true,
                "no CRL material carried by this pack (online-tier renewal deployments \
                 verify at the hub's handshake)"
                    .to_owned(),
            ),
            CrlReading::Unverifiable(detail) => push(
                LinkLayer::Crl,
                true,
                true,
                format!(
                    "CRL material present but unreadable: {detail} — treated as \
                         unverifiable, never clean"
                ),
            ),
            CrlReading::PackUnreadable(e) => {
                push(LinkLayer::Crl, true, true, format!("CRL read failed: {e}"));
            }
        }
    } else {
        push(
            LinkLayer::Crl,
            true,
            true,
            "CRL membership not checked — pass --pack <dir> to compare this leg's active \
             serials against the CRL material it carries"
                .to_owned(),
        );
    }

    // --- Layer 3: data plane -------------------------------------------
    match input.probe_url {
        None => push(
            LinkLayer::DataPlane,
            true,
            true,
            "data plane not probed — green cards and listening sockets prove NOTHING \
             (the 455991a case: card green, listener present, tunnel dead). Pass \
             --probe-url http://… for one real request"
                .to_owned(),
        ),
        Some(url) => match http_get(url) {
            HttpVerdict::Answered(status) => push(
                LinkLayer::DataPlane,
                true,
                false,
                format!("probe {url} answered: {status} — a real byte crossed the tunnel"),
            ),
            HttpVerdict::Refused => push(
                LinkLayer::DataPlane,
                false,
                false,
                format!(
                    "probe {url} refused — the target service refused the connection (the \
                 tunnel carried the attempt: look at the far-end service)",
                ),
            ),
            HttpVerdict::Timeout => push(
                LinkLayer::DataPlane,
                false,
                false,
                format!(
                    "probe {url} timed out — the request entered but nothing answered: \
                 protocol mismatch or a half-alive service. timeout ≠ reset: check the \
                 far-end service BEFORE the mesh",
                ),
            ),
            HttpVerdict::Error(e) => {
                push(
                    LinkLayer::DataPlane,
                    false,
                    false,
                    format!("probe {url} failed: {e}"),
                );
            }
        },
    }

    LinkReport { results }
}

/// Reads `/etc/hosts` for the hub host (the ClashX-hardening pinning
/// discipline). `None` on platforms/paths without the file.
fn hosts_file_text() -> Option<String> {
    std::fs::read_to_string("/etc/hosts").ok()
}

fn hosts_pins_host(hosts: &str, host: &str) -> bool {
    hosts
        .lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains(host))
}

fn join_ips(addrs: &[IpAddr]) -> String {
    addrs
        .iter()
        .map(std::net::IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    let port = port.parse().ok()?;
    // Bracketed IPv6 literals keep their brackets out of the name.
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    Some((host, port))
}

/// What the CRL membership layer concluded, and from WHICH source — the
/// reading's evidential weight depends on it (the issuer's current CRL is
/// authoritative; the pack's carried snapshot can never acquit its own
/// pack).
#[derive(Debug)]
enum CrlReading {
    /// The issuer's current CRL revokes an active serial (✘, decisive).
    IssuerRevokes(Vec<String>),
    /// The issuer's current CRLs parse and revoke nothing (✔, a true
    /// green — the source is authoritative).
    IssuerClean,
    /// The pack's own carried snapshot revokes an active serial (✘ — even
    /// a stale source proving revocation is decisive).
    CarriedRevokes(Vec<String>),
    /// The carried snapshot parsed clean (· — structurally incapable of
    /// acquitting this pack, so never a ✔).
    CarriedClean,
    /// No CRL material anywhere (·, the tier's honest skip note).
    NoMaterial,
    /// Material was present but unparseable (·, "cannot judge" — never
    /// "clean").
    Unverifiable(String),
    /// The pack itself did not load (·, pre-existing skip note).
    PackUnreadable(interflow_core::error::InterflowError),
}

/// Serials checked against CRL material `crls` (label → PEM): the hit
/// lines and the labels that failed to parse. A parse failure is surfaced,
/// never silently absorbed — the caller degrades the reading to
/// "unverifiable" instead of "clean" (the `crl_revokes_serial` "cannot
/// judge ≠ clean" contract).
fn scan_crls(serials: &[String], crls: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    let mut hits = Vec::new();
    let mut unparseable = Vec::new();
    for (label, pem) in crls {
        for serial in serials {
            match interflow_identity::revocation::crl_revokes_serial(pem, serial) {
                Ok(Some(true)) => hits.push(format!("serial {serial} revoked by {label}")),
                Ok(_) => {}
                Err(e) => {
                    unparseable.push(format!("{label}: {e}"));
                    break;
                }
            }
        }
    }
    (hits, unparseable)
}

/// The issuer store's current CRL files (`<issuer>/<stem>.crl.pem`, the
/// naming `revoke` writes) as label → PEM — the authoritative membership
/// source. `None` = the directory holds no CRLs (no issuer in hand).
fn issuer_crl_material(issuer_dir: &Path) -> Option<Vec<(String, String)>> {
    let mut crls = Vec::new();
    let entries = std::fs::read_dir(issuer_dir).ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let path = entry.path();
        if file_name
            .to_str()
            .is_none_or(|name| !name.ends_with(".crl.pem"))
        {
            continue;
        }
        if let Ok(pem) = std::fs::read_to_string(&path) {
            crls.push((format!("issuer CRL {}", path.display()), pem));
        }
    }
    (!crls.is_empty()).then_some(crls)
}

/// Every CRL the pack carries (the offline tier embeds snapshots under
/// `trust/crls/`; the online tier refreshes `state/crls/`) as label → PEM.
fn carried_crl_material(pack_dir: &Path) -> Vec<(String, String)> {
    let mut crls = Vec::new();
    for dir in ["trust/crls", "state/crls"] {
        let dir = pack_dir.join(dir);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "pem") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                crls.push((path.display().to_string(), text));
            }
        }
    }
    crls
}

/// The CRL membership reading: the pack's active serials checked against
/// the issuer's current CRLs when the operator has them (the authoritative
/// source — `--issuer` on the operator machine), falling back to the
/// pack's carried snapshot with an honestly downgraded reading.
fn crl_membership_reading(pack_dir: &Path, issuer_crls: Option<&[(String, String)]>) -> CrlReading {
    let pack = match interflow_identity::pack::CredentialPack::load_runtime(pack_dir) {
        Ok(pack) => pack,
        Err(e) => {
            return CrlReading::PackUnreadable(interflow_cli::runtime::pack_error(e));
        }
    };
    let active =
        match interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack) {
            Ok(active) => active,
            Err(e) => {
                return CrlReading::PackUnreadable(interflow_cli::runtime::pack_error(e));
            }
        };
    let serials = active.serials();
    if let Some(issuer_crls) = issuer_crls {
        let (hits, unparseable) = scan_crls(&serials, issuer_crls);
        if !unparseable.is_empty() {
            return CrlReading::Unverifiable(unparseable.join("; "));
        }
        if hits.is_empty() {
            CrlReading::IssuerClean
        } else {
            CrlReading::IssuerRevokes(hits)
        }
    } else {
        let crls = carried_crl_material(pack_dir);
        if crls.is_empty() {
            return CrlReading::NoMaterial;
        }
        let (hits, unparseable) = scan_crls(&serials, &crls);
        if !hits.is_empty() {
            return CrlReading::CarriedRevokes(hits);
        }
        if !unparseable.is_empty() {
            return CrlReading::Unverifiable(unparseable.join("; "));
        }
        CrlReading::CarriedClean
    }
}

/// A minimal blocking HTTP/1.1 GET (data-plane probes are to local
/// listeners; anything needing TLS is not this product's probe shape).
fn http_get(url: &str) -> HttpVerdict {
    let Some(rest) = url.strip_prefix("http://") else {
        return HttpVerdict::Error(
            "only http:// probe URLs are supported (probe a local listener through the \
             tunnel)"
                .to_owned(),
        );
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match split_host_port(host_port) {
        Some((h, p)) => (h.to_owned(), p),
        None => (host_port.to_owned(), 80),
    };
    let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() else {
        return HttpVerdict::Error(format!("probe host {host:?} is not an address literal"));
    };
    let Some(mut stream) = crate::probe::connect(addr, crate::probe::THROUGH_TUNNEL) else {
        return HttpVerdict::Refused;
    };
    match crate::probe::get(&mut stream, host_port, &path, 256) {
        crate::probe::ProbeRead::Answered(chunk) => {
            HttpVerdict::Answered(crate::probe::status_line(&chunk))
        }
        crate::probe::ProbeRead::WriteFailed => HttpVerdict::Error("write failed".to_owned()),
        crate::probe::ProbeRead::Closed => {
            HttpVerdict::Error("the stream closed without a response".to_owned())
        }
        crate::probe::ProbeRead::Timeout => HttpVerdict::Timeout,
        crate::probe::ProbeRead::IoFailed(e) => HttpVerdict::Error(e),
    }
}

// ---------------------------------------------------------------------------
// The three command faces
// ---------------------------------------------------------------------------

fn fetch_snapshot(
    manifest: &Path,
    issuer: &Path,
) -> interflow_core::error::Result<Option<(String, FleetSnapshotDoc)>> {
    interflow_cli::plan::with_hub_control_credential(
        manifest,
        issuer,
        |ep, ca, cert, key| async move {
            interflow_mesh::hub::snapshot::query_fleet_snapshot(&ep, &ca, &cert, &key).await
        },
    )
}

fn run_to(target: &str, args: &LinkArgs) -> interflow_core::error::Result<()> {
    outln!("Interflow doctor link — agent-side three-layer probe to {target}");
    outln!();
    let hub_snapshot = match fetch_snapshot(&args.manifest, &args.issuer) {
        Ok(Some((_, doc))) => Some(doc),
        Ok(None) => None,
        Err(e) => {
            outln!("  note: hub snapshot unavailable ({e}) — watermark layer skipped");
            None
        }
    };
    let hosts = hosts_file_text();
    // The issuer-side CRLs: the AUTHORITATIVE membership source for the
    // authorization layer. Presence is decided by the directory's actual
    // content (`--issuer` defaults to "issuer" and so always names a
    // path); no CRL files there = the operator has no issuer in hand and
    // the layer falls back to the pack's carried snapshot.
    let issuer_crls = issuer_crl_material(&args.issuer);
    if issuer_crls.is_none() {
        outln!(
            "  note: no issuer CRLs under {} — the CRL check will read the pack's carried \
             snapshot, which cannot witness its own revocation",
            args.issuer.display()
        );
    }
    let input = ToProbe {
        target,
        pack: args.pack.as_deref(),
        hub_snapshot: hub_snapshot.as_ref(),
        probe_url: args.probe_url.as_deref(),
        now_unix: interflow_identity::expiry::now_unix(),
        hosts_file: hosts.as_deref(),
        issuer_crls: issuer_crls.as_deref(),
    };
    let report = probe_to(&SystemProbe::default(), &input);
    print_report(&report);
    if let Some(broken) = report.first_broken() {
        outln!();
        outln!("Diagnosis:");
        outln!("  {}", broken.line);
        outln!();
        outln!(
            "Fix: see the reading above — the broken layer is the {} layer.",
            broken.layer.name()
        );
        return Err(interflow_core::error::InterflowError::config(format!(
            "link broken at the {} layer",
            broken.layer.name()
        )));
    }
    outln!();
    outln!("All layers healthy (skipped layers carry their how-to-enable note).");
    Ok(())
}

fn print_report(report: &LinkReport) {
    for result in &report.results {
        let glyph = if result.skipped {
            "·"
        } else if result.ok {
            "✔"
        } else {
            "✘"
        };
        outln!("{glyph} [{}] {}", result.layer.name(), result.line);
    }
}

fn run_hub_side(args: &LinkArgs) -> interflow_core::error::Result<()> {
    outln!("Interflow doctor link — hub-side fleet reading");
    outln!();
    let Some((endpoint, doc)) = fetch_snapshot(&args.manifest, &args.issuer)? else {
        return Err(interflow_core::error::InterflowError::config(format!(
            "manifest {} names no hub endpoint — nothing to read",
            args.manifest.display()
        )));
    };
    let any_fail = render_hub_reading(&endpoint, &doc);
    if any_fail {
        return Err(interflow_core::error::InterflowError::config(
            "fleet reading carries ✘ rows — see the diagnoses above",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// --hub: the policy face's four-state reading
// ---------------------------------------------------------------------------

/// The four-state reading of one leg's policy face — the LEVEL material
/// (watermark + confirmation instant) the hub's watermark table now
/// records on every pull
///. Pure, so the
/// same verdict logic is unit-testable without a live hub.
///
/// `now_unix` is the DOCUMENT's capture instant (hub truth), not the
/// operator's clock: a persisted snapshot judges recency as of its own
/// capture, so a stale document cannot manufacture a silent verdict the
/// hub never observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicySeenReading {
    /// No completed pull since this hub process started — now the ONE
    /// honest meaning of `never` (steady-state pulls land in the face).
    Never,
    /// A watermark whose confirmation instant is older than the silent
    /// threshold — present but fossilized, the previously invisible
    /// failure class (a dead watcher between publishes).
    Silent { seen: u64, age_secs: u64 },
    /// Pulling (recency known or not), but below the serving generation.
    Behind {
        seen: u64,
        serving: u64,
        /// `None` = an older hub reports no confirmation instant — the
        /// value renders, recency does not (never guess a class).
        age_secs: Option<u64>,
    },
    /// At or above the serving generation. `age_secs: None` = recency
    /// unjudgeable (older hub).
    Current { seen: u64, age_secs: Option<u64> },
}

/// Classifies one leg's policy face. The silent threshold is the mesh's
/// single-source constant (3× the policy watch interval — one or two
/// missed ticks are session-rebuild transients; three quiet intervals
/// match no healthy cadence).
fn policy_seen_reading(
    seen: Option<u64>,
    last_pull_unix: Option<u64>,
    serving: Option<u64>,
    now_unix: i64,
) -> PolicySeenReading {
    let Some(seen) = seen else {
        return PolicySeenReading::Never;
    };
    let age_secs = last_pull_unix.map(|last_pull| {
        let age = now_unix - i64::try_from(last_pull).unwrap_or(i64::MAX);
        if age > 0 {
            u64::try_from(age).unwrap_or(u64::MAX)
        } else {
            0
        }
    });
    if let Some(age) = age_secs
        && age > interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS
    {
        return PolicySeenReading::Silent {
            seen,
            age_secs: age,
        };
    }
    match serving {
        Some(serving) if seen < serving => PolicySeenReading::Behind {
            seen,
            serving,
            age_secs,
        },
        _ => PolicySeenReading::Current { seen, age_secs },
    }
}

/// The leg line's `policy_seen=…` fragment (the reading, rendered).
fn policy_seen_line(reading: &PolicySeenReading) -> String {
    match reading {
        PolicySeenReading::Never => "policy_seen=never".to_owned(),
        PolicySeenReading::Current { seen, age_secs } => match age_secs {
            Some(age) => format!("policy_seen={seen} · pulled {age}s ago"),
            None => format!("policy_seen={seen}"),
        },
        PolicySeenReading::Behind {
            seen,
            serving,
            age_secs,
        } => match age_secs {
            Some(age) => format!("policy_seen={seen} (serving {serving}) · pulled {age}s ago"),
            None => format!("policy_seen={seen} (serving {serving})"),
        },
        PolicySeenReading::Silent { seen, age_secs } => {
            format!("policy_seen={seen} · silent {age_secs}s ⚠")
        }
    }
}

/// The CRL-poll liveness reading for one node (or the hub itself) — the
/// 2026-10-19 liveness face's verdict shape. Simpler than the policy
/// reading: the face has no value dimension (no "behind"), only
/// "polling" / "silent" / "never reported".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrlPollReading {
    /// No report ever landed (an older node, or one without a renewal
    /// loop) — unknown, not silent.
    Never,
    /// The confirmation instant froze past the silent threshold — the
    /// poll loop wedged without erroring (the failure class this face
    /// exists to expose; the 1h fail-closed bound never fires because
    /// the loop itself is the thing that checks it).
    Silent { age_secs: u64 },
    /// Polling; the age of the last successful poll (no-change polls
    /// included — "polled, nothing moved").
    Current { age_secs: u64 },
}

/// Classifies one CRL-poll liveness level. `now_unix` is the DOCUMENT's
/// capture instant (same discipline as [`policy_seen_reading`]); the
/// threshold is the renewal crate's single-source constant (3× the 60s
/// poll cadence + sweep slack — one missed poll is an ordinary fetch
/// transient, three quiet cadences match no healthy loop).
fn crl_poll_reading(last_success_unix: Option<u64>, now_unix: i64) -> CrlPollReading {
    let Some(last) = last_success_unix else {
        return CrlPollReading::Never;
    };
    let age = now_unix - i64::try_from(last).unwrap_or(i64::MAX);
    let age_secs = if age > 0 {
        u64::try_from(age).unwrap_or(u64::MAX)
    } else {
        0
    };
    if age_secs > interflow_renewal::CRL_SILENT_AFTER_SECS {
        CrlPollReading::Silent { age_secs }
    } else {
        CrlPollReading::Current { age_secs }
    }
}

/// The rendered `crl_poll=…` fragment.
fn crl_poll_line(reading: &CrlPollReading, failures_total: Option<u64>) -> String {
    let failures = failures_total
        .filter(|total| *total > 0)
        .map_or_else(String::new, |total| format!(" ({total} failed polls)"));
    match reading {
        CrlPollReading::Never => "crl_poll=unknown".to_owned(),
        CrlPollReading::Current { age_secs } => {
            format!("crl_poll=ok · {age_secs}s ago{failures}")
        }
        CrlPollReading::Silent { age_secs } => {
            format!("crl_poll SILENT {age_secs}s ⚠{failures}")
        }
    }
}

/// The mailbox watermark's reading for one leg
/// — the CLI
/// `stream pause` "queued, applies on next check-in" message's dual: the
/// CONTINUOUS state of that queue, not just the instant it was queued.
///
/// Offline + waiting is expected (the op rides the next check-in);
/// ONLINE + waiting past the delivery budget is the intent watcher not
/// consuming — a working loop delivers within one watch interval.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueuedOpsReading {
    /// No ops waiting, nothing ever dropped (or an older hub without the
    /// field).
    Clear,
    /// Ops waiting on a leg.
    Waiting {
        count: u32,
        oldest_age_secs: u64,
        oldest_op: Option<String>,
        /// True = the leg is online and the ops outlived the delivery
        /// budget — the intent watcher is not consuming.
        stuck: bool,
    },
}

/// The delivery budget for an ONLINE leg: a working intent watcher
/// exchanges every watch interval and applies ops immediately; ops older
/// than this on an online leg mean the loop is not consuming.
const QUEUED_OPS_STUCK_AFTER_SECS: u64 =
    interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS;

/// Classifies one leg's mailbox watermark. `now_unix` is the DOCUMENT's
/// capture instant (the same anchor discipline as every recency reading).
fn queued_ops_reading(
    pending: Option<&interflow_mesh::hub::stream_intents::MailboxFace>,
    online: bool,
    now_unix: i64,
) -> QueuedOpsReading {
    let Some(face) = pending else {
        return QueuedOpsReading::Clear;
    };
    let Some(oldest) = face.oldest_queued_unix else {
        return QueuedOpsReading::Clear;
    };
    if face.pending_count == 0 {
        return QueuedOpsReading::Clear;
    }
    let age = (now_unix - i64::try_from(oldest).unwrap_or(i64::MAX)).max(0);
    let age_secs = u64::try_from(age).unwrap_or(u64::MAX);
    QueuedOpsReading::Waiting {
        count: face.pending_count,
        oldest_age_secs: age_secs,
        oldest_op: face.oldest_op.clone(),
        stuck: online && age_secs > QUEUED_OPS_STUCK_AFTER_SECS,
    }
}

/// Renders one leg's queued-op lines (the waiting line and, separately,
/// the drop history); returns whether any check FAILED.
fn render_queued_ops(reading: &QueuedOpsReading, dropped_total: u64) -> bool {
    let mut any_fail = false;
    if let QueuedOpsReading::Waiting {
        count,
        oldest_age_secs,
        oldest_op,
        stuck,
    } = reading
    {
        let op = oldest_op
            .as_deref()
            .map_or_else(String::new, |op| format!(" (oldest: {op})"));
        if *stuck {
            any_fail = true;
            outln!(
                "  ⚠ {count} queued op(s) undelivered for {oldest_age_secs}s on an ONLINE leg{op} — \
                 the intent watcher is not consuming (a working loop delivers within one watch \
                 interval)"
            );
        } else {
            outln!(
                "  ⚠ {count} queued op(s) undelivered for {oldest_age_secs}s{op} — node offline? \
                 (delivered on next check-in)"
            );
        }
    }
    if dropped_total > 0 {
        outln!(
            "  ⚠ the mailbox overflowed {dropped_total} time(s) — an op was dropped; re-issue if \
             it mattered"
        );
    }
    any_fail
}

/// The connection-quality reading for one leg
/// — the
/// window stats `doctor link` could never answer: how often this leg
/// reconnects, where the renewal backoff ladder sits, and what the
/// liveness roundtrip costs.
///
/// The verdict drivers are the COUNTABLE signals (reconnects, backoff
/// stage, probe timeouts); the RTT percentiles are diagnostic material
/// (a p99 spike earns a note, never a failure on its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionQualityReading {
    /// No connection section on the face (an older agent).
    Unknown,
    /// Every countable signal quiet.
    Healthy {
        reconnects: u32,
        backoff_stage: u32,
        rtt_p50_ms: Option<u64>,
        rtt_p99_ms: Option<u64>,
    },
    /// Reconnects in the window — the chronic-instability shape.
    Reconnecting {
        reconnects: u32,
        backoff_stage: u32,
        rtt_p50_ms: Option<u64>,
        rtt_p99_ms: Option<u64>,
    },
    /// Unanswered demanding probes — the one-way-blackhole leading
    /// signal (probes time out while the heartbeat stays in-register).
    ProbesUnanswered {
        reconnects: u32,
        backoff_stage: u32,
        timeouts: u32,
        rtt_p50_ms: Option<u64>,
        rtt_p99_ms: Option<u64>,
    },
}

/// The renewal backoff ladder's depth (the 5-stage e9c7ed2 ladder).
const RENEWAL_BACKOFF_STAGES: u32 = 5;

/// Classifies one leg's connection window. Pure; the p99-spike factor is
/// the engine's single source. `backoff_failures` rides the separate
/// CRL-liveness face (both are additive-optional; missing read unknown).
fn connection_quality_reading(
    connection: Option<&interflow_core::tunnel::transport::ConnectionQualityWire>,
    backoff_failures: Option<u32>,
) -> ConnectionQualityReading {
    let Some(conn) = connection else {
        return ConnectionQualityReading::Unknown;
    };
    let backoff_stage = backoff_failures.unwrap_or(0).min(RENEWAL_BACKOFF_STAGES);
    let fields = (
        conn.reconnects_last_hour,
        backoff_stage,
        conn.rtt_p50_ms,
        conn.rtt_p99_ms,
    );
    if conn.rtt_timeouts > 0 {
        return ConnectionQualityReading::ProbesUnanswered {
            reconnects: conn.reconnects_last_hour,
            backoff_stage,
            timeouts: conn.rtt_timeouts,
            rtt_p50_ms: conn.rtt_p50_ms,
            rtt_p99_ms: conn.rtt_p99_ms,
        };
    }
    if conn.reconnects_last_hour > 0 {
        return ConnectionQualityReading::Reconnecting {
            reconnects: conn.reconnects_last_hour,
            backoff_stage,
            rtt_p50_ms: conn.rtt_p50_ms,
            rtt_p99_ms: conn.rtt_p99_ms,
        };
    }
    let (reconnects, backoff_stage, rtt_p50_ms, rtt_p99_ms) = fields;
    ConnectionQualityReading::Healthy {
        reconnects,
        backoff_stage,
        rtt_p50_ms,
        rtt_p99_ms,
    }
}

/// Renders one leg's connection-quality lines; returns whether the
/// reading FAILED.
fn render_connection_quality(
    reading: &ConnectionQualityReading,
    backoff_max_today: Option<u32>,
) -> bool {
    match reading {
        ConnectionQualityReading::Unknown => false,
        ConnectionQualityReading::Healthy {
            reconnects,
            backoff_stage,
            rtt_p50_ms,
            rtt_p99_ms,
        } => {
            outln!(
                "  · connection: reconnects {reconnects}/h · backoff stage {backoff_stage}/{RENEWAL_BACKOFF_STAGES}{} · rtt {}",
                backoff_note(backoff_max_today),
                rtt_note(*rtt_p50_ms, *rtt_p99_ms),
            );
            false
        }
        ConnectionQualityReading::Reconnecting {
            reconnects,
            backoff_stage,
            rtt_p50_ms,
            rtt_p99_ms,
        } => {
            outln!(
                "  ⚠ connection: reconnects {reconnects}/h · backoff stage {backoff_stage}/{RENEWAL_BACKOFF_STAGES}{} · rtt {} — chronic instability (reconnects > 0{}); if backoff is climbing too, this leg is on the long-term-loss edge",
                backoff_note(backoff_max_today),
                rtt_note(*rtt_p50_ms, *rtt_p99_ms),
                if *backoff_stage > 0 {
                    " AND the backoff ladder is climbing"
                } else {
                    ""
                },
            );
            true
        }
        ConnectionQualityReading::ProbesUnanswered {
            reconnects,
            backoff_stage,
            timeouts,
            rtt_p50_ms,
            rtt_p99_ms,
        } => {
            outln!(
                "  ⚠ connection: {timeouts} liveness probe(s) unanswered (reconnects {reconnects}/h, backoff stage {backoff_stage}/{RENEWAL_BACKOFF_STAGES}{}, rtt {}) — the heartbeat staying in-register while probes go unanswered is the one-way-blackhole signature: check `circuit evicted` on the hub before assuming the network",
                backoff_note(backoff_max_today),
                rtt_note(*rtt_p50_ms, *rtt_p99_ms),
            );
            true
        }
    }
}

/// The ` (max N today)` fragment for the backoff stage.
fn backoff_note(max_today: Option<u32>) -> String {
    max_today
        .filter(|max| *max > 0)
        .map_or_else(String::new, |max| format!(" (max {max} today)"))
}

/// The `p50 Xms p99 Yms` fragment, with the spike note when p99 runs
/// 3× the median (the 2026-09-28 QUIC portrait's criterion).
fn rtt_note(p50_ms: Option<u64>, p99_ms: Option<u64>) -> String {
    match (p50_ms, p99_ms) {
        (Some(p50), Some(p99)) => {
            let spike = if p99
                > p50.saturating_mul(interflow_mesh::agent::connection_quality::P99_SPIKE_FACTOR)
            {
                " ⚠ p99 ≫ p50 — path degradation"
            } else {
                ""
            };
            format!("p50 {p50}ms p99 {p99}ms{spike}")
        }
        (Some(p50), None) => format!("p50 {p50}ms"),
        _ => "no samples".to_owned(),
    }
}

/// The credential-expiry reading for one leg
/// — "don't
/// forget to rotate" as a displayed level instead of a discipline.
///
/// The judgment is per-tier: the OFFLINE tier's lines are absolute days
/// (warn under one rotate-ceremony lead, red inside the backup
/// window), the REGISTRAR tier reuses the identity module's
/// span-relative phases (renewal should have landed long before a
/// short leaf ages into warn). The face carries the raw window; the
/// thresholds stay single-sourced here and in the identity module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialReading {
    /// No window on the face (an older hub, or the chain carried none).
    Unknown,
    /// Comfortably inside the tier's line.
    Ok {
        mode: &'static str,
        remaining_secs: i64,
    },
    /// Past the tier's yellow line.
    Warn {
        mode: &'static str,
        remaining_secs: i64,
    },
    /// Past the tier's red line (or already expired — the deepest form).
    Critical {
        mode: &'static str,
        remaining_secs: i64,
    },
}

/// Classifies one leg's credential window. `now_unix` is the DOCUMENT's
/// capture instant (the countdown reads against hub truth, never the
/// operator's clock).
fn credential_reading(
    not_before_unix: Option<i64>,
    not_after_unix: Option<i64>,
    now_unix: i64,
) -> CredentialReading {
    let (Some(not_before), Some(not_after)) = (not_before_unix, not_after_unix) else {
        return CredentialReading::Unknown;
    };
    let remaining = not_after - now_unix;
    let mode = interflow_mesh::hub::credential_watermarks::tier_from_span(not_after - not_before);
    if remaining < 0 {
        CredentialReading::Critical {
            mode,
            remaining_secs: remaining,
        }
    } else if mode == "offline" {
        let days = remaining / 86_400;
        if days < interflow_identity::expiry::OFFLINE_CRITICAL_DAYS {
            CredentialReading::Critical {
                mode,
                remaining_secs: remaining,
            }
        } else if days < interflow_identity::expiry::OFFLINE_WARN_DAYS {
            CredentialReading::Warn {
                mode,
                remaining_secs: remaining,
            }
        } else {
            CredentialReading::Ok {
                mode,
                remaining_secs: remaining,
            }
        }
    } else {
        match interflow_identity::expiry::leaf_phase_from_validity(not_before, not_after, now_unix)
            .phase
        {
            interflow_identity::expiry::LeafPhase::Healthy => CredentialReading::Ok {
                mode,
                remaining_secs: remaining,
            },
            interflow_identity::expiry::LeafPhase::Warn => CredentialReading::Warn {
                mode,
                remaining_secs: remaining,
            },
            interflow_identity::expiry::LeafPhase::Critical => CredentialReading::Critical {
                mode,
                remaining_secs: remaining,
            },
        }
    }
}

/// Renders one leg's credential line; returns whether the reading
/// FAILED (red — the rotate is now overdue). An OFFLINE leg's countdown
/// renders with a stale note: the window is absolute, time does not
/// pause for a down node.
fn render_credential(reading: &CredentialReading, online: bool) -> bool {
    match reading {
        CredentialReading::Unknown => {
            outln!("  · leaf expiry unknown (no window on this hub's face)");
            false
        }
        CredentialReading::Ok {
            mode,
            remaining_secs,
        } => {
            outln!(
                "  ✔ leaf {} remaining ({mode})",
                humanize_secs(u64::try_from(*remaining_secs).unwrap_or(0))
            );
            false
        }
        CredentialReading::Warn {
            mode,
            remaining_secs,
        } => {
            let stale = if online {
                ""
            } else {
                " · stale (node offline — the countdown keeps running)"
            };
            let tier_hint = if *mode == "registrar" {
                " — renewal stalled? the leaf is aging out faster than rotation lands"
            } else {
                " — offline tier: rotate with `interflow-cli rotate` before the red line"
            };
            outln!(
                "  ⚠ leaf {} remaining (< {}{}d){stale}{tier_hint}",
                humanize_secs(u64::try_from(*remaining_secs).unwrap_or(0)),
                interflow_identity::expiry::OFFLINE_WARN_DAYS,
                if *mode == "offline" {
                    ""
                } else {
                    "20% of span"
                }
            );
            false
        }
        CredentialReading::Critical {
            mode,
            remaining_secs,
        } => {
            let expired = if *remaining_secs < 0 { "EXPIRED" } else { "0" };
            let _ = expired;
            outln!(
                "  ✘ leaf {} remaining ({mode}) — rotate NOW with `interflow-cli rotate`; the                  node stops serving at expiry{}",
                humanize_secs(u64::try_from(*remaining_secs).unwrap_or(0)),
                if online {
                    ""
                } else {
                    " (node offline — rotate lands on its next start"
                }
            );
            true
        }
    }
}

/// The session-headroom reading for one admission scope (global or
/// per-agent): remaining capacity as a percentage, flagged when under
/// the mesh's single-source warn ratio — chronic growth surfaces BEFORE
/// the `Global stream limit reached` wall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeadroomReading {
    in_flight: u64,
    cap: u64,
    remaining_pct: u64,
    /// Remaining capacity under [`HEADROOM_WARN_RATIO`].
    tight: bool,
}

/// Classifies one scope's headroom. `cap = 0` (unlimited) reads `None`
/// — no wall, no reading. Pure; the ratio is the routing module's
/// single source.
fn headroom_reading(in_flight: u64, cap: u64) -> Option<HeadroomReading> {
    if cap == 0 {
        return None;
    }
    let remaining = cap.saturating_sub(in_flight);
    let remaining_pct = remaining * 100 / cap;
    // floor(remaining·100/cap) < P  ⟺  remaining/cap < P/100: the integer
    // form of the ratio test, no float arithmetic on the counts.
    let tight = remaining_pct < headroom_warn_pct();
    Some(HeadroomReading {
        in_flight,
        cap,
        remaining_pct,
        tight,
    })
}

/// The routing module's warn ratio as a whole percent.
// A const ratio in [0, 1] scaled to a percent: nothing to truncate, no sign
// to lose — the lints cannot see the range.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn headroom_warn_pct() -> u64 {
    (interflow_mesh::hub::routing::HEADROOM_WARN_RATIO * 100.0).round() as u64
}

/// Renders one headroom line; returns whether it reads tight (⚠ — a
/// warning, not a failure: the wall has not been hit, and growth is the
/// story to watch).
fn render_headroom(label: &str, reading: &HeadroomReading) -> bool {
    if reading.tight {
        outln!(
            "  ⚠ {label} sessions {}/{} — only {}% headroom (< {}%): chronic growth will hit the \
             admission wall",
            reading.in_flight,
            reading.cap,
            reading.remaining_pct,
            headroom_warn_pct()
        );
    } else {
        outln!(
            "  · {label} sessions {}/{} ({}% headroom)",
            reading.in_flight,
            reading.cap,
            reading.remaining_pct
        );
    }
    reading.tight
}

/// Humanizes a seconds count for operator lines ("3d 2h", "45m", "30s")
/// — day-scale fossil ages are unreadable as raw seconds.
fn humanize_secs(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{secs}s")
    }
}

/// Renders one leg's fossil lines (streams whose last byte went quiet
/// past a multiple of their own idle budget, or the unbudgeted default)
/// — the mirror of the presence face: "mounted" and "alive" are
/// different claims. Informational ⚠ by design: marking is an
/// observation, removing the rule is a plan-apply operation.
fn render_fossil_streams(
    streams: &[interflow_core::tunnel::transport::NodeStreamActivity],
    now_unix: i64,
) {
    let now = u64::try_from(now_unix).unwrap_or(0);
    for stream in streams {
        if interflow_mesh::hub::node_status::stream_is_fossil(
            stream.last_byte_unix,
            stream.idle_budget_secs,
            now,
        ) {
            let age = now.saturating_sub(stream.last_byte_unix);
            outln!(
                "  ⚠ stream {} idle for {} — fossil (the service may be gone, or the rule ready \
                 to remove); the listener stays armed by policy",
                stream.name,
                humanize_secs(age)
            );
        }
    }
}

/// The armed-assertion reading of the hub's resident tasks — the watchdog
/// face's verdict shape
///. Every row
/// carries its own cadence anchor, so "silent" means quieter than the
/// task's OWN rhythm, never a global threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchersReading {
    /// The face carries no rows (an older hub without the field) — the
    /// assertion is unjudgeable, never rendered as passed.
    Unknown,
    /// Every registered task ticked within its own threshold.
    AllArmed {
        count: usize,
        freshest_age_secs: u64,
        oldest_age_secs: u64,
    },
    /// At least one row went quiet past its own threshold — the "process
    /// alive, task inside it wedged" shape (name, interval, tick age).
    Silent {
        armed: usize,
        silent: Vec<(String, u64, u64)>,
    },
}

/// Classifies the watchdog face. `now_unix` is the DOCUMENT's capture
/// instant (same discipline as [`policy_seen_reading`]); the threshold is
/// the mesh watchdog's single-source factor (`strictly more than`
/// N×interval — exactly N× is a slow pass, not silence).
fn watchers_reading(
    rows: &[interflow_mesh::hub::watchdog::WatcherFaceRow],
    now_unix: i64,
) -> WatchersReading {
    if rows.is_empty() {
        return WatchersReading::Unknown;
    }
    let now = u64::try_from(now_unix).unwrap_or(0);
    let mut silent = Vec::new();
    let mut freshest = u64::MAX;
    let mut oldest = 0u64;
    for row in rows {
        let age = now.saturating_sub(row.last_tick_unix);
        freshest = freshest.min(age);
        oldest = oldest.max(age);
        if interflow_mesh::hub::watchdog::is_silent(row, now) {
            silent.push((row.name.clone(), row.interval_secs, age));
        }
    }
    if silent.is_empty() {
        WatchersReading::AllArmed {
            count: rows.len(),
            freshest_age_secs: freshest,
            oldest_age_secs: oldest,
        }
    } else {
        WatchersReading::Silent {
            armed: rows.len() - silent.len(),
            silent,
        }
    }
}

/// Renders the hub section's watcher assertion line(s); returns whether
/// the assertion FAILED (a silent row — the face's whole point is making
/// this one glance).
fn render_watchers(reading: &WatchersReading) -> bool {
    match reading {
        WatchersReading::Unknown => {
            outln!("  · watchers=unknown (this hub predates the watchdog face)");
            false
        }
        WatchersReading::AllArmed {
            count,
            freshest_age_secs,
            oldest_age_secs,
        } => {
            outln!(
                "✔ all watchers armed ({count}/{count}, ticks {freshest_age_secs}s–{oldest_age_secs}s ago)"
            );
            false
        }
        WatchersReading::Silent { armed, silent } => {
            let count = armed + silent.len();
            for (name, interval_secs, age_secs) in silent {
                outln!(
                    "⚠ watcher \"{name}\" silent {age_secs}s (interval {interval_secs}s) — the \
                     task is wedged while the hub keeps serving; check the journal for its \
                     last output before the silence started"
                );
            }
            outln!("✘ watchers {armed}/{count} armed — a resident task stopped ticking");
            true
        }
    }
}

/// Renders the hub-side reading; returns whether any check failed (the
/// caller maps that to the exit code).
fn render_hub_reading(endpoint: &str, doc: &FleetSnapshotDoc) -> bool {
    use interflow_mesh::hub::snapshot::SnapshotTransport;
    let mut any_fail = false;
    let node = doc.hub.node.as_deref().unwrap_or("(unnamed)");
    outln!("hub {node} at {endpoint}");
    match (doc.hub.serving_generation, doc.hub.serving_source) {
        (Some(generation), Some(ServingSource::StateLineage)) => {
            outln!(
                "✔ serving policy gen {generation} (from state lineage — the upgrade contract \
                 held)"
            );
        }
        (Some(generation), Some(ServingSource::PackSnapshot)) => {
            outln!(
                "· serving policy gen {generation} (from pack snapshot) — fresh install, or a \
                 lineage loss: if state/ was expected to survive, investigate; a gen ABOVE \
                 the old lineage re-converges by re-publishing"
            );
        }
        (Some(generation), None) => outln!("✔ serving policy gen {generation}"),
        (None, _) => {
            any_fail = true;
            outln!("✘ the hub serves NO policy bundle — every policy face is dark");
        }
    }
    outln!(
        "  floor {} · evicted_total {} (cumulative for this hub process)",
        doc.hub.floor_generation,
        doc.hub.evicted_total
    );
    // The hub's OWN poll loop (the liveness face's self slot): judged at
    // the document's capture instant like every recency verdict.
    let hub_crl = crl_poll_reading(doc.hub.crl_last_success_unix, doc.hub.captured_at_unix);
    outln!(
        "  {} (this hub's own renewal loop)",
        crl_poll_line(&hub_crl, doc.hub.crl_failures_total)
    );
    if let CrlPollReading::Silent { age_secs } = hub_crl {
        any_fail = true;
        outln!(
            "  ⚠ the hub's own CRL poll loop has not completed a poll for {age_secs}s (> {}s = \
             3× the 60s poll cadence): the loop may be wedged while the hub keeps serving",
            interflow_renewal::CRL_SILENT_AFTER_SECS
        );
    }
    // The resident-task armed assertion (the watchdog face): every
    // long-lived task judged against its own cadence. A silent row fails
    // the hub reading — the face exists to make this unmissable.
    let watchers = watchers_reading(&doc.hub.watchers, doc.hub.captured_at_unix);
    if render_watchers(&watchers) {
        any_fail = true;
    }
    // The route-breaker open set (edge gateways only; absent on plain
    // mesh hubs). Informational by design: an open route means traffic to
    // that host is being rejected — the symptom that drives investigation
    // — and this line makes the state readable without pulling the
    // metrics face.
    if !doc.hub.route_breakers_open.is_empty() {
        let entries = doc
            .hub
            .route_breakers_open
            .iter()
            .map(|row| {
                let open_age = (doc.hub.captured_at_unix
                    - i64::try_from(row.opened_unix).unwrap_or(i64::MAX))
                .max(0);
                let probe_age = (doc.hub.captured_at_unix
                    - i64::try_from(row.last_probe_unix).unwrap_or(i64::MAX))
                .max(0);
                format!("{} (open {open_age}s, probe {probe_age}s ago)", row.host)
            })
            .collect::<Vec<_>>()
            .join(", ");
        outln!("  ⚠ route breakers OPEN: {entries}");
    }
    if doc.hub.evicted_total > 0 {
        outln!(
            "  note: evictions have landed this run — correlate with the journal: \
             journalctl -u <hub> | grep -E 'evicted|eviction voided'"
        );
    }
    // The global session headroom (the admission caps the routing plane
    // enforces): chronic growth surfaces before the wall.
    if let Some(headroom) = doc
        .hub
        .streams_in_flight_total
        .zip(doc.hub.stream_limits.map(|limits| limits.total))
        .and_then(|(in_flight, cap)| headroom_reading(in_flight, cap))
    {
        render_headroom("hub", &headroom);
    }
    // The proposals queue's watermark: decisions awaiting the operator
    // (informational — the queue is the operator's own worklist).
    if let Some(proposals) = &doc.hub.proposals_pending {
        let age = (doc.hub.captured_at_unix
            - i64::try_from(proposals.oldest_submitted_unix).unwrap_or(i64::MAX))
        .max(0);
        outln!(
            "  · {} proposal(s) awaiting decision (oldest for {age}s) — `interflow-cli proposals`",
            proposals.pending_count
        );
    }
    outln!();
    outln!("legs:");
    for leg in &doc.agents {
        // Planned unavailability reads as its own (yellow) glyph language,
        // never red: a paused stream or a declared maintenance is operator
        // intent, not a fault — the whole point of the distinction.
        let glyph = if leg.maintenance.unwrap_or(false) {
            "⚠"
        } else if leg.online {
            "✔"
        } else {
            "·"
        };
        let transport = match leg.transport {
            Some(SnapshotTransport::Quic) => "quic",
            Some(SnapshotTransport::H2) => "h2",
            None => "-",
        };
        let build = leg.build.as_deref().unwrap_or("unknown build");
        let circuit = leg.circuit.as_deref().map_or("-", |c| &c[..8.min(c.len())]);
        // The policy face's four-state reading, judged at the document's
        // capture instant. For an OFFLINE leg the presence glyph already
        // carries the story — its recency renders plain (no ⚠, no fail):
        // "silent" is reserved for the failure class where presence stays
        // and only the policy plane stopped.
        let reading = policy_seen_reading(
            leg.seen_generation,
            leg.last_pull_unix,
            doc.hub.serving_generation,
            doc.hub.captured_at_unix,
        );
        // The node's CRL-poll liveness reading, same capture anchor. For
        // an OFFLINE leg the presence glyph already carries the story —
        // its frozen level renders plain (no ⚠, no fail).
        let crl = crl_poll_reading(leg.crl_last_success_unix, doc.hub.captured_at_unix);
        outln!(
            "{glyph} {} online={} transport={} build={} circuit={}… {} · {}",
            leg.agent,
            leg.online,
            transport,
            build,
            circuit,
            policy_seen_line(&reading),
            crl_poll_line(&crl, leg.crl_failures_total)
        );
        if leg.online
            && let PolicySeenReading::Silent { seen, age_secs } = reading
        {
            any_fail = true;
            outln!(
                "  ⚠ silent policy face — the leg holds gen {seen} but has not pulled for \
                 {age_secs}s (> {}s = 3× the 10s watch interval): the node's policy watcher \
                 may be dead while the leg stays online",
                interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS
            );
        }
        if leg.online
            && let CrlPollReading::Silent { age_secs } = crl
        {
            any_fail = true;
            outln!(
                "  ⚠ silent CRL poll — the node has not completed a poll for {age_secs}s (> \
                 {}s = 3× the 60s poll cadence): the renewal loop may be wedged while the node \
                 stays online (the 1h fail-closed bound only fires if the loop itself still \
                 runs)",
                interflow_renewal::CRL_SILENT_AFTER_SECS
            );
        }
        if leg.maintenance.unwrap_or(false) {
            outln!(
                "  ⚠ under declared maintenance — the leg's absence is expected, not an \
                 accident; the declaration lifts itself when the node rejoins"
            );
        }
        if let Some(paused) = &leg.paused_streams
            && !paused.is_empty()
        {
            outln!("  ⚠ paused streams (planned): {}", paused.join(", "));
        }
        // The connection-quality window: reconnects, the backoff ladder,
        // the liveness roundtrip — the chronic-degradation shape a point
        // reading can never show.
        let quality =
            connection_quality_reading(leg.connection.as_ref(), leg.renewal_backoff_failures);
        if render_connection_quality(&quality, leg.renewal_backoff_max_today) {
            any_fail = true;
        }
        // The credential-expiry face: the countdown as a displayed
        // level (red fails the reading — the rotate is overdue).
        let credential = credential_reading(
            leg.leaf_not_before_unix,
            leg.leaf_not_after_unix,
            doc.hub.captured_at_unix,
        );
        if render_credential(&credential, leg.online) {
            any_fail = true;
        }
        // The mailbox watermark (queued ops waiting on this leg + the
        // drop history) — the "queued, applies on next check-in" instant
        // made continuous.
        let queued = queued_ops_reading(
            leg.pending_ops.as_ref(),
            leg.online,
            doc.hub.captured_at_unix,
        );
        if render_queued_ops(
            &queued,
            leg.pending_ops.as_ref().map_or(0, |f| f.dropped_total),
        ) {
            any_fail = true;
        }
        // The fossil face: streams mounted and listening but quiet past
        // their own budget multiple — presence without life.
        render_fossil_streams(&leg.streams, doc.hub.captured_at_unix);
        // The per-leg headroom (the per-agent admission cap), rendered
        // only when tight — the hub line carries the steady state.
        if let Some(headroom) = leg
            .streams_in_flight
            .zip(doc.hub.stream_limits.map(|limits| limits.per_agent))
            .and_then(|(in_flight, cap)| headroom_reading(in_flight, cap))
            .filter(|reading| reading.tight)
        {
            render_headroom(&leg.agent, &headroom);
        }
    }
    outln!();
    // Same-build-string + zero-dirty (the acceptance's 五表面 core, hub side).
    let mut builds: Vec<String> = doc
        .agents
        .iter()
        .filter(|a| a.online)
        .filter_map(|a| a.build.clone())
        .collect();
    builds.sort();
    builds.dedup();
    let distinct = builds;
    let dirty = distinct.iter().filter(|b| b.contains("-dirty")).count();
    if distinct.is_empty() {
        outln!("· no online leg reports a build string (older agents) — same-string check vacuous");
    } else if distinct.len() == 1 && dirty == 0 {
        outln!(
            "✔ online legs share one build string ({}) — zero dirty",
            distinct[0]
        );
    } else {
        any_fail = true;
        outln!(
            "✘ online legs carry {} build string(s): {}{} — mixed strings fail acceptance; a \
             -dirty (amber) string voids the leg for production entirely",
            distinct.len(),
            distinct.join(", "),
            if dirty == 0 {
                String::new()
            } else {
                format!(" ({dirty} dirty)")
            }
        );
    }
    // Watermark inversion scan (the authorization layer's hub-side face).
    let inversions: Vec<&interflow_mesh::hub::snapshot::FleetSnapshotAgent> = doc
        .agents
        .iter()
        .filter(|a| matches!((a.seen_generation, doc.hub.serving_generation), (Some(seen), Some(serving)) if seen > serving))
        .collect();
    if let Some(serving) = doc.hub.serving_generation {
        if inversions.is_empty() {
            outln!("✔ no watermark above the serving generation {serving}");
        } else {
            any_fail = true;
            outln!(
                "✘ watermark inversion against serving gen {serving}: {} — the \
                 lineage-deadlock shape; re-publish above the highest watermark",
                inversions
                    .iter()
                    .map(|a| format!("{} holds {}", a.agent, a.seen_generation.unwrap()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    // The all-QUIC formation note (the ping=0 baseline judgment).
    let online = doc.agents.iter().filter(|a| a.online).collect::<Vec<_>>();
    let all_quic = !online.is_empty()
        && online
            .iter()
            .all(|a| a.transport == Some(SnapshotTransport::Quic));
    if all_quic {
        outln!(
            "  note: every online leg is QUIC — the hub heartbeat baseline reads ping=0 in \
             this formation (QUIC legs skip the h2 PING path; ping counts h2 legs only, do \
             not read it as an outage against an old ping=N baseline)"
        );
    }
    any_fail
}

// ---------------------------------------------------------------------------
// --upgrade-check: the acceptance, one command
// ---------------------------------------------------------------------------

/// The probe-triple offsets (§10.8's bar: three shots across the 30-40s
/// death window — 0s, +60s, +180s). A library parameter so tests compress
/// it; the CLI always runs the production cadence.
pub const UPGRADE_PROBE_OFFSETS_SECS: [u64; 3] = [0, 60, 180];

fn run_upgrade_check(args: &LinkArgs) -> interflow_core::error::Result<()> {
    outln!("Interflow doctor link — upgrade acceptance");
    outln!();
    let Some((endpoint, before)) = fetch_snapshot(&args.manifest, &args.issuer)? else {
        return Err(interflow_core::error::InterflowError::config(format!(
            "manifest {} names no hub endpoint — nothing to check against",
            args.manifest.display()
        )));
    };
    outln!(
        "snapshot A: {} online leg(s) at hub {endpoint}",
        before.agents.iter().filter(|a| a.online).count()
    );

    // The data-plane triple (skipped without --probe-url — with the
    // handbook's why spelled out).
    let probe_outcome = match args.probe_url.as_deref() {
        None => {
            outln!(
                "· data-plane triple skipped — green cards and listening sockets prove \
                 NOTHING; pass --probe-url http://… for the 0s/+60s/+180s triple"
            );
            None
        }
        Some(url) => {
            // A target under PLANNED unavailability (paused stream /
            // declared-maintenance node) is detected BEFORE the triple:
            // probing a listener that is down by intent measures the
            // intent, not the mesh — skip the three-minute triple and let
            // the verdict read it as planned (⚠).
            if let Some(note) = probe_target_planned(&args.manifest, &args.issuer, url)? {
                outln!("⚠ probe target under planned unavailability — {note}");
                outln!("  data-plane triple deliberately not counted");
                Some(ProbeTriple::TargetPlanned { note })
            } else {
                Some(probe_triple(url))
            }
        }
    };

    let (_, after) = fetch_snapshot(&args.manifest, &args.issuer)?.ok_or_else(|| {
        interflow_core::error::InterflowError::config(
            "the hub stopped answering between the two snapshots — that is the finding",
        )
    })?;
    outln!(
        "snapshot B: {} online leg(s)",
        after.agents.iter().filter(|a| a.online).count()
    );

    // Persist the pair when asked (the upgrade log's attachment).
    if let Some(dir) = &args.snapshot_out {
        std::fs::create_dir_all(dir)?;
        for (name, doc) in [
            ("upgrade-before.json", &before),
            ("upgrade-after.json", &after),
        ] {
            let envelope = status::SnapshotFile {
                cli_build: interflow_buildinfo::VERSION_WITH_TAG.to_owned(),
                hub_endpoint: endpoint.clone(),
                snapshot: doc.clone(),
            };
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&envelope).map_err(|e| {
                        interflow_core::error::InterflowError::protocol(
                            "snapshot serialization".to_string(),
                        )
                        .with_source(e)
                    })?
                ),
            )?;
            outln!("  persisted: {}", path.display());
        }
    }

    let diff = status::compare(&before, &after);
    let mut any_fail = false;
    for (glyph, line) in upgrade_verdicts(&diff, probe_outcome) {
        if glyph == "✘" {
            any_fail = true;
        }
        outln!("{glyph} {line}");
    }

    if let Some(baseline) = &args.baseline {
        let baseline = read_baseline(baseline)?;
        let continuity = status::compare(&baseline, &after);
        outln!();
        outln!("baseline {} → snapshot B:", baseline.hub.captured_at_unix);
        let (before_online, after_online) = continuity.online_leg_counts();
        let builds = continuity.online_builds();
        outln!(
            "  online {before_online} → {after_online} · builds [{}]",
            builds.join(", ")
        );
        if continuity.hub.gen_regression() {
            any_fail = true;
            outln!("  ✘ serving generation moved BACKWARDS against the baseline");
        }
    }

    outln!();
    if any_fail {
        outln!("Verdict: ✘ — at least one acceptance check failed; see the lines above.");
        return Err(interflow_core::error::InterflowError::config(
            "upgrade acceptance failed",
        ));
    }
    outln!("Verdict: ✔ — same string, steady window, generation continuity.");
    Ok(())
}

fn read_baseline(path: &Path) -> interflow_core::error::Result<FleetSnapshotDoc> {
    // Reuse status's envelope loader (schema-versioned, well-narrated).
    let file: status::SnapshotFile =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| {
            interflow_core::error::InterflowError::config(format!(
                "read baseline {}: {e}",
                path.display()
            ))
        })?)
        .map_err(|e| {
            interflow_core::error::InterflowError::config(format!(
                "parse baseline {} as a status-snapshot file: {e} — capture it with \
             `interflow-cli status snapshot --out …`",
                path.display()
            ))
        })?;
    Ok(file.snapshot)
}

/// What the data-plane probe triple established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeTriple {
    /// All three offsets answered.
    Answered,
    /// At least one offset failed.
    Failed,
    /// The target is under planned unavailability (a paused stream or a
    /// declared-maintenance source node): the triple is deliberately not
    /// run/counted — probing a listener that is down BY INTENT measures
    /// the intent, not the mesh. Carries the human note naming what is
    /// planned.
    TargetPlanned { note: String },
}

/// Runs the data-plane triple against `url` (0s/+60s/+180s), printing
/// per-offset results. `None` is impossible here — the caller decides
/// skip-vs-run.
fn probe_triple(url: &str) -> ProbeTriple {
    let mut failures = Vec::new();
    let mut elapsed = 0u64;
    for offset in UPGRADE_PROBE_OFFSETS_SECS {
        if offset > elapsed {
            std::thread::sleep(Duration::from_secs(offset - elapsed));
            elapsed = offset;
        }
        match http_get(url) {
            HttpVerdict::Answered(status) => {
                outln!("  probe +{offset}s: answered ({status})");
            }
            other => {
                failures.push(format!("+{offset}s: {other:?}"));
                outln!("  probe +{offset}s: ✘ {other:?}");
            }
        }
    }
    if failures.is_empty() {
        outln!("✔ data-plane triple 0s/+60s/+180s — crossed the 30-40s death window");
        ProbeTriple::Answered
    } else {
        outln!(
            "✘ the data-plane triple failed ({}) — timeout ≠ reset: a timeout means \
             the request entered but nothing answered (check the far-end service \
             first); a reset means the path or the far end refused",
            failures.join(", ")
        );
        ProbeTriple::Failed
    }
}

/// Whether the probe target is under planned unavailability, and the
/// human note naming it. Joins the probe URL's authority against the
/// manifest's ingress listens, then the hub's reported faces (paused
/// streams, maintenance declarations). `None` = not planned (probe on).
fn probe_target_planned(
    manifest: &std::path::Path,
    issuer: &std::path::Path,
    url: &str,
) -> interflow_core::error::Result<Option<String>> {
    let authority = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return Ok(None);
    }
    let Ok(manifest_doc) = interflow_identity::manifest::Manifest::load(manifest) else {
        return Ok(None);
    };
    // The agent whose listen matches the probe authority (bare name).
    let owners: Vec<(&String, &interflow_identity::manifest::MeshIngressRule)> = manifest_doc
        .agent
        .iter()
        .flat_map(|(name, agent)| agent.mesh_ingress.iter().map(move |rule| (name, rule)))
        .filter(|(_, rule)| rule.listen == authority)
        .collect();
    if owners.is_empty() {
        return Ok(None);
    }
    let Some((endpoint, overview)) = interflow_cli::plan::with_hub_control_credential(
        manifest,
        issuer,
        |ep, ca, cert, key| async move {
            interflow_mesh::hub::policy::query_hub_overview(&ep, &ca, &cert, &key).await
        },
    )?
    else {
        return Ok(None);
    };
    let _ = endpoint;
    for (agent, rule) in owners {
        let row = overview
            .agents
            .iter()
            .find(|row| row.agent.rsplit('/').next() == Some(agent.as_str()));
        if let Some(row) = row {
            if row
                .paused_streams
                .as_ref()
                .is_some_and(|paused| paused.iter().any(|p| p == &rule.name))
            {
                return Ok(Some(format!(
                    "stream {} on {} is paused (listener deliberately down)",
                    rule.name, row.agent
                )));
            }
            if row.maintenance {
                return Ok(Some(format!(
                    "node {} is under declared maintenance",
                    row.agent
                )));
            }
        }
    }
    Ok(None)
}

/// The acceptance verdicts over a before/after diff — pure, unit-tested.
/// `(glyph, line)` pairs; `probes` is `None` when the triple was skipped
/// entirely (no `--probe-url`).
pub fn upgrade_verdicts(
    diff: &status::SnapshotDiff,
    probes: Option<ProbeTriple>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    // 1. Same build string, zero dirty (五表面 core, hub side).
    let builds = diff.online_builds();
    let dirty = builds.iter().filter(|b| b.contains("-dirty")).count();
    if builds.is_empty() {
        out.push((
            "·",
            "no online leg reports a build string (older agents) — same-string check \
             vacuous"
                .to_owned(),
        ));
    } else if builds.len() == 1 && dirty == 0 {
        out.push((
            "✔",
            format!(
                "online legs share one build string ({}) — zero dirty",
                builds[0]
            ),
        ));
    } else {
        let reason = if builds.len() > 1 {
            format!("MIXED build strings: {}", builds.join(", "))
        } else {
            format!(
                "DIRTY build string: {} — an amber string voids the leg entirely",
                builds[0]
            )
        };
        out.push(("✘", reason));
    }
    // 2. Steady window: evictions flat.
    if diff.hub.evicted_delta() == 0 {
        out.push((
            "✔",
            format!(
                "steady window: evicted_total {} → {} (no eviction landed)",
                diff.hub.evicted_from, diff.hub.evicted_to
            ),
        ));
    } else {
        out.push((
            "✘",
            format!(
                "evictions landed between the captures (+{}) — find the reason: \
                 journalctl -u <hub> | grep evicted",
                diff.hub.evicted_delta()
            ),
        ));
    }
    // 3. Online stability — with planned unavailability carved out: a leg
    // that went offline under a declared maintenance is the EXPECTED
    // reading (⚠, named), not an acceptance failure. Only unplanned
    // movement fails the card.
    let (before, after) = diff.online_leg_counts();
    let went_offline: Vec<&status::AgentDiff> = diff
        .agents
        .iter()
        .filter(|a| a.presence == status::PresenceChange::WentOffline)
        .collect();
    let planned = |a: &status::AgentDiff| a.maintenance_now || a.maintenance_change.is_some();
    let offline_planned: Vec<&str> = went_offline
        .iter()
        .filter(|a| planned(a))
        .map(|a| a.agent.as_str())
        .collect();
    let any_unplanned = went_offline.iter().any(|a| !planned(a));
    if before == after && went_offline.is_empty() {
        out.push(("✔", format!("online legs stable ({before} → {after})")));
    } else if !any_unplanned && !offline_planned.is_empty() {
        out.push((
            "⚠",
            format!(
                "online legs moved ({before} → {after}); offline: {} — all under \
                 declared maintenance (planned unavailability, not an accident)",
                offline_planned.join(", ")
            ),
        ));
    } else {
        out.push((
            "✘",
            format!(
                "online legs moved ({before} → {after}){} — a leg still down after the \
                 window: check its journal before anything else",
                if went_offline.is_empty() {
                    String::new()
                } else {
                    let names: Vec<&str> = went_offline.iter().map(|a| a.agent.as_str()).collect();
                    format!("; offline: {}", names.join(", "))
                }
            ),
        ));
    }
    // 4. Generation continuity.
    if diff.hub.gen_regression() {
        out.push((
            "✘",
            format!(
                "serving generation moved BACKWARDS ({} → {}) — a lineage-loss shape",
                diff.hub
                    .serving_from
                    .map_or_else(|| "?".to_owned(), |g| g.to_string()),
                diff.hub
                    .serving_to
                    .map_or_else(|| "?".to_owned(), |g| g.to_string()),
            ),
        ));
    } else {
        out.push((
            "✔",
            format!(
                "serving generation held or advanced ({} → {})",
                diff.hub
                    .serving_from
                    .map_or_else(|| "?".to_owned(), |g| g.to_string()),
                diff.hub
                    .serving_to
                    .map_or_else(|| "?".to_owned(), |g| g.to_string()),
            ),
        ));
    }
    if diff.hub.lineage_lost() {
        out.push((
            "⚠",
            "lineage origin flipped to pack snapshot — with the direction caveat: at a \
             HIGHER generation it re-converges by re-publishing; at a lower one it is the \
             deadlock shape"
                .to_owned(),
        ));
    }
    // 5. The probe triple.
    match probes {
        None => out.push((
            "·",
            "data-plane triple not run (no --probe-url) — the strongest check is missing, \
             green cards prove nothing"
                .to_owned(),
        )),
        Some(ProbeTriple::Answered) => out.push((
            "✔",
            "data-plane triple 0s/+60s/+180s all answered — crossed the 30-40s death \
             window"
                .to_owned(),
        )),
        Some(ProbeTriple::TargetPlanned { note }) => out.push((
            "⚠",
            format!(
                "probe target under planned unavailability ({note}) — the triple was \
                 deliberately not counted; probe it again after the resume / the node's \
                 return"
            ),
        )),
        Some(ProbeTriple::Failed) => out.push((
            "✘",
            "the data-plane triple failed — timeout ≠ reset: check the far-end service \
             before the mesh"
                .to_owned(),
        )),
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use interflow_mesh::hub::snapshot::{FleetSnapshotAgent, FleetSnapshotHub};

    // ----- packet / classification primitives -------------------------------

    /// The VN trigger is a long header with an unknown version and the
    /// DCID carried verbatim; VN responses carry version 0x00000000.
    #[test]
    fn version_negotiation_packet_shape() {
        let dcid = [0xabu8; 8];
        let packet = version_negotiation_trigger(&dcid);
        assert_eq!(
            packet[0] & 0xc0,
            0xc0,
            "long header + fixed bit: {:02x}",
            packet[0]
        );
        assert_eq!(&packet[1..5], &[0x0a, 0x0a, 0x0a, 0x0a], "unknown version");
        assert_eq!(packet[5], 8, "DCID length");
        assert_eq!(&packet[6..14], &dcid);
        assert_eq!(packet[14], 0, "empty SCID");

        let mut vn = vec![0xc0 | 0x1f];
        vn.extend_from_slice(&[0, 0, 0, 0]);
        vn.extend_from_slice(&[8]);
        vn.extend_from_slice(&dcid);
        assert!(looks_like_version_negotiation(&vn));
        // A real Initial (version 1) must NOT read as VN.
        let mut initial = vec![0xc0, 0, 0, 0, 1];
        initial.extend_from_slice(&[0u8; 16]);
        assert!(!looks_like_version_negotiation(&initial));
        assert!(!looks_like_version_negotiation(&[0xc0, 0, 0]));
    }

    /// The fake-ip benchmark range, precisely.
    #[test]
    fn fake_ip_range_membership() {
        let fake = |s: &str| is_fake_ip(&s.parse::<IpAddr>().unwrap());
        assert!(fake("198.18.0.1") && fake("198.19.255.254"));
        assert!(!fake("198.17.255.255") && !fake("198.20.0.1") && !fake("182.92.112.81"));
        assert!(!fake("::1"));
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_host_port("mesh.example.com:6666"),
            Some(("mesh.example.com", 6666))
        );
        assert_eq!(split_host_port("[::1]:6666"), Some(("::1", 6666)));
        assert_eq!(split_host_port("127.0.0.1:6666"), Some(("127.0.0.1", 6666)));
        assert_eq!(split_host_port("nohost"), None);
        assert_eq!(split_host_port("host:"), None);
    }

    // ----- the layered engine over a fake probe ----------------------------

    struct FakeProbe {
        dns: DnsVerdict,
        tcp: TcpVerdict,
        udp: UdpVerdict,
        tls: TlsVerdict,
    }
    impl LinkProbe for FakeProbe {
        fn resolve(&self, _host: &str) -> DnsVerdict {
            self.dns.clone()
        }
        fn tcp(&self, _addr: SocketAddr) -> TcpVerdict {
            self.tcp
        }
        fn udp(&self, _addr: SocketAddr) -> UdpVerdict {
            self.udp.clone()
        }
        fn mtls(&self, _addr: SocketAddr, _host: &str, _pack: Option<&Path>) -> TlsVerdict {
            self.tls.clone()
        }
    }

    fn healthy_probe() -> FakeProbe {
        FakeProbe {
            dns: DnsVerdict::Resolved(vec!["182.92.112.81".parse().unwrap()]),
            tcp: TcpVerdict::Open,
            udp: UdpVerdict::Answered,
            tls: TlsVerdict::HandshakeOk {
                not_before: 0,
                not_after: 4_102_444_800,
            },
        }
    }

    fn doc(serving: Option<u64>, rows: Vec<FleetSnapshotAgent>) -> FleetSnapshotDoc {
        doc_at(serving, rows, 0)
    }

    /// [`doc`] with the capture instant recency judgments anchor against.
    fn doc_at(
        serving: Option<u64>,
        rows: Vec<FleetSnapshotAgent>,
        captured_at_unix: i64,
    ) -> FleetSnapshotDoc {
        FleetSnapshotDoc {
            format_version: 1,
            hub: FleetSnapshotHub {
                crl_last_success_unix: None,
                crl_failures_total: None,
                crl_last_reload_unix: None,
                route_breakers_open: vec![],
                watchers: vec![],
                proposals_pending: None,
                streams_in_flight_total: None,
                stream_limits: None,
                node: Some("promptcn".into()),
                serving_generation: serving,
                serving_source: serving.map(|_| ServingSource::StateLineage),
                floor_generation: serving.unwrap_or(0),
                evicted_total: 0,
                crl_numbers: std::collections::BTreeMap::new(),
                captured_at_unix,
            },
            agents: rows,
        }
    }

    fn leg(agent: &str, online: bool, seen: Option<u64>) -> FleetSnapshotAgent {
        leg_recency(agent, online, seen, seen.map(|_| 0))
    }

    /// [`leg`] with an explicit confirmation instant (unix seconds,
    /// judged against the doc's `captured_at_unix`).
    fn leg_recency(
        agent: &str,
        online: bool,
        seen: Option<u64>,
        last_pull_unix: Option<u64>,
    ) -> FleetSnapshotAgent {
        FleetSnapshotAgent {
            crl_last_success_unix: None,
            crl_failures_total: None,
            pending_ops: None,
            streams_in_flight: None,
            streams: vec![],
            leaf_not_before_unix: None,
            leaf_not_after_unix: None,
            credential_mode: None,
            credential_last_seen_unix: None,
            connection: None,
            renewal_backoff_failures: None,
            renewal_backoff_max_today: None,
            agent: agent.to_owned(),
            online,
            seen_generation: seen,
            last_pull_unix,
            build: Some("2026-10-12_bf11cd8".into()),
            transport: Some(interflow_mesh::hub::snapshot::SnapshotTransport::Quic),
            circuit: Some("ab".repeat(16)),
            paused_streams: None,
            maintenance: None,
        }
    }

    fn input<'a>(
        probe_pack: Option<&'a Path>,
        hub: Option<&'a FleetSnapshotDoc>,
        now: i64,
    ) -> ToProbe<'a> {
        ToProbe {
            target: "mesh.example.com:6666",
            pack: probe_pack,
            hub_snapshot: hub,
            probe_url: None,
            now_unix: now,
            hosts_file: Some("127.0.0.1 localhost\n"),
            issuer_crls: None,
        }
    }

    /// The four handbook injections, as test doubles: DNS failure, the
    /// security-group UDP gap, a dead far end, watermark inversion — each
    /// must name ITS layer, not a generic failure.
    #[test]
    fn broken_layers_are_named() {
        let hub = doc(Some(15), vec![leg("main/lan-a", true, Some(15))]);

        // DNS gone → the authentication layer's DNS row, nothing further.
        let broken_dns = FakeProbe {
            dns: DnsVerdict::Failed("nx".into()),
            ..healthy_probe()
        };
        let report = probe_to(&broken_dns, &input(None, Some(&hub), 1_760_000_000));
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Dns);
        assert_eq!(broken.layer.name(), "authentication");
        assert!(
            broken.line.contains("dig +short"),
            "the split-the-question fix: {}",
            broken.line
        );

        // Fake-ip: the ClashX signature with the hosts-pinning fix.
        let fake_dns = FakeProbe {
            dns: DnsVerdict::Resolved(vec!["198.18.0.7".parse().unwrap()]),
            ..healthy_probe()
        };
        let report = probe_to(&fake_dns, &input(None, Some(&hub), 1_760_000_000));
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Dns);
        assert!(broken.line.contains("fake-ip"), "{}", broken.line);

        // TCP timeout → path judgment (timeout ≠ reset).
        let unreachable = FakeProbe {
            tcp: TcpVerdict::Unreachable,
            ..healthy_probe()
        };
        let report = probe_to(&unreachable, &input(None, Some(&hub), 1_760_000_000));
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Tcp);
        assert!(broken.line.contains("timeout ≠ reset"), "{}", broken.line);

        // TCP open + UDP silent → the security-group gap, named precisely.
        let udp_gap = FakeProbe {
            udp: UdpVerdict::Silent,
            ..healthy_probe()
        };
        let report = probe_to(&udp_gap, &input(None, Some(&hub), 1_760_000_000));
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Udp);
        assert!(
            broken.line.contains("TCP rules do not cover UDP"),
            "{}",
            broken.line
        );

        // Watermark inversion → the authorization layer.
        let inverted_hub = doc(Some(10), vec![leg("main/lan-a", true, Some(15))]);
        let report = probe_to(
            &healthy_probe(),
            &input(None, Some(&inverted_hub), 1_760_000_000),
        );
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Watermark);
        assert_eq!(broken.layer.name(), "authorization");
        assert!(broken.line.contains("deadlock"), "{}", broken.line);

        // Clock skew: the peer cert window starts in the future. (A pack
        // path must be present to arm the layer; the fake probe ignores it.)
        let skewed = FakeProbe {
            tls: TlsVerdict::HandshakeOk {
                not_before: 1_760_000_000 + 3_600,
                not_after: 4_102_444_800,
            },
            ..healthy_probe()
        };
        let report = probe_to(
            &skewed,
            &input(Some(Path::new("/pack")), Some(&hub), 1_760_000_000),
        );
        let broken = report.first_broken().unwrap();
        assert_eq!(broken.layer, LinkLayer::Tls);
        assert!(broken.line.contains("clock is BEHIND"), "{}", broken.line);
    }

    /// The healthy path: every layer ✔ or explicitly skipped with its
    /// how-to-enable note — never a fake green without input.
    #[test]
    fn healthy_path_and_skips() {
        let hub = doc(Some(15), vec![leg("main/lan-a", true, Some(15))]);
        let report = probe_to(&healthy_probe(), &input(None, Some(&hub), 1_760_000_000));
        assert!(report.first_broken().is_none(), "{report:?}");
        assert!(
            report
                .results
                .iter()
                .any(|r| r.skipped && r.layer == LinkLayer::Tls && r.line.contains("--pack")),
            "the TLS skip explains itself: {:?}",
            report.results
        );
        // No pack → CRL skipped too; watermark read from the hub doc.
        assert!(
            report
                .results
                .iter()
                .any(|r| r.layer == LinkLayer::Watermark && r.ok && !r.skipped)
        );
    }

    // ----- the policy face's four-state reading --------------------------------

    /// The CRL-poll liveness reading's three states and the silent
    /// boundary, plus the rendered fragments.
    #[test]
    fn crl_poll_reading_states_and_boundary() {
        use interflow_renewal::CRL_SILENT_AFTER_SECS as threshold;
        let now = 1_760_000_000i64;
        let polled = |age: u64| Some((now - i64::try_from(age).unwrap()).cast_unsigned());

        // Current: polling, nothing changed (no-change polls count).
        assert_eq!(
            crl_poll_reading(polled(45), now),
            CrlPollReading::Current { age_secs: 45 }
        );
        // Never: no report landed (older node / no renewal loop).
        assert_eq!(crl_poll_reading(None, now), CrlPollReading::Never);
        // The boundary: AT the threshold is not yet silent…
        assert_eq!(
            crl_poll_reading(polled(threshold), now),
            CrlPollReading::Current {
                age_secs: threshold
            }
        );
        // …one second past it is the wedged-loop class.
        assert_eq!(
            crl_poll_reading(polled(threshold + 1), now),
            CrlPollReading::Silent {
                age_secs: threshold + 1
            }
        );
        // Rendered fragments: quiet in health, the failure counter rides
        // along only when it moved, the ⚠ only on the silent class.
        assert_eq!(
            crl_poll_line(&CrlPollReading::Current { age_secs: 45 }, Some(0)),
            "crl_poll=ok · 45s ago"
        );
        assert_eq!(
            crl_poll_line(&CrlPollReading::Current { age_secs: 45 }, Some(3)),
            "crl_poll=ok · 45s ago (3 failed polls)"
        );
        assert_eq!(
            crl_poll_line(&CrlPollReading::Never, None),
            "crl_poll=unknown"
        );
        assert_eq!(
            crl_poll_line(
                &CrlPollReading::Silent {
                    age_secs: threshold + 1
                },
                Some(9)
            ),
            format!("crl_poll SILENT {}s ⚠ (9 failed polls)", threshold + 1)
        );
    }

    /// The four states with the threshold boundary pinned: exactly 3× the
    /// watch interval is still a transient (a mid-rebuild session), one
    /// second past it is the silent class.
    #[test]
    fn connection_quality_reading_states_and_notes() {
        use interflow_core::tunnel::transport::ConnectionQualityWire;
        let wire = |reconnects: u32, timeouts: u32| ConnectionQualityWire {
            reconnects_last_hour: reconnects,
            rtt_p50_ms: Some(100),
            rtt_p99_ms: Some(190),
            rtt_timeouts: timeouts,
            rtt_samples: 12,
        };

        // Unknown: no connection section (an older agent).
        assert_eq!(
            connection_quality_reading(None, Some(0)),
            ConnectionQualityReading::Unknown
        );
        // Healthy: everything countable quiet.
        assert_eq!(
            connection_quality_reading(Some(&wire(0, 0)), Some(0)),
            ConnectionQualityReading::Healthy {
                reconnects: 0,
                backoff_stage: 0,
                rtt_p50_ms: Some(100),
                rtt_p99_ms: Some(190)
            }
        );
        // Reconnecting: any reconnect in the window; the backoff stage
        // rides along (clamped to the ladder's depth).
        assert_eq!(
            connection_quality_reading(Some(&wire(6, 0)), Some(9)),
            ConnectionQualityReading::Reconnecting {
                reconnects: 6,
                backoff_stage: 5,
                rtt_p50_ms: Some(100),
                rtt_p99_ms: Some(190)
            }
        );
        // ProbesUnanswered outranks reconnects (the blackhole's leading
        // signal fires while the session object stays alive).
        assert!(matches!(
            connection_quality_reading(Some(&wire(6, 3)), Some(0)),
            ConnectionQualityReading::ProbesUnanswered { timeouts: 3, .. }
        ));
        // The rtt note's spike criterion (strictly past 3× the median).
        assert_eq!(rtt_note(Some(100), Some(190)), "p50 100ms p99 190ms");
        assert_eq!(
            rtt_note(Some(100), Some(301)),
            "p50 100ms p99 301ms ⚠ p99 ≫ p50 — path degradation"
        );
        // The backoff note renders only with history.
        assert_eq!(backoff_note(None), "");
        assert_eq!(backoff_note(Some(0)), "");
        assert_eq!(backoff_note(Some(4)), " (max 4 today)");
    }

    #[test]
    fn credential_reading_tiers_and_boundaries() {
        let now = 1_760_000_000i64;
        let window = |span: i64, not_after_offset: i64| {
            (
                Some(now - span + not_after_offset),
                Some(now + not_after_offset),
            )
        };

        // Offline green: 45d of a 90d leaf.
        assert_eq!(
            credential_reading(
                window(90 * 86_400, 45 * 86_400).0,
                window(90 * 86_400, 45 * 86_400).1,
                now
            ),
            CredentialReading::Ok {
                mode: "offline",
                remaining_secs: 45 * 86_400
            }
        );
        // Offline yellow boundary: exactly 14d is still green; one
        // second less is yellow; 7d exact is still yellow; one less red.
        assert!(matches!(
            credential_reading(
                window(90 * 86_400, 14 * 86_400).0,
                window(90 * 86_400, 14 * 86_400).1,
                now
            ),
            CredentialReading::Ok { .. }
        ));
        assert!(matches!(
            credential_reading(
                window(90 * 86_400, 14 * 86_400 - 1).0,
                window(90 * 86_400, 14 * 86_400 - 1).1,
                now
            ),
            CredentialReading::Warn {
                mode: "offline",
                ..
            }
        ));
        assert!(matches!(
            credential_reading(
                window(90 * 86_400, 7 * 86_400).0,
                window(90 * 86_400, 7 * 86_400).1,
                now
            ),
            CredentialReading::Warn {
                mode: "offline",
                ..
            }
        ));
        assert!(matches!(
            credential_reading(
                window(90 * 86_400, 7 * 86_400 - 1).0,
                window(90 * 86_400, 7 * 86_400 - 1).1,
                now
            ),
            CredentialReading::Critical {
                mode: "offline",
                ..
            }
        ));
        // Registrar: span-relative phases (a 24h leaf aging past 20%/10%).
        let span = 24 * 3600;
        assert!(matches!(
            credential_reading(window(span, span / 2).0, window(span, span / 2).1, now),
            CredentialReading::Ok {
                mode: "registrar",
                ..
            }
        ));
        assert!(matches!(
            credential_reading(window(span, span / 10).0, window(span, span / 10).1, now),
            CredentialReading::Warn {
                mode: "registrar",
                ..
            }
        ));
        assert!(matches!(
            credential_reading(window(span, span / 20).0, window(span, span / 20).1, now),
            CredentialReading::Critical {
                mode: "registrar",
                ..
            }
        ));
        // Expired: the deepest critical, either tier.
        assert!(matches!(
            credential_reading(window(span, -1).0, window(span, -1).1, now),
            CredentialReading::Critical { .. }
        ));
        // Unknown: no window.
        assert_eq!(
            credential_reading(None, None, now),
            CredentialReading::Unknown
        );
    }

    #[test]
    fn headroom_reading_boundary_and_humanize() {
        // Unlimited scope: no wall, no reading.
        assert_eq!(headroom_reading(47, 0), None);
        // Exactly 20% remaining is not yet tight (the ratio is strict):
        // 50 of 250; one slot less is.
        assert_eq!(
            headroom_reading(200, 250).map(|r| r.tight),
            Some(false),
            "20% remaining is not yet tight (the ratio is strict)"
        );
        assert_eq!(headroom_reading(201, 250).map(|r| r.tight), Some(true));
        assert_eq!(
            headroom_reading(240, 256).map(|r| (r.remaining_pct, r.tight)),
            Some((6, true)),
            "the incremental-sessions shape: chronic growth visible before the wall"
        );
        // At the wall: zero remaining, still a reading.
        assert_eq!(headroom_reading(256, 256).map(|r| r.remaining_pct), Some(0));
        // The humanizer keeps day-scale ages readable.
        assert_eq!(humanize_secs(45), "45s");
        assert_eq!(humanize_secs(3_000), "50m");
        assert_eq!(humanize_secs(9_000), "2h 30m");
        assert_eq!(humanize_secs(12 * 86_400 + 7_200), "12d 2h");
    }

    #[test]
    fn queued_ops_reading_states_and_boundary() {
        use interflow_mesh::hub::stream_intents::MailboxFace;
        let now = 1_760_000_000i64;
        let face = |count: u32, oldest_age: u64, dropped: u64| MailboxFace {
            pending_count: count,
            oldest_queued_unix: Some((now - i64::try_from(oldest_age).unwrap()).cast_unsigned()),
            oldest_op: Some("pause ollama".to_owned()),
            dropped_total: dropped,
        };

        // Clear: no face at all (an older hub), or an empty history-only
        // block (drops but nothing waiting reads through the counter
        // alone — the reading is Clear, the drop line renders apart).
        assert_eq!(
            queued_ops_reading(None, false, now),
            QueuedOpsReading::Clear
        );
        // Offline + waiting: expected — the op rides the next check-in.
        assert_eq!(
            queued_ops_reading(Some(&face(1, 259_200, 0)), false, now),
            QueuedOpsReading::Waiting {
                count: 1,
                oldest_age_secs: 259_200,
                oldest_op: Some("pause ollama".to_owned()),
                stuck: false
            }
        );
        // Online + fresh: inside the delivery budget, not yet stuck.
        assert_eq!(
            queued_ops_reading(Some(&face(1, QUEUED_OPS_STUCK_AFTER_SECS, 0)), true, now),
            QueuedOpsReading::Waiting {
                count: 1,
                oldest_age_secs: QUEUED_OPS_STUCK_AFTER_SECS,
                oldest_op: Some("pause ollama".to_owned()),
                stuck: false,
            },
            "exactly the budget is a slow exchange, not a stuck one"
        );
        // Online + past the budget: the intent watcher is not consuming.
        assert_eq!(
            queued_ops_reading(
                Some(&face(2, QUEUED_OPS_STUCK_AFTER_SECS + 1, 0)),
                true,
                now
            ),
            QueuedOpsReading::Waiting {
                count: 2,
                oldest_age_secs: QUEUED_OPS_STUCK_AFTER_SECS + 1,
                oldest_op: Some("pause ollama".to_owned()),
                stuck: true
            }
        );
    }

    #[test]
    fn watchers_reading_states_and_boundary() {
        use interflow_mesh::hub::watchdog::WatcherFaceRow;
        let now = 1_760_000_000i64;
        let row = |name: &str, interval: u64, tick_age: u64| WatcherFaceRow {
            name: name.to_owned(),
            interval_secs: interval,
            started_unix: 1,
            last_tick_unix: (now - i64::try_from(tick_age).unwrap()).cast_unsigned(),
        };

        // Unknown: the face carries no rows (an older hub) — unjudgeable,
        // never "all armed".
        assert_eq!(watchers_reading(&[], now), WatchersReading::Unknown);
        // All armed: every row inside its own threshold.
        assert_eq!(
            watchers_reading(&[row("heartbeat", 15, 8), row("renewal", 60, 45)], now),
            WatchersReading::AllArmed {
                count: 2,
                freshest_age_secs: 8,
                oldest_age_secs: 45
            }
        );
        // The boundary is per-row: exactly 3× the row's OWN interval is a
        // slow pass…
        assert_eq!(
            watchers_reading(&[row("policy", 10, 30)], now),
            WatchersReading::AllArmed {
                count: 1,
                freshest_age_secs: 30,
                oldest_age_secs: 30
            }
        );
        // …one second past it is the wedged class — while a slower task
        // with the SAME tick age stays armed (the anchor is the row's own
        // cadence, never a global threshold).
        assert_eq!(
            watchers_reading(&[row("policy", 10, 31)], now),
            WatchersReading::Silent {
                armed: 0,
                silent: vec![("policy".to_owned(), 10, 31)]
            }
        );
        assert_eq!(
            watchers_reading(&[row("renewal", 60, 31)], now),
            WatchersReading::AllArmed {
                count: 1,
                freshest_age_secs: 31,
                oldest_age_secs: 31
            }
        );
        // Mixed: the silent row is named, the armed count keeps the rest.
        assert_eq!(
            watchers_reading(&[row("heartbeat", 15, 3), row("policy", 10, 45)], now),
            WatchersReading::Silent {
                armed: 1,
                silent: vec![("policy".to_owned(), 10, 45)]
            }
        );
    }

    #[test]
    fn policy_seen_reading_four_states_and_boundary() {
        use interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS as threshold;
        let now = 1_760_000_000i64;
        let pulled = |age: u64| Some((now - i64::try_from(age).unwrap()).cast_unsigned());

        // Current: at the serving generation, confirming recently.
        assert_eq!(
            policy_seen_reading(Some(15), pulled(8), Some(15), now),
            PolicySeenReading::Current {
                seen: 15,
                age_secs: Some(8)
            }
        );
        // Behind: pulling, below serving.
        assert_eq!(
            policy_seen_reading(Some(14), pulled(8), Some(15), now),
            PolicySeenReading::Behind {
                seen: 14,
                serving: 15,
                age_secs: Some(8)
            }
        );
        // Never: no completed pull — the one honest meaning left.
        assert_eq!(
            policy_seen_reading(None, None, Some(15), now),
            PolicySeenReading::Never
        );
        // The boundary: AT the threshold is not yet silent…
        assert_eq!(
            policy_seen_reading(Some(15), pulled(threshold), Some(15), now),
            PolicySeenReading::Current {
                seen: 15,
                age_secs: Some(threshold)
            }
        );
        // …one second past it is.
        assert_eq!(
            policy_seen_reading(Some(15), pulled(threshold + 1), Some(15), now),
            PolicySeenReading::Silent {
                seen: 15,
                age_secs: threshold + 1
            }
        );
        // An older hub (a watermark without the confirmation instant): the
        // value classifies, recency never guesses.
        assert_eq!(
            policy_seen_reading(Some(15), None, Some(15), now),
            PolicySeenReading::Current {
                seen: 15,
                age_secs: None
            }
        );
        assert_eq!(
            policy_seen_reading(Some(14), None, Some(15), now),
            PolicySeenReading::Behind {
                seen: 14,
                serving: 15,
                age_secs: None
            }
        );
        // And the rendered lines.
        assert_eq!(
            policy_seen_line(&PolicySeenReading::Current {
                seen: 15,
                age_secs: Some(8)
            }),
            "policy_seen=15 · pulled 8s ago"
        );
        assert_eq!(
            policy_seen_line(&PolicySeenReading::Silent {
                seen: 15,
                age_secs: 31
            }),
            "policy_seen=15 · silent 31s ⚠"
        );
        assert_eq!(
            policy_seen_line(&PolicySeenReading::Never),
            "policy_seen=never"
        );
    }

    /// Silent is a FAILURE only while the leg is present: an offline leg's
    /// quiet policy face is carried by the presence reading — the ⚠ and
    /// the exit code are reserved for "online but policy-dead".
    #[test]
    fn silent_policy_face_fails_only_online_legs() {
        use interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS as threshold;
        let now = 1_760_000_000i64;
        let last_pull = Some((now - i64::try_from(threshold + 1).unwrap()).cast_unsigned());

        let online_silent = doc_at(
            Some(15),
            vec![leg_recency("main/lan-a", true, Some(15), last_pull)],
            now,
        );
        assert!(
            render_hub_reading("hub:7443", &online_silent),
            "an online leg with a silent policy face fails the reading"
        );

        let offline_quiet = doc_at(
            Some(15),
            vec![leg_recency("main/lan-a", false, Some(15), last_pull)],
            now,
        );
        assert!(
            !render_hub_reading("hub:7443", &offline_quiet),
            "an offline leg does not double-fail through its policy face"
        );

        let online_current = doc_at(
            Some(15),
            vec![leg_recency(
                "main/lan-a",
                true,
                Some(15),
                Some(now.cast_unsigned()),
            )],
            now,
        );
        assert!(
            !render_hub_reading("hub:7443", &online_current),
            "a current, confirming leg stays green"
        );
    }

    // ----- the upgrade verdicts --------------------------------------------

    fn snapshot_pair(
        old_build: &str,
        new_build: &str,
        evicted_before: u64,
        evicted_after: u64,
    ) -> (FleetSnapshotDoc, FleetSnapshotDoc) {
        let mk = |build: &str, evicted: u64, online: bool| FleetSnapshotDoc {
            format_version: 1,
            hub: FleetSnapshotHub {
                crl_last_success_unix: None,
                crl_failures_total: None,
                crl_last_reload_unix: None,
                route_breakers_open: vec![],
                watchers: vec![],
                proposals_pending: None,
                streams_in_flight_total: None,
                stream_limits: None,
                node: None,
                serving_generation: Some(15),
                serving_source: Some(ServingSource::StateLineage),
                floor_generation: 15,
                evicted_total: evicted,
                crl_numbers: std::collections::BTreeMap::new(),
                captured_at_unix: 0,
            },
            agents: vec![FleetSnapshotAgent {
                crl_last_success_unix: None,
                crl_failures_total: None,
                pending_ops: None,
                streams_in_flight: None,
                streams: vec![],
                agent: "main/lan-a".into(),
                online,
                seen_generation: Some(15),
                last_pull_unix: None,
                build: Some(build.into()),
                transport: Some(interflow_mesh::hub::snapshot::SnapshotTransport::Quic),
                circuit: Some("ab".repeat(16)),
                paused_streams: None,
                maintenance: None,
                leaf_not_before_unix: None,
                leaf_not_after_unix: None,
                credential_mode: None,
                credential_last_seen_unix: None,
                connection: None,
                renewal_backoff_failures: None,
                renewal_backoff_max_today: None,
            }],
        };
        (
            mk(old_build, evicted_before, true),
            mk(new_build, evicted_after, true),
        )
    }

    /// The green acceptance: same string, zero dirty, steady window,
    /// stable legs, generation continuity, triple answered.
    #[test]
    fn upgrade_verdicts_green() {
        let (a, b) = snapshot_pair("2026-10-12_bf11cd8", "2026-10-12_bf11cd8", 0, 0);
        let diff = status::compare(&a, &b);
        let verdicts = upgrade_verdicts(&diff, Some(ProbeTriple::Answered));
        assert!(verdicts.iter().all(|(g, _)| g != &"✘"), "{verdicts:?}");
        assert!(verdicts.iter().any(|(_, l)| l.contains("zero dirty")));
        assert!(verdicts.iter().any(|(_, l)| l.contains("death window")));
    }

    /// The membership scanner against a REAL signed CRL: hits name the
    /// revoked serial, unparseable material is surfaced (never absorbed
    /// into "clean"), and a parsed CRL with no matching entry stays clean.
    #[test]
    fn scan_crls_hits_flags_unparseable_and_stays_clean() {
        let dir = tempfile::tempdir().unwrap();
        let store = interflow_identity::issuance::IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        let mut list = interflow_identity::revocation::RevocationList::default();
        list.record(interflow_identity::revocation::RevocationEntry {
            serial: "00ff".to_owned(),
            issuer: "control".to_owned(),
            reason: "key-compromise".to_owned(),
            revoked_at: "2026-10-13T00:00:00Z".to_owned(),
            pack_digest: None,
        });
        let crl = interflow_identity::revocation::build_crl(
            &store.realm_issuer().unwrap(),
            &list.entries,
            list.next_crl_number,
        )
        .unwrap();
        let label = "issuer CRL test".to_owned();

        // Revoked serial hits; the untouched one does not.
        let (hits, bad) = scan_crls(
            &["00ff".to_owned(), "00ee".to_owned()],
            &[(label.clone(), crl.clone())],
        );
        assert_eq!(hits.len(), 1, "exactly the revoked serial: {hits:?}");
        assert!(hits[0].contains("00ff") && hits[0].contains(&label));
        assert_eq!(bad.len(), 0);

        // Nothing revoked at all: clean with no unparseable material.
        let (hits, bad) = scan_crls(&["00ee".to_owned()], &[(label.clone(), crl.clone())]);
        assert!(hits.is_empty() && bad.is_empty());

        // Unparseable material surfaces — "cannot judge", never "clean".
        let (hits, bad) = scan_crls(
            &["00ee".to_owned()],
            &[(label, crl), ("bogus".to_owned(), "not a crl".to_owned())],
        );
        assert_eq!(hits.len(), 0);
        assert_eq!(bad.len(), 1, "the bogus CRL is named: {bad:?}");
    }

    /// Each failure mode flips exactly its own verdict line.
    #[test]
    fn upgrade_verdicts_flag_each_failure() {
        // Mixed strings.
        let (a, b) = snapshot_pair("2026-10-11_b9aab4a", "2026-10-12_bf11cd8", 0, 0);
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), None);
        // Same agent upgraded → one build string; mixed requires two legs.
        assert!(verdicts.iter().any(|(g, _)| g == &"✔"), "{verdicts:?}");

        // Dirty build.
        let (a, b) = snapshot_pair("2026-10-12_bf11cd8", "2026-10-12_bf11cd8-dirty", 0, 0);
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), None);
        assert!(
            verdicts
                .iter()
                .any(|(g, l)| g == &"✘" && l.contains("amber")),
            "{verdicts:?}"
        );

        // Evictions landed.
        let (a, b) = snapshot_pair("x", "x", 0, 1);
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), None);
        assert!(
            verdicts
                .iter()
                .any(|(g, l)| g == &"✘" && l.contains("evictions landed")),
            "{verdicts:?}"
        );

        // A leg went offline.
        let (a, b) = snapshot_pair("x", "x", 0, 0);
        let mut b = b;
        b.agents[0].online = false;
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), None);
        assert!(
            verdicts
                .iter()
                .any(|(g, l)| g == &"✘" && l.contains("online legs moved")),
            "{verdicts:?}"
        );

        // The probe triple failed.
        let (a, b) = snapshot_pair("x", "x", 0, 0);
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), Some(ProbeTriple::Failed));
        assert!(
            verdicts
                .iter()
                .any(|(g, l)| g == &"✘" && l.contains("timeout ≠ reset")),
            "{verdicts:?}"
        );
    }
}
