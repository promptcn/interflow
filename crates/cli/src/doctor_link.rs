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
use std::io::Write as _;
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
/// with a Version Negotiation packet. DCID carried for the response's
/// correlation (any nonzero value works for the probe).
pub fn version_negotiation_trigger(dcid: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14);
    packet.extend_from_slice(&[0xc0]); // long header, type bits zeroed
    packet.extend_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]); // unknown version
    packet.push(u8::try_from(dcid.len()).unwrap_or(8)); // DCID length
    packet.extend_from_slice(dcid);
    packet.push(0); // empty SCID
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
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return HttpVerdict::Refused;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return HttpVerdict::Error("write failed".to_owned());
    }
    let mut buf = [0u8; 256];
    match std::io::Read::read(&mut stream, &mut buf) {
        Ok(0) => HttpVerdict::Error("the stream closed without a response".to_owned()),
        Ok(n) => HttpVerdict::Answered(
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
        ),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            HttpVerdict::Timeout
        }
        Err(e) => HttpVerdict::Error(e.to_string()),
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
    if doc.hub.evicted_total > 0 {
        outln!(
            "  note: evictions have landed this run — correlate with the journal: \
             journalctl -u <hub> | grep -E 'evicted|eviction voided'"
        );
    }
    outln!();
    outln!("legs:");
    for leg in &doc.agents {
        let glyph = if leg.online { "✔" } else { "·" };
        let transport = match leg.transport {
            Some(SnapshotTransport::Quic) => "quic",
            Some(SnapshotTransport::H2) => "h2",
            None => "-",
        };
        let build = leg.build.as_deref().unwrap_or("unknown build");
        let circuit = leg.circuit.as_deref().map_or("-", |c| &c[..8.min(c.len())]);
        let seen = leg
            .seen_generation
            .map_or_else(|| "never".to_owned(), |g| g.to_string());
        outln!(
            "{glyph} {} online={} transport={} build={} circuit={}… policy_seen={}",
            leg.agent,
            leg.online,
            transport,
            build,
            circuit,
            seen
        );
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
                Some(true)
            } else {
                outln!(
                    "✘ the data-plane triple failed ({}) — timeout ≠ reset: a timeout means \
                     the request entered but nothing answered (check the far-end service \
                     first); a reset means the path or the far end refused",
                    failures.join(", ")
                );
                Some(false)
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

/// The acceptance verdicts over a before/after diff — pure, unit-tested.
/// `(glyph, line)` pairs; `probes` is `None` when the triple was skipped.
pub fn upgrade_verdicts(
    diff: &status::SnapshotDiff,
    probes: Option<bool>,
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
    // 3. Online stability.
    let (before, after) = diff.online_leg_counts();
    let went_offline: Vec<&str> = diff
        .agents
        .iter()
        .filter(|a| a.presence == status::PresenceChange::WentOffline)
        .map(|a| a.agent.as_str())
        .collect();
    if before == after && went_offline.is_empty() {
        out.push(("✔", format!("online legs stable ({before} → {after})")));
    } else {
        out.push((
            "✘",
            format!(
                "online legs moved ({before} → {after}){} — a leg still down after the \
                 window: check its journal before anything else",
                if went_offline.is_empty() {
                    String::new()
                } else {
                    format!("; offline: {}", went_offline.join(", "))
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
        Some(true) => out.push((
            "✔",
            "data-plane triple 0s/+60s/+180s all answered — crossed the 30-40s death \
             window"
                .to_owned(),
        )),
        Some(false) => out.push((
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
        FleetSnapshotDoc {
            format_version: 1,
            hub: FleetSnapshotHub {
                node: Some("promptcn".into()),
                serving_generation: serving,
                serving_source: serving.map(|_| ServingSource::StateLineage),
                floor_generation: serving.unwrap_or(0),
                evicted_total: 0,
                crl_numbers: std::collections::BTreeMap::new(),
                captured_at_unix: 0,
            },
            agents: rows,
        }
    }

    fn leg(agent: &str, online: bool, seen: Option<u64>) -> FleetSnapshotAgent {
        FleetSnapshotAgent {
            agent: agent.to_owned(),
            online,
            seen_generation: seen,
            build: Some("2026-10-12_bf11cd8".into()),
            transport: Some(interflow_mesh::hub::snapshot::SnapshotTransport::Quic),
            circuit: Some("ab".repeat(16)),
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
                node: None,
                serving_generation: Some(15),
                serving_source: Some(ServingSource::StateLineage),
                floor_generation: 15,
                evicted_total: evicted,
                crl_numbers: std::collections::BTreeMap::new(),
                captured_at_unix: 0,
            },
            agents: vec![FleetSnapshotAgent {
                agent: "main/lan-a".into(),
                online,
                seen_generation: Some(15),
                build: Some(build.into()),
                transport: Some(interflow_mesh::hub::snapshot::SnapshotTransport::Quic),
                circuit: Some("ab".repeat(16)),
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
        let verdicts = upgrade_verdicts(&diff, Some(true));
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
        assert!(bad.is_empty());

        // Nothing revoked at all: clean with no unparseable material.
        let (hits, bad) = scan_crls(&["00ee".to_owned()], &[(label.clone(), crl.clone())]);
        assert!(hits.is_empty() && bad.is_empty());

        // Unparseable material surfaces — "cannot judge", never "clean".
        let (hits, bad) = scan_crls(
            &["00ee".to_owned()],
            &[(label, crl), ("bogus".to_owned(), "not a crl".to_owned())],
        );
        assert!(hits.is_empty());
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
        let verdicts = upgrade_verdicts(&status::compare(&a, &b), Some(false));
        assert!(
            verdicts
                .iter()
                .any(|(g, l)| g == &"✘" && l.contains("timeout ≠ reset")),
            "{verdicts:?}"
        );
    }
}
