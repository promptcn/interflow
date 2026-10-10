//! The form editor's acceptance path against a comment-dense operator
//! document: a dedicated fictional mesh manifest, designed from the
//! stress profile of real operator-maintained files — dated rationale
//! blocks, comment-only lines between rules, trailing comments on
//! values, a non-default idle budget — the shapes that break naive
//! editors. The document loads into the document model, takes a
//! structured edit, and comes back with every comment intact and the
//! document still valid. Every identifier is fictional.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use interflow_cli::manifest_edit::{self, ManifestEdit, MeshEgressEdit, MeshIngressEdit};
use interflow_identity::manifest::{Manifest, MeshProtocol};

/// A fictional three-node mesh in the voice of a real operator file:
/// decisions and their dates live in the comments, and the comments are
/// the document — the editor must never eat one.
const CORPUS: &str = r#"# Homelab mesh manifest — the single entry point for identity and trust.
#
# `interflow-cli plan apply` (run on the operator machine) issues the
# hub and agent Credential Packs from this file; nodes start from
# their pack and nothing else. No hand-written engine TOML, no
# hand-rolled openssl — trust, identity, and admission policy all
# travel inside the signed material.
#
# Topology (2026-01-12): the workstation reaches two peer machines
# through a public hub — the home server holds the model stack, the
# loaner laptop holds the portal and metrics scrapers. The hub rides a
# dedicated public port with mTLS admission; there is no fronting
# proxy on this face.
#
# Adding or removing a service is a policy-level operation (see the
# dated notes on the rules below): edit the rule, re-run apply. When
# the identity plane is untouched only the next policy generation is
# signed and published — online agents pick it up within seconds,
# nothing is re-issued, nobody touches a machine.

[realm]
id = "atlas-mesh"

# Offline tier: single operator, no registrar — long-lived leaves with
# a manual rotate roughly halfway through their lifetime. The peers
# are unattended for weeks at a time, so the rotate cadence is set by
# the calendar, not by certificate anxiety.
[identity]
mode = "offline"
leaf_ttl = "90d"

# The public hub. The endpoint is the dial address the agents carry;
# the hub certificate's SAN derives from it, so changing it later is
# an identity-plane operation (rotate), not an edit.
[mesh.hub.atlas]
listen = "0.0.0.0:6666"
quic_listen = "0.0.0.0:6666"                    # same port number as TCP, different stack
endpoint = "mesh.example.com:6666"

[workspace.main]

# The workstation — mesh ingress side. Named by role, not by host: the
# expose-face deployment of the same machine uses a different agent
# name, so one machine can hold two roles without muddying the audit
# trail.
[agent.workstation]
workspace = "main"
transport = "quic"    # dial the hub's QUIC face; effective after the next pack rotate

# Local 11434 → through the hub to the home server's model API. If a
# local instance ever squats on 11434 it must be stopped first; the
# rule itself never conflicts, the port does.
[[agent.workstation.mesh_ingress]]
name = "llm"
listen = "127.0.0.1:11434"
target_agent = "home-server"
remote_addr = "127.0.0.1:11434"

# Speech synthesis front-end (2026-01-19). Adding this used to be a
# re-issue-everything operation; now it is one rule plus apply.
[[agent.workstation.mesh_ingress]]
name = "speech"
listen = "127.0.0.1:8055"
target_agent = "home-server"
remote_addr = "127.0.0.1:8055"

# Transcription (2026-01-25). Same policy-level shape as speech, but
# the idle budget is the interesting part: transcription connections
# carry zero bytes while a long audio segment is processed
# server-side, and a single GPU queues segments serially at roughly
# five minutes each. A silent, non-streaming long request is exactly
# what the default five-minute budget would cut; raised to thirty
# minutes (legal range 1s–24h).
[[agent.workstation.mesh_ingress]]
name = "transcribe"
listen = "127.0.0.1:8056"
target_agent = "home-server"
remote_addr = "127.0.0.1:8056"
idle_timeout_secs = 1800

# Portal on the loaner laptop (2026-02-02): the entry port sits on a
# different number than the service on purpose, to keep the home-server
# ranges and the laptop ranges from colliding in muscle memory.
[[agent.workstation.mesh_ingress]]
name = "portal"
listen = "127.0.0.1:9091"
target_agent = "lab-laptop"
remote_addr = "127.0.0.1:9090"
# Idle stays at the default (2026-02-03 post-mortem): the portal is a
# request-response dev server; a raised budget would only turn fast
# failures into half-hour hangs. Raise it only with cut-stream logs
# naming this rule as evidence.

# Metrics scraper passthrough (2026-02-10), same port number on both
# sides. Request-response traffic; default budget unless the scrape
# logs say otherwise.
[[agent.workstation.mesh_ingress]]
name = "metrics"
listen = "127.0.0.1:8849"
target_agent = "lab-laptop"
remote_addr = "127.0.0.1:8849"

# The home server — mesh egress side. The loopback-wide authorization
# is a deliberate trade-off, recorded here so future-us re-derives it
# instead of re-guessing: authorizing the whole loopback range (any
# port) means adding a service later is a workstation-side rule plus
# apply, with zero action on this machine — at the cost of widening a
# leaked pack's blast radius from one port to every loopback service.
# Nothing sensitive beyond the mesh stack listens on this machine's
# loopback; judged acceptable. To tighten later, swap the CIDR for
# per-port addresses and apply once — same policy-level path. The
# validator rejects catch-all and SSRF-reserved ranges, so the
# authorization can never silently widen beyond what is written here.
[agent.home-server]
workspace = "main"
transport = "quic"    # dual-stack transition: runs h2 until the rotated pack lands

[[agent.home-server.mesh_egress]]
name = "loopback-services"
target_cidr = "127.0.0.0/8"

# The loaner laptop — mesh egress side, same loopback-wide tier as the
# home server. Physical control is weaker (it travels), so its pack
# only ever moves over a trusted channel and rotates on the same
# calendar as everything else.
[agent.lab-laptop]
workspace = "main"
transport = "quic"    # joined after the QUIC face opened; no h2 legacy

[[agent.lab-laptop.mesh_egress]]
name = "loopback-services"
target_cidr = "127.0.0.0/8"

# Flow idle budget reference: the default is five minutes of silence
# in both directions. Streaming traffic never sees it; silent
# non-streaming requests get the per-rule override above. When a
# budget cuts a stream, the ingress log names the rule and the value
# in force — no journal archaeology required.
"#;

/// Every comment line, in order — the invariant the editor owes the file.
fn comment_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.trim_start().starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn comment_dense_manifest_takes_structured_edits_with_comments_intact() {
    Manifest::parse(CORPUS).expect("the corpus manifest is valid");

    // The 2026-01-25 operator flow, expressed as form edits: tune the
    // transcription rule's idle budget, and add a new ingress rule
    // against the peer's loopback-range egress — both land with the
    // funnel satisfied.
    let tuned = manifest_edit::apply_edit(
        CORPUS,
        &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
            agent: "workstation".into(),
            name: "transcribe".into(),
            listen: "127.0.0.1:8056".into(),
            protocol: MeshProtocol::Tcp,
            target_agent: "home-server".into(),
            remote_addr: "127.0.0.1:8056".into(),
            idle_timeout_secs: Some(3600),
        }),
    )
    .unwrap();
    assert!(
        tuned.contains("idle_timeout_secs = 3600"),
        "the tuned budget lands: {tuned}"
    );

    let added = manifest_edit::apply_edit(
        &tuned,
        &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
            agent: "workstation".into(),
            name: "acceptance-probe".into(),
            listen: "127.0.0.1:19999".into(),
            protocol: MeshProtocol::Tcp,
            target_agent: "home-server".into(),
            remote_addr: "127.0.0.1:19999".into(),
            idle_timeout_secs: None,
        }),
    )
    .unwrap();
    let manifest = Manifest::parse(&added).unwrap();
    assert_eq!(
        manifest.agent["workstation"]
            .mesh_ingress
            .iter()
            .filter(|rule| rule.name == "acceptance-probe")
            .count(),
        1,
        "the new rule appends inside workstation's list"
    );

    // The document model's core promise for this file: the comments —
    // the blast-radius tradeoffs, the idle-budget rationale — are the
    // operator documentation; every one of them survives both edits.
    assert_eq!(
        comment_lines(CORPUS),
        comment_lines(&added),
        "every comment of the operator document survives a tune + an add"
    );

    // The read model reports the edited document as applyable.
    let summary = manifest_edit::summarize(&added).unwrap();
    assert!(summary.issues.is_empty(), "{:?}", summary.issues);

    // Removing the probe returns the file to its shipped rule set (the
    // probe's own lines go with it; the operator comments stay).
    let removed = manifest_edit::apply_edit(
        &added,
        &ManifestEdit::RemoveMeshIngress {
            agent: "workstation".into(),
            name: "acceptance-probe".into(),
        },
    )
    .unwrap();
    assert_eq!(
        comment_lines(CORPUS),
        comment_lines(&removed),
        "comments survive the removal too"
    );
    assert!(
        !removed.contains("acceptance-probe"),
        "the probe is gone: {removed}"
    );

    // Egress edits ride the same path: the loopback-range authorization
    // is the peer-side pairing every ingress above relies on.
    let egress = manifest_edit::apply_edit(
        &removed,
        &ManifestEdit::UpsertMeshEgress(MeshEgressEdit {
            agent: "home-server".into(),
            name: "loopback-services".into(),
            protocol: MeshProtocol::Tcp,
            target_addr: None,
            target_cidr: Some("127.0.0.0/8".into()),
            udp_idle_timeout_secs: None,
        }),
    )
    .unwrap();
    assert_eq!(
        egress, removed,
        "re-applying the same egress rule is a no-op"
    );
}
