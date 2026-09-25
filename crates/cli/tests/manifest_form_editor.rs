//! The form editor's acceptance path against the real deployment file:
//! the promptcn site-to-site manifest (comment-heavy, the comments are
//! load-bearing operator documentation) loads into the document model,
//! takes a structured edit, and comes back with every comment intact and
//! the document still valid.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use interflow_cli::manifest_edit::{self, ManifestEdit, MeshEgressEdit, MeshIngressEdit};
use interflow_identity::manifest::{Manifest, MeshProtocol};

/// Every comment line, in order — the invariant the editor owes the file.
fn comment_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.trim_start().starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn site_to_site_manifest_takes_structured_edits_with_comments_intact() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("cli crate at <workspace>/crates/cli")
        .join("deployments/promptcn/site-to-site/interflow.toml");
    let original = std::fs::read_to_string(&path).unwrap();
    Manifest::parse(&original).expect("the shipped site-to-site manifest is valid");

    // The 2026-09-25 operator flow, expressed as form edits: tune the ASR
    // rule's idle budget, and add a new ingress rule against the peer's
    // loopback-range egress — both land with the funnel satisfied.
    let tuned = manifest_edit::apply_edit(
        &original,
        &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
            agent: "leo-mesh".into(),
            name: "asr".into(),
            listen: "127.0.0.1:8056".into(),
            protocol: MeshProtocol::Tcp,
            target_agent: "home-win".into(),
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
            agent: "leo-mesh".into(),
            name: "acceptance-probe".into(),
            listen: "127.0.0.1:19999".into(),
            protocol: MeshProtocol::Tcp,
            target_agent: "home-win".into(),
            remote_addr: "127.0.0.1:19999".into(),
            idle_timeout_secs: None,
        }),
    )
    .unwrap();
    let manifest = Manifest::parse(&added).unwrap();
    assert_eq!(
        manifest.agent["leo-mesh"]
            .mesh_ingress
            .iter()
            .filter(|rule| rule.name == "acceptance-probe")
            .count(),
        1,
        "the new rule appends inside leo-mesh's list"
    );

    // The document model's core promise for this file: the comments — the
    // blast-radius tradeoffs, the idle-budget rationale — are the operator
    // documentation; every one of them survives both edits.
    assert_eq!(
        comment_lines(&original),
        comment_lines(&added),
        "every comment of the real deployment survives a tune + an add"
    );

    // The read model reports the edited document as applyable.
    let summary = manifest_edit::summarize(&added).unwrap();
    assert!(summary.issues.is_empty(), "{:?}", summary.issues);

    // Removing the probe returns the file to its shipped rule set (the
    // probe's own lines go with it; the shipped comments stay).
    let removed = manifest_edit::apply_edit(
        &added,
        &ManifestEdit::RemoveMeshIngress {
            agent: "leo-mesh".into(),
            name: "acceptance-probe".into(),
        },
    )
    .unwrap();
    assert_eq!(
        comment_lines(&original),
        comment_lines(&removed),
        "comments survive the removal too"
    );
    assert!(
        !removed.contains("acceptance-probe"),
        "the probe is gone: {removed}"
    );

    // Egress edits ride the same path: the loopback-range authorization is
    // the peer-side pairing every ingress above relies on.
    let egress = manifest_edit::apply_edit(
        &removed,
        &ManifestEdit::UpsertMeshEgress(MeshEgressEdit {
            agent: "home-win".into(),
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
