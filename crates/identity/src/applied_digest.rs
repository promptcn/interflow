//! The identity-face digest: which parts of a [`Manifest`] the applied
//! baseline's `stripped_manifest_digest` covers.
//!
//! The digest answers one question for `plan apply` / `plan diff`: "did the
//! identity/trust/dial face of the declaration move since the last apply?"
//! Everything the signed policy carries (mesh rules, services, routes —
//! hot-applied by every node kind) is emptied before hashing, so a
//! policy-only edit leaves the digest alone and takes the policy-only fast
//! path, while any other edit re-renders every pack.
//!
//! The digest is a cache of the applied declaration snapshot, not a truth
//! of its own: when it disagrees with a freshly computed one, the two
//! declaration texts are compared under this same rule (`plan`'s snapshot
//! arbitration) — so the rule needs no version label. Evolving the rule is
//! safe by construction: the same text, stripped by the same rule,
//! compares equal whatever the recorded digest was produced by.

use crate::manifest::Manifest;
use crate::{Error, Result};

/// The digest of `manifest` with its policy face emptied: `sha256:<hex>`
/// of the canonical JSON of the stripped manifest.
pub fn identity_face_digest(manifest: &Manifest) -> Result<String> {
    let mut stripped = manifest.clone();
    strip_policy_face(&mut stripped);
    let text = serde_json::to_string(&stripped)
        .map_err(|e| Error::serialize("manifest serialization").with_source(e))?;
    Ok(format!(
        "sha256:{}",
        interflow_util::sha256_hex(text.as_bytes())
    ))
}

/// Empties the policy material the identity face does not count: mesh rule
/// lists, each agent's services, and the top-level routes — the whole
/// hot-applied policy face.
fn strip_policy_face(manifest: &mut Manifest) {
    for agent in manifest.agent.values_mut() {
        agent.mesh_ingress.clear();
        agent.mesh_egress.clear();
        agent.services.clear();
    }
    manifest.route.clear();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The strip is exactly the policy face: editing policy material is
    /// invisible to the digest, editing identity material is not.
    #[test]
    fn the_strip_covers_exactly_the_policy_face() {
        let text = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com"

[identity]
mode = "offline"
leaf_ttl = "90d"

[ingress.edge]
workspaces = ["main"]

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;
        let manifest = Manifest::parse(text).unwrap();
        let digest = identity_face_digest(&manifest).unwrap();
        assert!(digest.starts_with("sha256:"));

        // Removing the policy material from the declaration itself changes
        // nothing — the strip empties it either way.
        let mut bare = manifest.clone();
        bare.agent.get_mut("desktop").unwrap().services.clear();
        bare.route.clear();
        assert_eq!(identity_face_digest(&bare).unwrap(), digest);

        // A service edit alone is policy-only: invisible to the face.
        let mut service_moved = manifest.clone();
        service_moved.agent.get_mut("desktop").unwrap().services[0].address =
            "127.0.0.1:8081".into();
        assert_eq!(identity_face_digest(&service_moved).unwrap(), digest);

        // An identity-face edit is visible.
        let mut renamed = manifest;
        renamed.realm.id = "other".into();
        assert_ne!(identity_face_digest(&renamed).unwrap(), digest);
    }
}
