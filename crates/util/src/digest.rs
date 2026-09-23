//! Content digests — lowercase-hex SHA-256, the fingerprint form used by
//! pack manifests (`SHA256SUMS`), trust bundles, issuer fingerprints, and
//! pinned-verifier cert pins.

use sha2::{Digest, Sha256};

/// Lowercase-hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn matches_known_vector() {
        // SHA-256("abc"), FIPS 180-4 test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
