//! Sealed pack distribution: the `.iflowpack` format (age-encrypted tar).
//!
//! [`seal`] turns a rendered pack directory into one distributable file;
//! [`install`] decrypts + verifies it into a runtime directory and returns
//! the loaded [`CredentialPack`].

use super::CredentialPack;
use crate::{Error, Result};
use age::Encryptor;
use std::io::{Read, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Sealed distribution format (.iflowpack = age-encrypted tar)
// ---------------------------------------------------------------------------

/// How to open the age encryption.
#[derive(Debug, Clone)]
pub enum SealKey {
    Passphrase(String),
    /// age X25519 recipient string (`age1...`) for sealing.
    Recipient(String),
}

/// A freshly generated sealing passphrase: 18 random bytes as 24 base64url
/// characters (144 bits) — at or above the strength of a human-chosen one,
/// with none of the reuse habits. CLI `pack seal --generate-passphrase` and
/// the GUI issue wizard share this one source, so both surfaces seal with
/// the same entropy.
pub fn generate_passphrase() -> Result<String> {
    let mut bytes = [0u8; 18];
    // `getrandom::Error` does not implement `std::error::Error`, so the
    // message is the only place the cause can surface.
    getrandom::fill(&mut bytes).map_err(|e| Error::pack(format!("passphrase entropy: {e}")))?;
    // 18 bytes = 6 × 3-byte groups → exactly 24 chars, no padding.
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(24);
    for group in 0..6 {
        let base = group * 3;
        let n = (u32::from(bytes[base]) << 16)
            | (u32::from(bytes[base + 1]) << 8)
            | u32::from(bytes[base + 2]);
        out.push(URL_SAFE[(n >> 18 & 0x3f) as usize] as char);
        out.push(URL_SAFE[(n >> 12 & 0x3f) as usize] as char);
        out.push(URL_SAFE[(n >> 6 & 0x3f) as usize] as char);
        out.push(URL_SAFE[(n & 0x3f) as usize] as char);
    }
    Ok(out)
}

/// Seals a pack directory into `.iflowpack`.
pub fn seal(pack_dir: &Path, out_file: &Path, key: &SealKey) -> Result<()> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for entry in std::fs::read_dir(pack_dir).map_err(|e| Error::Io {
            path: pack_dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::Io {
                path: pack_dir.display().to_string(),
                source: e,
            })?;
            let rel = entry.file_name();
            if rel == "state" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                builder
                    .append_dir_all(&rel, &path)
                    .map_err(|e| Error::pack(format!("pack tar entry {rel:?}")).with_source(e))?;
            } else {
                builder
                    .append_path_with_name(&path, &rel)
                    .map_err(|e| Error::pack(format!("pack tar entry {rel:?}")).with_source(e))?;
            }
        }
        builder
            .into_inner()
            .map_err(|e| Error::pack("pack tar finish".to_string()).with_source(e))?;
    }
    let out = std::fs::File::create(out_file).map_err(|e| Error::Io {
        path: out_file.display().to_string(),
        source: e,
    })?;
    let mut writer = std::io::BufWriter::new(out);
    let encryptor = match key {
        SealKey::Passphrase(p) => Encryptor::with_user_passphrase(p.to_owned().into()),
        SealKey::Recipient(r) => {
            use std::str::FromStr as _;
            let recipient = age::x25519::Recipient::from_str(r)
                .map_err(|e| Error::pack("age recipient".to_string()).with_source(e))?;
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| Error::pack("age recipients".to_string()).with_source(e))?
        }
    };
    let mut wrapper = encryptor
        .wrap_output(&mut writer)
        .map_err(|e| Error::pack("age encryption".to_string()).with_source(e))?;
    wrapper
        .write_all(&tar_bytes)
        .map_err(|e| Error::pack("age write".to_string()).with_source(e))?;
    wrapper
        .finish()
        .map_err(|e| Error::pack("age finish".to_string()).with_source(e))?;
    writer
        .flush()
        .map_err(|e| Error::pack("age flush".to_string()).with_source(e))?;
    Ok(())
}

/// Installs a sealed pack: decrypt → unpack to `out_dir` → full validation.
pub fn install(sealed: &Path, out_dir: &Path, passphrase: &str) -> Result<CredentialPack> {
    let bytes = std::fs::read(sealed).map_err(|e| Error::Io {
        path: sealed.display().to_string(),
        source: e,
    })?;
    let decryptor = age::Decryptor::new_buffered(&bytes[..])
        .map_err(|e| Error::pack("sealed pack format".to_string()).with_source(e))?;
    if !decryptor.is_scrypt() {
        return Err(Error::pack(
            "this sealed pack targets key recipients; supply the identity via \
             `interflow pack install --identity`"
                .to_owned(),
        ));
    }
    let identity = age::scrypt::Identity::new(passphrase.to_owned().into());
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| Error::pack("sealed pack decryption failed".to_string()).with_source(e))?;
    let mut tar_bytes = Vec::new();
    reader
        .read_to_end(&mut tar_bytes)
        .map_err(|e| Error::pack("sealed pack read".to_string()).with_source(e))?;
    if out_dir.exists() {
        return Err(Error::pack(format!(
            "install target {} already exists — move it aside first",
            out_dir.display()
        )));
    }
    std::fs::create_dir_all(out_dir).map_err(|e| Error::Io {
        path: out_dir.display().to_string(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(&tar_bytes[..]);
    archive
        .unpack(out_dir)
        .map_err(|e| Error::pack("sealed pack unpack".to_string()).with_source(e))?;
    // Security: tighten everything, then validate before returning.
    tighten_dir(out_dir)?;
    CredentialPack::load(out_dir)
}

fn tighten_dir(dir: &Path) -> Result<()> {
    fn walk(dir: &Path) -> Result<()> {
        for entry in std::fs::read_dir(dir).map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::Io {
                path: dir.display().to_string(),
                source: e,
            })?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path)?;
            } else if path.extension().is_some_and(|e| e == "key") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&path)
                        .map_err(|e| Error::Io {
                            path: path.display().to_string(),
                            source: e,
                        })?
                        .permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(&path, perms).map_err(|e| Error::Io {
                        path: path.display().to_string(),
                        source: e,
                    })?;
                }
            }
        }
        Ok(())
    }
    walk(dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::generate_passphrase;

    /// 24 base64url characters, twice-generated values differ (fresh OS
    /// entropy, not a fixed seed).
    #[test]
    fn generated_passphrases_are_24_url_safe_chars() {
        let a = generate_passphrase().unwrap();
        let b = generate_passphrase().unwrap();
        assert_eq!(a.len(), 24, "18 bytes → 24 base64url chars, no padding");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "url-safe alphabet only: {a}"
        );
        assert_ne!(a, b, "two draws must not collide");
    }
}
