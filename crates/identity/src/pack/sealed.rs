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
