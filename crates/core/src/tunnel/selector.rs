//! Encrypted stream selector exchanged after inner TLS establishment.
//!
//! The hub routes only opaque stream identities. The LAN target is deliberately
//! absent from the wire Open frame; this frame is the first application bytes
//! on the inner TLS stream and is therefore confidential and authenticated by
//! the peer certificate.

use crate::error::{InterflowError, Result};
use interflow_contract::FORMAT_VERSION;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAGIC: &[u8; 8] = b"IFSTREAM";
const MAX_VALUE_LEN: usize = 2048;
const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + 2 + 32 + 16;

/// How the target egress chooses its LAN backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelector {
    /// Use the only rule matching the stream protocol.
    Default,
    /// Use an explicit host:port supplied by the authenticated initiating principal.
    Address(String),
    /// Use the local egress rule whose name/service id exactly matches.
    Service(String),
}

/// Post-handshake stream metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerStreamHello {
    pub source_principal: String,
    pub source_fingerprint: [u8; 32],
    pub selector: TargetSelector,
    pub correlation_id: [u8; 16],
}

impl InnerStreamHello {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.source_principal.len() > MAX_VALUE_LEN {
            return Err(InterflowError::protocol(
                "inner hello principal is too long",
            ));
        }
        let value = match &self.selector {
            TargetSelector::Default => "",
            TargetSelector::Address(v) | TargetSelector::Service(v) => v,
        };
        if value.len() > MAX_VALUE_LEN {
            return Err(InterflowError::protocol("inner hello selector is too long"));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + value.len());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(match self.selector {
            TargetSelector::Default => 0,
            TargetSelector::Address(_) => 1,
            TargetSelector::Service(_) => 2,
        });
        out.extend_from_slice(&self.correlation_id);
        out.extend_from_slice(&self.source_fingerprint);
        out.extend_from_slice(
            &(u16::try_from(self.source_principal.len()).unwrap_or(0)).to_be_bytes(),
        );
        out.extend_from_slice(self.source_principal.as_bytes());
        out.extend_from_slice(&(u16::try_from(value.len()).unwrap_or(0)).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
            return Err(InterflowError::protocol("invalid inner hello header"));
        }
        let mut pos = MAGIC.len();
        let version = bytes[pos];
        pos += 1;
        let selector_kind = bytes[pos];
        pos += 1;
        if version != FORMAT_VERSION || selector_kind > 2 {
            return Err(InterflowError::protocol("unsupported inner hello"));
        }
        let mut correlation_id = [0u8; 16];
        correlation_id.copy_from_slice(&bytes[pos..pos + 16]);
        pos += 16;
        let mut source_fingerprint = [0u8; 32];
        source_fingerprint.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let principal_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if principal_len > MAX_VALUE_LEN || bytes.len() < pos + principal_len + 2 {
            return Err(InterflowError::protocol("invalid inner hello principal"));
        }
        let source_principal = std::str::from_utf8(&bytes[pos..pos + principal_len])
            .map_err(|_| InterflowError::protocol("inner hello principal is not UTF-8"))?
            .to_owned();
        pos += principal_len;
        let value_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if value_len > MAX_VALUE_LEN || bytes.len() != pos + value_len {
            return Err(InterflowError::protocol("invalid inner hello selector"));
        }
        let value = std::str::from_utf8(&bytes[pos..])
            .map_err(|_| InterflowError::protocol("inner hello selector is not UTF-8"))?
            .to_owned();
        let selector = match selector_kind {
            0 if value.is_empty() => TargetSelector::Default,
            1 if !value.is_empty() => TargetSelector::Address(value),
            2 if !value.is_empty() => TargetSelector::Service(value),
            _ => return Err(InterflowError::protocol("invalid inner hello selector")),
        };
        Ok(Self {
            source_principal,
            source_fingerprint,
            selector,
            correlation_id,
        })
    }

    pub async fn write<T>(&self, io: &mut T) -> io::Result<()>
    where
        T: AsyncWriteExt + Unpin,
    {
        io.write_all(&self.encode().map_err(io::Error::other)?)
            .await?;
        io.flush().await
    }

    pub async fn read<T>(io: &mut T) -> Result<Self>
    where
        T: AsyncReadExt + Unpin,
    {
        let mut header = [0u8; HEADER_LEN];
        io.read_exact(&mut header).await.map_err(|e| {
            InterflowError::connection("inner hello read failed".to_string()).with_source(e)
        })?;
        let principal_len =
            u16::from_be_bytes([header[header.len() - 2], header[header.len() - 1]]) as usize;
        let mut rest = vec![0u8; principal_len + 2];
        io.read_exact(&mut rest).await.map_err(|e| {
            InterflowError::connection("inner hello body read failed".to_string()).with_source(e)
        })?;
        let value_len = u16::from_be_bytes([rest[principal_len], rest[principal_len + 1]]) as usize;
        if value_len > MAX_VALUE_LEN {
            return Err(InterflowError::protocol("inner hello selector is too long"));
        }
        let mut value_bytes = vec![0u8; value_len];
        io.read_exact(&mut value_bytes).await.map_err(|e| {
            InterflowError::connection("inner hello selector read failed".to_string())
                .with_source(e)
        })?;
        rest.extend(value_bytes);
        let mut full = header.to_vec();
        full.extend(rest);
        Self::decode(&full)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let hello = InnerStreamHello {
            source_principal: "acme/api".to_owned(),
            source_fingerprint: [7; 32],
            selector: TargetSelector::Address("10.1.2.3:8443".to_owned()),
            correlation_id: [9; 16],
        };
        assert_eq!(
            hello,
            InnerStreamHello::decode(&hello.encode().unwrap()).unwrap()
        );
    }

    #[test]
    fn malformed_selector_is_rejected() {
        let mut hello = InnerStreamHello {
            source_principal: "api".to_owned(),
            source_fingerprint: [0; 32],
            selector: TargetSelector::Default,
            correlation_id: [0; 16],
        }
        .encode()
        .unwrap();
        *hello.last_mut().unwrap() = b'!';
        assert!(InnerStreamHello::decode(&hello).is_err()); // Default cannot carry a selector
        hello.truncate(10);
        assert!(InnerStreamHello::decode(&hello).is_err());
    }

    #[test]
    fn wrong_magic_or_format_version_is_rejected() {
        let hello = InnerStreamHello {
            source_principal: "api".to_owned(),
            source_fingerprint: [0; 32],
            selector: TargetSelector::Default,
            correlation_id: [0; 16],
        }
        .encode()
        .unwrap();
        assert_eq!(&hello[..MAGIC.len()], b"IFSTREAM");
        assert_eq!(hello[MAGIC.len()], FORMAT_VERSION);

        for version in [0u8, 1, 3, 255] {
            if version == FORMAT_VERSION {
                continue;
            }
            let mut wrong = hello.clone();
            wrong[MAGIC.len()] = version;
            assert!(InnerStreamHello::decode(&wrong).is_err());
        }

        let mut wrong_magic = hello;
        wrong_magic[0] = b'X';
        assert!(InnerStreamHello::decode(&wrong_magic).is_err());
    }

    #[tokio::test]
    async fn async_read_round_trip() {
        let hello = InnerStreamHello {
            source_principal: "in".to_owned(),
            source_fingerprint: [1; 32],
            selector: TargetSelector::Default,
            correlation_id: [2; 16],
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        hello.write(&mut client).await.unwrap();
        assert_eq!(hello, InnerStreamHello::read(&mut server).await.unwrap());
    }
}
