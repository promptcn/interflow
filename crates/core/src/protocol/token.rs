//! Cryptographically random opaque identifiers used by the data plane.
//!
//! Real tokens are 128-bit CSPRNG values; distinct Rust types prevent a route
//! token from being accidentally used as a circuit token or stream id. The
//! canonical text form (logs, HTTP headers, audit) is 32 lowercase hex
//! characters; the frame header carries the raw 16 bytes. An all-zero
//! value is the frame contract's "field absent" marker (never a real token:
//! generation and hex parsing reject it), so wire conversions accept it while
//! `random`/`from_hex` keep rejecting it.

use crate::error::{InterflowError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const TOKEN_HEX_LEN: usize = 32;

macro_rules! opaque_token {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// The all-zero marker the frame contract uses for an absent field.
            pub const ZERO: Self = Self([0u8; 16]);

            /// Generates a fresh cryptographically random token.
            pub fn random() -> Result<Self> {
                let mut bytes = [0u8; 16];
                getrandom::fill(&mut bytes)
                    .map_err(|e| InterflowError::protocol("system RNG failed").with_source(e))?;
                if bytes.iter().all(|&b| b == 0) {
                    return Err(InterflowError::protocol(
                        "system RNG returned an all-zero opaque token",
                    ));
                }
                Ok(Self(bytes))
            }

            /// Parses the canonical lowercase-hex wire representation.
            pub fn from_hex(value: &str) -> Result<Self> {
                let invalid = || {
                    InterflowError::protocol(concat!(
                        stringify!($name),
                        " must be 32 lowercase hex characters"
                    ))
                };
                if value.len() != TOKEN_HEX_LEN {
                    return Err(invalid());
                }
                if value
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && !b.is_ascii_lowercase())
                {
                    return Err(invalid());
                }
                let decoded = hex::decode(value).map_err(|_| invalid())?;
                let out: [u8; 16] = decoded.try_into().map_err(|_| invalid())?;
                if out.iter().all(|&b| b == 0) {
                    return Err(invalid());
                }
                Ok(Self(out))
            }

            /// Formats the token as canonical lowercase hex.
            pub fn to_hex(self) -> String {
                let mut out = String::with_capacity(TOKEN_HEX_LEN);
                for byte in self.0 {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{byte:02x}");
                }
                out
            }

            /// The raw 16 bytes carried in the frame header.
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }

            /// Interprets raw header bytes. Unlike [`Self::from_hex`] this
            /// accepts the all-zero absent-marker — the frame contract
            /// decides per type whether zero is legal there.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Whether this is the all-zero absent-marker.
            pub const fn is_zero(self) -> bool {
                let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = self.0;
                a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p == 0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = InterflowError;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Self::from_hex(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::from_hex(&value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_token!(
    CircuitToken,
    "A per-connection opaque identity for one authenticated agent circuit."
);
opaque_token!(
    RouteToken,
    "A source-session-scoped opaque route lease for one semantic target."
);
opaque_token!(
    StreamId,
    "A random opaque multiplexing identity for one tunnel stream."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_round_trip_and_use_lowercase_hex() {
        let token = CircuitToken::random().unwrap();
        let text = token.to_hex();
        assert_eq!(text.len(), 32);
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(CircuitToken::from_hex(&text).unwrap(), token);
    }

    #[test]
    fn malformed_tokens_fail_closed() {
        for value in ["", "0", "00".repeat(16).as_str(), "G".repeat(32).as_str()] {
            assert!(CircuitToken::from_hex(value).is_err());
            assert!(RouteToken::from_hex(value).is_err());
            assert!(StreamId::from_hex(value).is_err());
        }
    }

    #[test]
    fn raw_bytes_round_trip_and_zero_marker() {
        let token = CircuitToken::random().unwrap();
        assert_eq!(CircuitToken::from_bytes(token.to_bytes()), token);
        // The all-zero marker round-trips through raw bytes (frame-header
        // absent marker) but stays rejected by the strict hex form.
        let zero = CircuitToken::from_bytes([0u8; 16]);
        assert_eq!(zero, CircuitToken::ZERO);
        assert!(zero.is_zero());
        assert!(!token.is_zero());
        assert!(CircuitToken::from_hex(&zero.to_hex()).is_err());
    }
}
