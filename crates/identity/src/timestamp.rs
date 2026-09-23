//! RFC 3339 timestamps — the canonical clock format of identity documents
//! (credential packs, enrollment records, revocation entries).

use crate::{Error, Result};
use time::OffsetDateTime;

/// Formats a timestamp as RFC 3339.
pub fn rfc3339(ts: OffsetDateTime) -> Result<String> {
    ts.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::serialize("timestamp".to_string()).with_source(e))
}

/// The current UTC time, RFC 3339 formatted.
pub fn rfc3339_now() -> Result<String> {
    rfc3339(OffsetDateTime::now_utc())
}

/// Parses an RFC 3339 timestamp.
pub fn parse_rfc3339(text: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::serialize(format!("timestamp {text:?}")).with_source(e))
}
