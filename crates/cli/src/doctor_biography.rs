//! `interflow-cli doctor biography` — one leg's event timeline, one
//! query.
//!
//! The events were always in the hub's `audit.jsonl`; what was missing
//! was the operator endpoint and the rendering — every incident
//! timeline was ssh + journalctl + manual timestamp alignment. This
//! command reads the biography face and prints the rows newest-first,
//! reasons expanded, contexts carried.

use interflow_cli::outln;
use std::path::Path;

/// Parses a "30m" / "12h" / "2d" duration into seconds (the lookback
/// window's CLI form). Falls back with an honest error on anything
/// else — a silently wrong window hides exactly the events asked for.
fn parse_since(text: &str) -> interflow_core::error::Result<u64> {
    let trimmed = text.trim();
    let (number, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let value: u64 = number.parse().map_err(|_| {
        interflow_core::error::InterflowError::config(format!(
            "--since {text:?} is not a <number><unit> window (30m / 12h / 2d)"
        ))
    })?;
    match unit {
        "m" => Ok(value * 60),
        "h" => Ok(value * 3600),
        "d" => Ok(value * 86_400),
        other => Err(interflow_core::error::InterflowError::config(format!(
            "--since unit {other:?} is not one of m/h/d"
        ))),
    }
}

/// Runs the biography query and renders the timeline.
pub fn run(
    agent: &str,
    since: Option<&str>,
    manifest: &Path,
    issuer: &Path,
) -> interflow_core::error::Result<()> {
    let since_secs = since.map_or_else(|| Ok(48 * 3600), parse_since)?;
    outln!(
        "Interflow doctor biography — {agent} (last {}s)",
        humanize_window(since_secs)
    );
    outln!();
    let query_agent = agent.to_owned();
    let doc = interflow_cli::plan::with_hub_control_credential(
        manifest,
        issuer,
        move |ep, ca, cert, key| async move {
            interflow_mesh::hub::biography::query_biography(
                &ep,
                &ca,
                &cert,
                &key,
                &query_agent,
                since_secs,
            )
            .await
        },
    )?;
    let Some((_endpoint, doc)) = doc else {
        return Err(interflow_core::error::InterflowError::config(format!(
            "manifest {} names no hub endpoint — nothing to query",
            manifest.display()
        )));
    };
    if doc.rows.is_empty() {
        outln!(
            "· no events for {agent} in the window (the leg may predate the window or never registered)"
        );
        return Ok(());
    }
    for row in &doc.rows {
        // "10-19 09:12" — the timestamp's leading date/time fields.
        let short_ts = short_timestamp(&row.ts);
        outln!("{short_ts}  {}  {}", row.kind, row.detail);
    }
    outln!();
    outln!("{} event(s), newest first.", doc.rows.len());
    Ok(())
}

/// `2026-10-19T09:12:33…` → `10-19 09:12` (the operator's local-eye
/// form; the full instant stays one hover away in the JSON face).
fn short_timestamp(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if bytes.len() >= 16 {
        format!(
            "{}-{} {}",
            ts[5..7].to_owned(),
            ts[8..10].to_owned(),
            ts[11..16].to_owned()
        )
    } else {
        ts.to_owned()
    }
}

fn humanize_window(secs: u64) -> String {
    if secs.is_multiple_of(86_400) {
        format!("{}d", secs / 86_400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else {
        format!("{}m", secs / 60)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn since_parsing_covers_the_three_units_and_rejects_junk() {
        assert_eq!(parse_since("30m").unwrap(), 1800);
        assert_eq!(parse_since("12h").unwrap(), 43_200);
        assert_eq!(parse_since("2d").unwrap(), 172_800);
        assert!(parse_since("2w").is_err());
        assert!(parse_since("forever").is_err());
    }

    #[test]
    fn timestamp_shortening_keeps_the_operators_eye_form() {
        assert_eq!(
            short_timestamp("2026-10-19T09:12:33.123456789Z"),
            "10-19 09:12"
        );
        assert_eq!(short_timestamp("short"), "short");
    }
}
