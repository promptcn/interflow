//! One-line expansion of an error's full `source()` chain, for log and
//! report boundaries that render a single string.

/// Formats `error` followed by its full `source()` chain, joined with
/// `": "` — `top: cause: root cause`. Errors without sources render as
/// their own `Display`.
pub fn format_chain(error: &(dyn std::error::Error + '_)) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        out.push_str(": ");
        out.push_str(&e.to_string());
        source = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::format_chain;

    #[derive(thiserror::Error, Debug)]
    #[error("root cause")]
    struct Root;

    #[derive(thiserror::Error, Debug)]
    #[error("middle")]
    struct Middle(#[source] Root);

    #[derive(thiserror::Error, Debug)]
    #[error("top")]
    struct Top(#[source] Middle);

    #[test]
    fn joins_the_full_chain() {
        assert_eq!(format_chain(&Top(Middle(Root))), "top: middle: root cause");
    }

    #[test]
    fn sourceless_errors_render_plainly() {
        assert_eq!(format_chain(&Root), "root cause");
    }
}
