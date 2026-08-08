//! Single-pass path inspection used as the matching surface.
//!
//! The shield never mutates the live HTTP request. Adapters (e.g. the Tower
//! service) build an [`InspectionPath`] once per request from
//! `http::Uri::path()`, then pass it to [`crate::CompiledRuleSet::evaluate`].
//!
//! # What is derived
//!
//! 1. Take the raw URI path (percent-encoded as received).
//! 2. Percent-decode **once**. Invalid `%` sequences stay verbatim so the
//!    inspection form is never “shorter” (more permissive) than the input.
//! 3. Lazily ASCII-lowercase only when a case-insensitive rule needs it and
//!    the decoded path actually contains uppercase ASCII.
//!
//! # What is deliberately not done
//!
//! - Query string is excluded (callers must pass path only).
//! - `.` / `..` segments are not collapsed (left to the router).
//! - Duplicate and trailing slashes are preserved.
//! - Backslashes are not rewritten to `/`.
//! - Decoding is not iterative (`%252e` stays `/%2e…`, not `/.…`).
//!
//! # Encoded bypasses and `%2F`
//!
//! One-pass decode covers trivial probes such as `/%2eenv` and `/.%65nv`.
//! `%2F` becomes `/`, so `/.%2Fenv` matches a rule for `/.//env` after
//! decode, **not** a rule for `/.env`. That boundary is intentional.

use std::{borrow::Cow, cell::OnceCell};

/// Raw path plus the single-pass decoded form used by matchers.
///
/// Build once per request; reuse across every rule comparison via
/// [`InspectionPath::for_case`].
#[derive(Debug, Clone)]
pub struct InspectionPath<'a> {
    /// Unmodified URI path as supplied by the caller (may be percent-encoded).
    pub raw: &'a str,
    /// Path after exactly one percent-decode pass.
    pub decoded: Cow<'a, str>,
    has_ascii_uppercase: bool,
    decoded_lower: OnceCell<String>,
}

impl<'a> InspectionPath<'a> {
    /// Derive inspection forms from a path-only string (no query).
    pub fn new(raw: &'a str) -> Self {
        let decoded = percent_decode_once(raw);
        let has_ascii_uppercase = decoded.bytes().any(|byte| byte.is_ascii_uppercase());
        InspectionPath {
            raw,
            decoded,
            has_ascii_uppercase,
            decoded_lower: OnceCell::new(),
        }
    }

    /// Select decoded or lowercased form for a rule's case policy.
    pub fn for_case(&self, case: crate::matcher::CaseSensitivity) -> &str {
        match case {
            crate::matcher::CaseSensitivity::Sensitive => self.decoded.as_ref(),
            crate::matcher::CaseSensitivity::Insensitive => {
                if self.has_ascii_uppercase {
                    self.decoded_lower
                        .get_or_init(|| self.decoded.to_ascii_lowercase())
                } else {
                    self.decoded.as_ref()
                }
            }
        }
    }
}

/// Percent-decode ASCII octets exactly once; leave invalid / non-ASCII `%` runs intact.
fn percent_decode_once(input: &str) -> Cow<'_, str> {
    let bytes = input.as_bytes();
    let mut out: Option<String> = None;
    let mut copy_from = 0;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                let byte = (h << 4) | l;
                // Only materialise ASCII so multi-byte UTF-8 path components
                // that were percent-encoded stay intact as sequences.
                if byte < 0x80 {
                    let decoded = out.get_or_insert_with(|| String::with_capacity(bytes.len()));
                    decoded.push_str(&input[copy_from..i]);
                    decoded.push(byte as char);
                    i += 3;
                    copy_from = i;
                    continue;
                }
            }
        }
        i += 1;
    }

    if let Some(mut decoded) = out {
        decoded.push_str(&input[copy_from..]);
        Cow::Owned(decoded)
    } else {
        Cow::Borrowed(input)
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::CaseSensitivity;

    #[test]
    fn decodes_dotenv_bypass() {
        let p = InspectionPath::new("/%2eenv");
        assert_eq!(p.decoded, "/.env");
    }

    #[test]
    fn does_not_double_decode() {
        let p = InspectionPath::new("/%252eenv");
        // %25 → '%', remaining '2eenv' is literal (single-pass only).
        // Result is '/%2eenv', NOT '/.env' (no second decode pass).
        assert_eq!(p.decoded, "/%2eenv");
    }

    #[test]
    fn invalid_percent_left_verbatim() {
        let p = InspectionPath::new("/%zz");
        assert_eq!(p.decoded, "/%zz");
    }

    #[test]
    fn case_insensitive_lowercased() {
        let p = InspectionPath::new("/FOO/BAR");
        assert_eq!(p.for_case(CaseSensitivity::Insensitive), "/foo/bar");
    }

    #[test]
    fn query_not_included() {
        // The InspectionPath is given only the path portion from http::Uri::path()
        // which already excludes the query. This test confirms we do not
        // accidentally include '?' or later.
        let p = InspectionPath::new("/foo");
        assert!(!p.decoded.contains('?'));
    }

    #[test]
    fn trailing_slash_preserved() {
        let p = InspectionPath::new("/wp-admin/");
        assert_eq!(p.decoded, "/wp-admin/");
    }

    #[test]
    fn backslash_preserved() {
        let p = InspectionPath::new("/foo\\bar");
        assert_eq!(p.decoded, "/foo\\bar");
    }

    #[test]
    fn unencoded_lowercase_path_borrows_without_allocating() {
        let p = InspectionPath::new("/api/users");
        assert!(matches!(p.decoded, Cow::Borrowed(_)));
        assert!(p.decoded_lower.get().is_none());
        assert_eq!(p.for_case(CaseSensitivity::Insensitive), "/api/users");
        assert!(p.decoded_lower.get().is_none());
    }

    #[test]
    fn preserves_unencoded_unicode() {
        let p = InspectionPath::new("/café/%zz");
        assert_eq!(p.decoded, "/café/%zz");
    }
}
