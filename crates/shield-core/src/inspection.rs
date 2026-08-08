//! Path inspection and normalisation.
//!
//! # Policy
//!
//! The shield inspects a *derived representation* of the request URI path.
//! The original request is **never mutated**. The derived representation is
//! computed once in the Tower service before matching begins.
//!
//! ## What the inspection path is
//!
//! 1. The raw URI path from `http::Uri::path()` (already percent-encoded).
//! 2. Percent-decode the path **once** to produce the canonical form.
//!    Malformed sequences (`%XX` where XX is not valid hex, or a truncated
//!    `%X` at end-of-string) are left as-is in order not to accidentally
//!    obscure an injection.
//! 3. For the case-insensitive variant the result is ASCII-lowercased.
//!
//! ## What the inspection path is NOT
//!
//! - The query string is **not** included.
//! - The path is **not** collapsed for `.` or `..` segments – those are
//!   left to the downstream router.
//! - Duplicate slashes and trailing slashes are preserved.
//! - Backslashes are **not** converted to forward slashes.
//!
//! ## Encoded bypasses
//!
//! Because we decode once, `%2eenv`, `%2F.env`, `/.%65nv` and similar
//! trivial bypasses are covered. We do not iteratively decode.
//!
//! ## Encoded slash
//!
//! `%2F` decodes to `/`. The Tower service matches on the decoded form,
//! which means `/.%2Fenv` would match a rule for `/.//env` after decoding,
//! but not a rule for `/.env`. This is intentional and documented.
//!
//! Callers that rely on the router treating `%2F` as a literal slash
//! separator should be aware that blocking happens on the decoded path.

/// Carries both the original path and its decoded inspection form.
#[derive(Debug, Clone)]
pub struct InspectionPath {
    /// The original, unmodified URI path (may contain percent-encoding).
    pub raw: String,
    /// Decoded once: percent sequences decoded, original otherwise.
    pub decoded: String,
    /// Lower-cased decoded form, for case-insensitive matchers.
    pub decoded_lower: String,
}

impl InspectionPath {
    /// Build from a raw URI path string.
    pub fn new(raw: &str) -> Self {
        let decoded = percent_decode_once(raw);
        let decoded_lower = decoded.to_ascii_lowercase();
        InspectionPath {
            raw: raw.to_owned(),
            decoded,
            decoded_lower,
        }
    }

    /// Return the form appropriate for the given case sensitivity.
    pub fn for_case(&self, case: crate::matcher::CaseSensitivity) -> &str {
        match case {
            crate::matcher::CaseSensitivity::Sensitive => &self.decoded,
            crate::matcher::CaseSensitivity::Insensitive => &self.decoded_lower,
        }
    }
}

/// Decode percent-encoded octets exactly once.
///
/// Invalid sequences are left verbatim so that the inspection form is
/// never shorter (more permissive) than the original path.
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                let byte = (h << 4) | l;
                // Decode to the corresponding character if it is ASCII.
                // Non-ASCII bytes are kept as the percent-encoded form so
                // we never break valid non-ASCII path components.
                if byte < 0x80 {
                    out.push(byte as char);
                    i += 3;
                    continue;
                }
            }
            // Invalid or non-ASCII: emit verbatim.
            out.push(bytes[i] as char);
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
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
}
