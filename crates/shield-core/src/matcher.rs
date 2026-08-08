//! Semantic path-comparison operators used by [`crate::Rule`] matchers.
//!
//! Matchers describe *what* to compare on an [`crate::InspectionPath`];
//! compilation into the engine form lives in [`crate::ruleset`]. Prefer the
//! narrowest operator that covers a probe so evaluation stays cheap and
//! Cloudflare export (when used) stays faithful.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How a rule compares against the decoded inspection path.
///
/// Prefer the narrowest operator that still covers the probe: `Exact` and
/// `Prefix` are cheapest and export cleanly to Cloudflare; `Wildcard` and
/// `Segment` have known export/parity limits (see `towershield-cloudflare`).
///
/// # Wildcard patterns
///
/// `*` matches any run of non-`/` characters; `**` matches any run including
/// `/`. Patterns compile to a small recursive matcher, not a regex.
///
/// # Regex
///
/// Requires the `regex` Cargo feature. The pattern is applied to the
/// inspection path string (not re-anchored by this crate beyond what the
/// pattern itself specifies).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "match", content = "value", rename_all = "snake_case")
)]
pub enum PathMatcher {
    /// Full-path equality after inspection decoding.
    Exact(String),
    /// Path starts with this prefix (including any required trailing `/`).
    Prefix(String),
    /// Path ends with this suffix (e.g. `".pem"`).
    Suffix(String),
    /// A complete `/`-delimited segment equals this value (no `/` in value).
    Segment(String),
    /// Substring appears anywhere in the path.
    Contains(String),
    /// Glob-style pattern: `*` stays in one segment; `**` crosses `/`.
    Wildcard(String),
    /// Regular-expression match (requires the `regex` feature).
    #[cfg(feature = "regex")]
    Regex(String),
}

/// Per-rule case-handling policy applied during compile and evaluate.
///
/// The enum's [`Default`] is [`CaseSensitivity::Sensitive`]. New
/// [`crate::Rule`] values and serde loads that omit the field still default
/// to **insensitive** match behaviour so scanner-probe coverage is not
/// case-fragile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CaseSensitivity {
    /// Compare the decoded path as-is (case-sensitive).
    #[default]
    Sensitive,
    /// Compare against the ASCII-lowercased inspection form.
    Insensitive,
}

/// Discriminant of a [`PathMatcher`] without the pattern payload.
///
/// Carried on [`crate::ShieldMatch`] so metrics and block callbacks can
/// report *how* a rule matched without retaining the pattern string or
/// leaking probe details into client-facing responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchKind {
    /// Full-path equality ([`PathMatcher::Exact`]).
    Exact,
    /// Path-prefix match ([`PathMatcher::Prefix`]).
    Prefix,
    /// Path-suffix match ([`PathMatcher::Suffix`]).
    Suffix,
    /// Complete `/`-delimited segment equality ([`PathMatcher::Segment`]).
    Segment,
    /// Substring match ([`PathMatcher::Contains`]).
    Contains,
    /// Glob-style `*` / `**` match ([`PathMatcher::Wildcard`]).
    Wildcard,
    /// Regex match (source rule requires the `regex` Cargo feature).
    Regex,
}

impl From<&PathMatcher> for MatchKind {
    fn from(m: &PathMatcher) -> Self {
        match m {
            PathMatcher::Exact(_) => MatchKind::Exact,
            PathMatcher::Prefix(_) => MatchKind::Prefix,
            PathMatcher::Suffix(_) => MatchKind::Suffix,
            PathMatcher::Segment(_) => MatchKind::Segment,
            PathMatcher::Contains(_) => MatchKind::Contains,
            PathMatcher::Wildcard(_) => MatchKind::Wildcard,
            #[cfg(feature = "regex")]
            PathMatcher::Regex(_) => MatchKind::Regex,
        }
    }
}
