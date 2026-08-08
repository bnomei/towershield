//! Path matcher types: [`PathMatcher`], [`CaseSensitivity`], [`MatchKind`].

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How to match the request path.
///
/// # Wildcard patterns
///
/// Wildcard patterns support `*` (any run of non-`/` characters) and `**`
/// (any run of characters including `/`). They are converted to a simple
/// NFA rather than to a regex at compile time.
///
/// # Regex
///
/// Only available with the `regex` Cargo feature. The pattern is anchored
/// to the start of the path string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "match", content = "value", rename_all = "snake_case")
)]
pub enum PathMatcher {
    /// The path must equal the value exactly.
    Exact(String),
    /// The path must start with the given prefix.
    Prefix(String),
    /// The path must end with the given suffix.
    Suffix(String),
    /// The path must contain the given string as a complete URI path segment.
    Segment(String),
    /// The path must contain the given string anywhere.
    Contains(String),
    /// Wildcard: `*` matches any run of non-`/` characters; `**` matches
    /// any run including `/`.
    Wildcard(String),
    /// Regular-expression match (requires `regex` Cargo feature).
    #[cfg(feature = "regex")]
    Regex(String),
}

/// Case-handling policy for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CaseSensitivity {
    /// Match is case-sensitive (default).
    #[default]
    Sensitive,
    /// Match is case-insensitive. The path is lowercased before comparison.
    Insensitive,
}

/// The discriminant of a [`PathMatcher`] variant.
///
/// Used in [`crate::ShieldMatch`] and metrics so the match kind can be
/// reported without carrying the full pattern string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchKind {
    /// Exact path equality.
    Exact,
    /// Prefix match.
    Prefix,
    /// Suffix match.
    Suffix,
    /// Complete URI-segment match.
    Segment,
    /// Substring match.
    Contains,
    /// Wildcard pattern.
    Wildcard,
    /// Regular-expression match.
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
