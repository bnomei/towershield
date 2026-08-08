//! Known semantic gaps between the Tower path denylist and Cloudflare edge rules.
//!
//! Export is best-effort translation, not a proof of identical blocking.
//! Operators should treat edge rules as a coarse first filter and keep the
//! Tower middleware as the authoritative in-process denylist.
//!
//! # Known differences
//!
//! | Concern | Tower middleware | Cloudflare |
//! |---|---|---|
//! | Path field | `http::Uri::path()` + [`towershield_core::InspectionPath`] | `http.request.uri.path` (CF-normalised) |
//! | Percent encoding | Single-pass decode in core | Field-dependent CF handling |
//! | Segment matcher | Exact `/`-delimited segment equality | Approximated as `contains "/seg/"` (FP/FN risk) |
//! | Wildcard matcher | `*` in-segment; `**` crosses `/` | Skipped — no exact CF encoding |
//! | Case | Explicit lowercased inspection form | Explicit `lower()` in expressions |
//! | Trailing slash | Preserved | May be altered by CF normalisation |
//!
//! Soft gaps surface in [`crate::output::ExportReport::diagnostics`] when a
//! rule is skipped or only approximated.
