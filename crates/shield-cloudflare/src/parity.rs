//! Documented parity gaps between the Tower middleware and Cloudflare.
//!
//! # Known differences
//!
//! | Concern | Tower middleware | Cloudflare |
//! |---|---|---|
//! | Path field | `http::Uri::path()` – decoded by the HTTP stack | `http.request.uri.path` – Cloudflare-normalised |
//! | Percent encoding | One-pass decode in [`shield_core::InspectionPath`] | CF may decode or not depending on field |
//! | Segment matcher | Split on `/`, compare each segment | Approximated as `contains "/seg/"` – may produce false positives |
//! | Case | Explicit lowercase before compare | Explicit `lower()` wrapper |
//! | Trailing slash | Preserved | May be stripped by CF normalisation |
//!
//! Parity is not guaranteed byte-for-byte. The exporter reports semantic
//! differences in [`crate::output::ExportReport::diagnostics`].
