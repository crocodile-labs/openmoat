//! HMAC-SHA-256 (RFC 2104) over the `sha2` crate, so the session credentials
//! need no new dependency. It lives in `openmoat-audit`, whose keyed chain
//! (ADR-100) needs it too; checked against the test vectors of RFC 4231 in
//! `tests.rs`.

/// `HMAC-SHA-256(key, message)`.
pub use openmoat_audit::hmac_sha256 as sha256;
