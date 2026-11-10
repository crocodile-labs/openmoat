//! The webhook's signature headers (ADR-081): HMAC-SHA-256 under the sink's
//! key over `<timestamp>.<body>`, so a receiver can check that the body came
//! from a holder of the key, unchanged, and refuse a replay outside its own
//! window by the timestamp.

use std::fmt::Write as _;

use crate::proxy_session::hmac;

/// The request's time in ms since the epoch, as signed.
pub const TIMESTAMP: &str = "X-OpenMoat-Timestamp";
/// `v1=<hex>`: the signature, version 1.
pub const SIGNATURE: &str = "X-OpenMoat-Signature";
/// A name for the batch, the same on every retry of it, so a receiver can
/// drop a batch it already stored.
pub const DELIVERY: &str = "X-OpenMoat-Delivery";

/// `v1=` and the lowercase hex HMAC-SHA-256 of `<timestamp_ms>.<body>`.
pub fn signature(key: &[u8], timestamp_ms: i64, body: &[u8]) -> String {
    let mut message = timestamp_ms.to_string().into_bytes();
    message.push(b'.');
    message.extend_from_slice(body);
    let mac = hmac::sha256(key, &message);
    mac.iter().fold(String::from("v1="), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value a receiver computes with its own HMAC library (here Python's
    /// `hmac.new(key, b"1700000000000." + body, sha256)`), for a key and body
    /// made up for the test.
    #[test]
    fn the_signature_is_what_a_receiver_computes() {
        let sig = signature(b"openmoat-test-key", 1_700_000_000_000, br#"{"a":1}"#);
        assert_eq!(
            sig,
            "v1=ca967f7929ce0dbfa2d4fee6c805379e2dc57b1551f7d9caeec2ab0af63caf04"
        );
        assert_ne!(
            sig,
            signature(b"openmoat-test-key", 1_700_000_000_001, br#"{"a":1}"#)
        );
        assert_ne!(
            sig,
            signature(b"openmoat-test-kez", 1_700_000_000_000, br#"{"a":1}"#)
        );
    }
}
