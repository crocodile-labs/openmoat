//! HMAC-SHA-256 (RFC 2104) over the `sha2` crate the CLI already uses, so the
//! session credentials need no new dependency. Checked against the test
//! vectors of RFC 4231 in `tests.rs`.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// SHA-256's block size in bytes.
const BLOCK: usize = 64;

/// `HMAC-SHA-256(key, message)`.
pub fn sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // A key longer than the block is hashed first; a shorter one is padded
    // with zeros (RFC 2104 §2).
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut ipad = Zeroizing::new([0u8; BLOCK]);
    let mut opad = Zeroizing::new([0u8; BLOCK]);
    for (i, byte) in block.iter().enumerate() {
        ipad[i] = byte ^ 0x36;
        opad[i] = byte ^ 0x5c;
    }
    inner.update(ipad.as_slice());
    inner.update(message);
    outer.update(opad.as_slice());
    outer.update(inner.finalize());
    outer.finalize().into()
}
