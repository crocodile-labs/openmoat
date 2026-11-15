//! The audit key (ADR-101): a per-install secret whose MAC each event carries
//! beside its public chain hash, so a log rewritten by someone without the key
//! no longer verifies.
//!
//! The chain hash (`store/chain.rs`) stays unkeyed: anyone can check an export
//! with it, and anchors record it. The MAC is `HMAC-SHA-256(key, domain ||
//! hash)`; the hash already commits to every cell of the event and, through
//! `prev_hash`, to every event before it, so one MAC per event authenticates
//! the whole chain up to it.
//!
//! The key file holds the key and where the keyed events start: the id of the
//! last event written before the key existed (`after`) and that event's chain
//! hash. Events up to it verify under the unkeyed chain only, every later one
//! must carry a MAC, and event `after` must still be there with that hash. Both
//! are kept with the key, not in the database, so someone who can write the
//! database but not the key can neither move the start to pass rewritten
//! events off as older than the key, nor drop the keyed events and rewrite
//! the ones before them.
//!
//! This crate only encodes, parses and computes; the CLI reads and writes the
//! file (`audit_key.rs`), as it does every key in OpenMoat's state directory.

use std::fmt::{self, Write as _};

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{EventId, StoreError};

/// SHA-256's block size in bytes.
const BLOCK: usize = 64;

/// Signed in front of every chain hash, so the key's MACs mean nothing else.
const MAC_DOMAIN: &[u8] = b"openmoat-audit-mac-v1\n";

/// Signed to name a key without showing it ([`ChainKey::id`]).
const ID_DOMAIN: &[u8] = b"openmoat-audit-key-id-v1\n";

/// The word before the start's id and hash in the key file.
const AFTER: &str = "after";

/// The key file's word for a start event without a hash: none (an empty log)
/// or one written before the hash chain existed.
const NO_HASH: &str = "none";

/// `HMAC-SHA-256(key, message)` (RFC 2104) over `sha2`, so no MAC crate is
/// needed. The CLI's session credentials and webhook signatures use it too;
/// it is checked against RFC 4231's vectors there (`proxy_session/tests.rs`).
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // A key longer than the block is hashed first; a shorter one is padded
    // with zeros (RFC 2104 §2).
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0u8; BLOCK]);
    let mut opad = Zeroizing::new([0u8; BLOCK]);
    for (i, byte) in block.iter().enumerate() {
        ipad[i] = byte ^ 0x36;
        opad[i] = byte ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad.as_slice());
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(opad.as_slice());
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The audit key and where the keyed events start; zeroed on drop, never
/// printed.
pub struct ChainKey {
    key: Zeroizing<[u8; 32]>,
    after: i64,
    after_hash: Option<String>,
}

impl fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainKey")
            .field("after", &self.after)
            .finish_non_exhaustive()
    }
}

impl ChainKey {
    /// A key made from 32 random bytes for a log whose newest event when the
    /// key was made is `after` (`EventId(0)` for an empty log), with chain hash
    /// `after_hash` (`None` for an empty log or an event from before the hash
    /// chain). The bytes are copied into zeroed memory, not moved by value.
    #[must_use]
    pub fn new(key: &[u8; 32], after: EventId, after_hash: Option<&str>) -> Self {
        let mut held = Zeroizing::new([0u8; 32]);
        held.copy_from_slice(key);
        Self {
            key: held,
            after: after.0.max(0),
            after_hash: after_hash.map(str::to_owned),
        }
    }

    /// The key a throwaway in-memory database writes with: it protects
    /// nothing, since the database goes when the handle does.
    pub(crate) fn throwaway() -> Self {
        Self::new(&[0x5a; 32], EventId(0), None)
    }

    /// The last event written before the key existed: events after it must
    /// carry a MAC.
    #[must_use]
    pub fn after(&self) -> EventId {
        EventId(self.after)
    }

    /// The chain hash event [`ChainKey::after`] had when the key was made.
    #[must_use]
    pub fn after_hash(&self) -> Option<&str> {
        self.after_hash.as_deref()
    }

    /// The key file's text: the key as 64 lowercase hex characters, then
    /// `after <id> <hash>`, the id in decimal and `none` for no hash.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(160));
        hex_into(&mut out, self.key.as_slice());
        let hash = self.after_hash.as_deref().unwrap_or(NO_HASH);
        let _ = write!(out, "\n{AFTER} {} {hash}\n", self.after);
        out
    }

    /// Parse [`ChainKey::encode`]'s text; an error that never quotes it.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        let invalid = |why: &str| StoreError::KeyInvalid(why.to_owned());
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let hex = lines.next().ok_or_else(|| invalid("it is empty"))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("its first line is not 64 hex characters"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid("it is not ASCII"))?;
            key[i] = u8::from_str_radix(pair, 16).map_err(|_| invalid("it is not hex"))?;
        }
        let start = lines.next().unwrap_or_default();
        let (after, after_hash) = parse_start(start)
            .ok_or_else(|| invalid("its second line is not `after <event id> <hash>`"))?;
        if lines.next().is_some() {
            return Err(invalid("it has more than two lines"));
        }
        Ok(Self {
            key,
            after,
            after_hash,
        })
    }

    /// A name for the key that does not show it: 16 hex characters. An export
    /// carries it, so a verifier knows which lines claim its key.
    #[must_use]
    pub fn id(&self) -> String {
        let mac = hmac_sha256(self.key.as_slice(), ID_DOMAIN);
        let mut out = String::with_capacity(16);
        hex_into(&mut out, &mac[..8]);
        out
    }

    /// The MAC of the event whose chain hash is `hash`, as lowercase hex.
    pub(crate) fn mac(&self, hash: &str) -> String {
        let mut message = Vec::with_capacity(MAC_DOMAIN.len() + hash.len());
        message.extend_from_slice(MAC_DOMAIN);
        message.extend_from_slice(hash.as_bytes());
        let mac = hmac_sha256(self.key.as_slice(), &message);
        let mut out = String::with_capacity(64);
        hex_into(&mut out, &mac);
        out
    }

    /// Whether `mac` is the MAC of `hash`, compared in constant time.
    pub(crate) fn verifies(&self, hash: &str, mac: &str) -> bool {
        let expected = self.mac(hash);
        expected.len() == mac.len()
            && expected
                .bytes()
                .zip(mac.bytes())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
    }
}

/// `after <id> <hash>`: the id, and the hash (`None` for [`NO_HASH`]). An id
/// past 0 needs a hash or `none`; 0 needs `none`.
fn parse_start(line: &str) -> Option<(i64, Option<String>)> {
    let mut words = line.split_whitespace();
    if words.next()? != AFTER {
        return None;
    }
    let after = words.next()?.parse::<i64>().ok().filter(|id| *id >= 0)?;
    let hash = match words.next()? {
        NO_HASH => None,
        hash if hash.len() == 64
            && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            Some(hash.to_owned())
        }
        _ => return None,
    };
    if words.next().is_some() || (after == 0 && hash.is_some()) {
        return None;
    }
    Some((after, hash))
}

fn hex_into(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "a4c71c405a0719bae1d6cd1fa50a92b6bfdcdf41f6789c7eea604f63c549c774";

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let mut hex = String::new();
        hex_into(&mut hex, &mac);
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn the_key_file_round_trips_and_names_no_secret_in_its_errors() {
        let key = ChainKey::new(&[7; 32], EventId(41), Some(HASH));
        let text = key.encode();
        assert!(
            text.ends_with(&format!("\nafter 41 {HASH}\n")),
            "{}",
            text.as_str()
        );
        let parsed = ChainKey::parse(&text).unwrap();
        assert_eq!(parsed.after(), EventId(41));
        assert_eq!(parsed.after_hash(), Some(HASH));
        assert_eq!(parsed.mac("ab"), key.mac("ab"));
        assert_eq!(parsed.id(), key.id());
        assert!(!format!("{parsed:?}").contains("0707"));
        let empty = ChainKey::new(&[7; 32], EventId(0), None);
        assert!(empty.encode().ends_with("\nafter 0 none\n"));
        assert_eq!(ChainKey::parse(&empty.encode()).unwrap().after_hash(), None);
        let hex = text.lines().next().unwrap();
        for bad in [
            String::new(),
            format!("{hex}\n"),
            format!("{hex}\nafter 41\n"),
            format!("{hex}\nafter -1 none\n"),
            format!("{hex}\nafter x none\n"),
            format!("{hex}\nafter 0 {HASH}\n"),
            format!("{hex}\nafter 4 nothex\n"),
            format!("{hex}\nafter 1 none extra\n"),
            format!("{hex}\nafter 1 none\nmore\n"),
            format!("{}\nafter 1 none\n", &hex[..62]),
        ] {
            let error = ChainKey::parse(&bad).err().unwrap().to_string();
            assert!(!error.contains(&hex[..16]), "{error}");
        }
    }

    #[test]
    fn a_mac_depends_on_the_key_and_the_hash() {
        let one = ChainKey::new(&[1; 32], EventId(0), None);
        let two = ChainKey::new(&[2; 32], EventId(0), None);
        assert_ne!(one.mac("ab"), two.mac("ab"));
        assert_ne!(one.mac("ab"), one.mac("ac"));
        assert_ne!(one.id(), two.id());
        assert!(one.verifies("ab", &one.mac("ab")));
        assert!(!one.verifies("ab", &two.mac("ab")));
        assert!(!one.verifies("ab", ""));
    }
}
