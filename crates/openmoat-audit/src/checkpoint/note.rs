//! Checkpoints as C2SP signed notes, and the Ed25519 keys that sign them.
//!
//! A checkpoint's text (C2SP `tlog-checkpoint`) is three lines: the origin,
//! the tree size in decimal, and the root hash in base64. A signed note (C2SP
//! `signed-note`) is that text, a blank line, then one line per signature:
//! `— <key name> <base64(key id || signature)>`, where the key id is the first
//! 4 bytes of `SHA-256(key name || "\n" || 0x01 || public key)` and 0x01 marks
//! Ed25519. A verifier key is written `<name>+<key id in hex>+<base64(0x01 ||
//! public key)>`, the form Go's `golang.org/x/mod/sumdb/note` and the
//! transparency-dev witness read.
//!
//! OpenMoat names each key, and each log's origin, after the key itself:
//! `openmoat.dev/audit/<first 16 hex of SHA-256(public key)>`. The name only
//! identifies; nothing is fetched from it. A new key is a new origin, so a
//! witness never sees two keys claim one log.

use std::fmt;

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::CheckpointError;
use super::encoding::{base64, hex, unbase64, unhex};

/// What every OpenMoat checkpoint's origin, and its key's name, starts with.
pub const ORIGIN_PREFIX: &str = "openmoat.dev/audit/";

/// The signature type byte of Ed25519 in signed notes.
const ED25519_TYPE: u8 = 0x01;

/// First line of the signing key file.
const KEY_TAG: &str = "openmoat-audit-signing-v1";

/// What begins each signature line: an em dash and a space.
const SIGNATURE_START: &str = "\u{2014} ";

/// The public half of a checkpoint signing key, as a verifier holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    name: String,
    id: [u8; 4],
    public: [u8; 32],
}

fn key_id(name: &str, public: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([ED25519_TYPE]);
    h.update(public);
    let digest = h.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

impl VerifierKey {
    fn of(public: [u8; 32]) -> Self {
        let name = format!("{ORIGIN_PREFIX}{}", &hex(&Sha256::digest(public))[..16]);
        Self {
            id: key_id(&name, &public),
            name,
            public,
        }
    }

    /// The key's name, which is also the origin of the checkpoints it signs.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `SHA256:` and the hex SHA-256 of the public key: what `openmoat
    /// doctor` shows, to compare with a copy kept elsewhere.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!("SHA256:{}", hex(&Sha256::digest(self.public)))
    }

    /// Parse a verifier key, `<name>+<hex key id>+<base64(0x01 || key)>`.
    /// Only OpenMoat's own names are taken: a key under another name could
    /// not have signed an OpenMoat checkpoint.
    pub fn parse(text: &str) -> Result<Self, CheckpointError> {
        let bad = |why: &str| CheckpointError::VerifierKey(why.to_owned());
        // The key's base64 may hold `+` itself: only the first two separate.
        let mut parts = text.trim().splitn(3, '+');
        let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(bad("expected <name>+<key id>+<key>"));
        };
        let raw = unbase64(key).ok_or_else(|| bad("the key is not base64"))?;
        let Some((&ED25519_TYPE, public)) = raw.split_first() else {
            return Err(bad("not an Ed25519 key"));
        };
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| bad("an Ed25519 key is 32 bytes"))?;
        let key = Self::of(public);
        if key.name != name {
            return Err(bad(
                "the name is not the one OpenMoat gives this key (openmoat.dev/audit/<fingerprint>)",
            ));
        }
        if unhex::<4>(id) != Some(key.id) {
            return Err(bad("the key id does not match the name and key"));
        }
        Ok(key)
    }

    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, self.public)
            .verify(message, signature)
            .is_ok()
    }
}

impl fmt::Display for VerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut key = Vec::with_capacity(33);
        key.push(ED25519_TYPE);
        key.extend_from_slice(&self.public);
        write!(f, "{}+{}+{}", self.name, hex(&self.id), base64(&key))
    }
}

/// A checkpoint signing key; its seed is zeroed when dropped and never
/// printed.
pub struct SigningKey {
    seed: Zeroizing<[u8; 32]>,
    pair: Ed25519KeyPair,
    verifier: VerifierKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifier", &self.verifier.name)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// The key whose Ed25519 seed (RFC 8032 private key) is `seed`; the bytes
    /// are copied into zeroed memory.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CheckpointError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| CheckpointError::KeyInvalid("the seed is not an Ed25519 key".into()))?;
        let public: [u8; 32] =
            pair.public_key().as_ref().try_into().map_err(|_| {
                CheckpointError::KeyInvalid("the public key is not 32 bytes".into())
            })?;
        let mut held = Zeroizing::new([0u8; 32]);
        held.copy_from_slice(seed);
        Ok(Self {
            seed: held,
            pair,
            verifier: VerifierKey::of(public),
        })
    }

    /// The key file's text: a tag line, then the seed as 64 hex characters.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{KEY_TAG}\n{}\n", hex(self.seed.as_slice())))
    }

    /// Parse [`SigningKey::encode`]'s text; an error that never quotes it.
    pub fn parse(text: &str) -> Result<Self, CheckpointError> {
        let invalid = |why: &str| CheckpointError::KeyInvalid(why.to_owned());
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        if lines.next() != Some(KEY_TAG) {
            return Err(invalid("it is not an OpenMoat audit signing key"));
        }
        let seed = lines
            .next()
            .and_then(|l| unhex::<32>(l).map(Zeroizing::new))
            .ok_or_else(|| invalid("its seed is not 64 hex characters"))?;
        if lines.next().is_some() {
            return Err(invalid("it has more lines than a key"));
        }
        Self::from_seed(&seed)
    }

    /// The public half.
    #[must_use]
    pub fn verifier(&self) -> &VerifierKey {
        &self.verifier
    }

    /// The signed note of `checkpoint`, which must name this key's origin.
    pub fn sign(&self, checkpoint: &Checkpoint) -> Result<String, CheckpointError> {
        if checkpoint.origin != self.verifier.name {
            return Err(CheckpointError::OriginMismatch {
                found: checkpoint.origin.clone(),
                expected: self.verifier.name.clone(),
            });
        }
        let body = checkpoint.body();
        let signature = self.pair.sign(body.as_bytes());
        let mut blob = Vec::with_capacity(68);
        blob.extend_from_slice(&self.verifier.id);
        blob.extend_from_slice(signature.as_ref());
        Ok(format!(
            "{body}\n{SIGNATURE_START}{} {}\n",
            self.verifier.name,
            base64(&blob)
        ))
    }
}

/// A log's state as a checkpoint states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The log's name: its signing key's name.
    pub origin: String,
    /// Chained events covered, oldest first.
    pub size: u64,
    /// The Merkle tree hash of those events ([`super::Frontier::root`]).
    pub root: [u8; 32],
}

impl Checkpoint {
    /// The checkpoint text a signature covers.
    #[must_use]
    pub fn body(&self) -> String {
        format!("{}\n{}\n{}\n", self.origin, self.size, base64(&self.root))
    }

    /// The root hash in lowercase hex.
    #[must_use]
    pub fn root_hex(&self) -> String {
        hex(&self.root)
    }

    /// The checkpoint `note` states, once `key` is shown to have signed it and
    /// it names `key`'s log. Other keys' signatures (a witness's cosignature)
    /// are allowed and not checked.
    pub fn open(note: &str, key: &VerifierKey) -> Result<Self, CheckpointError> {
        let bad = |why: &str| CheckpointError::Malformed(why.to_owned());
        let split = note
            .find("\n\n")
            .ok_or_else(|| bad("no blank line before the signatures"))?;
        let body = &note[..=split];
        let mut signed = false;
        for line in note[split + 2..].lines() {
            let rest = line
                .strip_prefix(SIGNATURE_START)
                .ok_or_else(|| bad("a signature line does not start with `— `"))?;
            let (name, blob) = rest
                .rsplit_once(' ')
                .ok_or_else(|| bad("a signature line has no signature"))?;
            if name != key.name {
                continue;
            }
            let blob = unbase64(blob).ok_or_else(|| bad("a signature is not base64"))?;
            let Some((id, signature)) = blob.split_at_checked(4) else {
                return Err(bad("a signature is too short"));
            };
            if id != key.id {
                continue;
            }
            if !key.verifies(body.as_bytes(), signature) {
                return Err(CheckpointError::BadSignature);
            }
            signed = true;
        }
        if !signed {
            return Err(CheckpointError::NoSignature(key.name.clone()));
        }
        let checkpoint = parse_body(body)?;
        if checkpoint.origin != key.name {
            return Err(CheckpointError::OriginMismatch {
                found: checkpoint.origin,
                expected: key.name.clone(),
            });
        }
        Ok(checkpoint)
    }
}

/// The origin, size and root of a checkpoint's text; extension lines after
/// them are allowed and ignored.
pub(super) fn parse_body(body: &str) -> Result<Checkpoint, CheckpointError> {
    let bad = |why: &str| CheckpointError::Malformed(why.to_owned());
    let mut lines = body.lines();
    let origin = lines
        .next()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| bad("no origin line"))?;
    let size = lines.next().ok_or_else(|| bad("no tree size line"))?;
    // Decimal, no sign and no leading zero: one size, one spelling.
    let canonical = size.bytes().all(|b| b.is_ascii_digit())
        && !size.is_empty()
        && (size == "0" || !size.starts_with('0'));
    let size: u64 = size
        .parse()
        .ok()
        .filter(|_| canonical)
        .ok_or_else(|| bad("the tree size is not a decimal number"))?;
    let root = lines
        .next()
        .and_then(unbase64)
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or_else(|| bad("the root hash is not 32 bytes of base64"))?;
    Ok(Checkpoint {
        origin: origin.to_owned(),
        size,
        root,
    })
}
