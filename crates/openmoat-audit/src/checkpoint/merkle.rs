//! The Merkle tree a checkpoint's root hash is the root of (RFC 6962 §2.1).
//!
//! Its leaves are the audit log's chained events in id order: each leaf's data
//! is the 32 bytes of the event's chain hash, which already commits to every
//! cell of the event. A leaf hashes as `SHA-256(0x00 || data)`, a node as
//! `SHA-256(0x01 || left || right)`, and the tree of no leaves as `SHA-256("")`,
//! so the root is the one a transparency log of the same leaves would have,
//! and a witness can check consistency between two checkpoints by the usual
//! proofs.
//!
//! [`Frontier`] keeps only the roots of the perfect subtrees the leaves so far
//! make (one per set bit of the size), so a new checkpoint reads only the
//! events since the last one.

use sha2::{Digest as _, Sha256};

use super::CheckpointError;
use super::encoding::{hex, unhex};
use crate::EventId;

/// First line of [`Frontier::encode`]'s text.
const TAG: &str = "openmoat-audit-frontier-v1";

fn leaf(data: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The compact state of the tree over the leaves pushed so far, and the last
/// event pushed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    /// The roots of the perfect subtrees, largest (oldest leaves) first.
    nodes: Vec<[u8; 32]>,
    /// The last event pushed and its chain hash.
    last: Option<(EventId, String)>,
}

impl Frontier {
    /// The tree of no leaves.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Leaves pushed: the tree size a checkpoint of it states.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The last event pushed and its chain hash.
    #[must_use]
    pub fn last(&self) -> Option<(EventId, &str)> {
        self.last.as_ref().map(|(id, hash)| (*id, hash.as_str()))
    }

    /// Add event `id`, whose chain hash is the lowercase hex `hash`, as the next
    /// leaf.
    pub fn push(&mut self, id: EventId, hash: &str) -> Result<(), CheckpointError> {
        let data = unhex::<32>(hash).ok_or_else(|| {
            CheckpointError::Malformed(format!("event {id} has no 64-character hex chain hash"))
        })?;
        let mut merged = leaf(&data);
        let mut size = self.size;
        // A set low bit is a subtree of the same size to the left: merge.
        while size & 1 == 1 {
            let Some(left) = self.nodes.pop() else {
                break;
            };
            merged = node(&left, &merged);
            size >>= 1;
        }
        self.nodes.push(merged);
        self.size += 1;
        self.last = Some((id, hash.to_owned()));
        Ok(())
    }

    /// The Merkle tree hash of the leaves pushed so far.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut nodes = self.nodes.iter().rev();
        let Some(mut acc) = nodes.next().copied() else {
            return Sha256::digest(b"").into();
        };
        for left in nodes {
            acc = node(left, &acc);
        }
        acc
    }

    /// The text [`Frontier::parse`] reads: a tag line, `<size> <last id> <last
    /// hash>` (`0 none` before any leaf), then one hex node per line.
    #[must_use]
    pub fn encode(&self) -> String {
        let (id, hash) = self
            .last
            .as_ref()
            .map_or((0, "none"), |(id, hash)| (id.0, hash.as_str()));
        let mut out = format!("{TAG}\n{} {id} {hash}\n", self.size);
        for n in &self.nodes {
            out.push_str(&hex(n));
            out.push('\n');
        }
        out
    }

    /// Parse [`Frontier::encode`]'s text.
    pub fn parse(text: &str) -> Result<Self, CheckpointError> {
        let bad = |why: &str| CheckpointError::Malformed(format!("frontier: {why}"));
        let mut lines = text.lines();
        if lines.next() != Some(TAG) {
            return Err(bad("unknown format"));
        }
        let head = lines.next().ok_or_else(|| bad("no size line"))?;
        let mut words = head.split(' ');
        let (Some(size), Some(id), Some(hash), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return Err(bad("the size line is not `<size> <id> <hash>`"));
        };
        let size: u64 = size.parse().map_err(|_| bad("the size is not a number"))?;
        let id: i64 = id.parse().map_err(|_| bad("the id is not a number"))?;
        let last = match (size, hash) {
            (0, "none") => None,
            (0, _) | (_, "none") => return Err(bad("the last event does not match the size")),
            (_, hash) if unhex::<32>(hash).is_some() => Some((EventId(id), hash.to_owned())),
            _ => return Err(bad("the last hash is not hex")),
        };
        let nodes = lines
            .map(|l| unhex::<32>(l).ok_or_else(|| bad("a node is not hex")))
            .collect::<Result<Vec<_>, _>>()?;
        if nodes.len() != size.count_ones() as usize {
            return Err(bad("the nodes do not match the size"));
        }
        Ok(Self { size, nodes, last })
    }
}

/// The Merkle tree hash of `leaves` (raw 32-byte leaf data), straight from
/// RFC 6962's recursive definition: what the tests check [`Frontier`] against.
#[cfg(test)]
pub(super) fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest(b"").into(),
        1 => leaf(&leaves[0]),
        n => {
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            node(&reference_root(&leaves[..k]), &reference_root(&leaves[k..]))
        }
    }
}
