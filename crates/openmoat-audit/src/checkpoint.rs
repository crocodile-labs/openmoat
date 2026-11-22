//! Signed checkpoints of the audit log (ADR-110): a statement, signed with an
//! Ed25519 key, of how many chained events the log held and the Merkle root
//! over them, that anyone holding the public key can check, without the audit
//! key (ADR-101) and on another machine.
//!
//! The format is C2SP's: a `tlog-checkpoint` (origin, tree size, root hash) in
//! a `signed-note`, over an RFC 6962 Merkle tree whose leaves are the events'
//! chain hashes in id order (`merkle.rs`). A checkpoint copied off the machine
//! (or to a witness) shows later that the log still holds the first `size`
//! events unchanged: an edit or rewrite of one of them changes the root, and a
//! log cut below `size` is short. Events after the newest checkpoint are
//! covered by the chain and the audit key only, as before.
//!
//! This crate encodes, parses, signs and checks; the CLI keeps the key file,
//! writes the checkpoints and decides when (`audit_signing.rs`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod encoding;
mod merkle;
mod note;
#[cfg(test)]
mod tests;

pub use merkle::Frontier;
pub use note::{Checkpoint, ORIGIN_PREFIX, SigningKey, VerifierKey};

use crate::store::{ExportedEvent, GENESIS};

/// Why a checkpoint, its key or its signature cannot be used. No message
/// quotes a private key.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckpointError {
    /// The signing key file does not parse.
    #[error("the audit signing key is not valid: {0}")]
    KeyInvalid(String),
    /// A verifier key does not parse.
    #[error("not an OpenMoat audit verifier key: {0}")]
    VerifierKey(String),
    /// A checkpoint, a signature line or a frontier does not parse.
    #[error("not a valid checkpoint: {0}")]
    Malformed(String),
    /// No signature by the given key is on the checkpoint.
    #[error("the checkpoint carries no signature by {0}")]
    NoSignature(String),
    /// A signature by the given key's name and id does not verify: the
    /// checkpoint was changed after it was signed.
    #[error("the checkpoint's signature does not verify: it was changed after it was signed")]
    BadSignature,
    /// The checkpoint names another log than the key's.
    #[error("the checkpoint is for {found}, not for {expected}")]
    OriginMismatch {
        /// The origin the checkpoint names.
        found: String,
        /// The key's name.
        expected: String,
    },
}

/// What a log shows when checked against a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum CheckpointCheck {
    /// The first `size` chained events have the checkpoint's root.
    Holds {
        /// The checkpoint's tree size.
        size: u64,
        /// Chained events in the log or export.
        total: u64,
    },
    /// Fewer chained events than the checkpoint covers: events were deleted.
    Truncated {
        /// The checkpoint's tree size.
        size: u64,
        /// Chained events in the log or export.
        total: u64,
    },
    /// The first `size` events have another root: one was edited, removed,
    /// inserted or rewritten since the checkpoint.
    Differs {
        /// The checkpoint's tree size.
        size: u64,
        /// Chained events in the log or export.
        total: u64,
    },
    /// The export does not start at the log's first chained event (`--since`):
    /// it cannot be checked against a checkpoint of the whole log.
    NotWholeLog,
}

impl CheckpointCheck {
    /// Whether the log holds what the checkpoint states.
    #[must_use]
    pub fn holds(self) -> bool {
        matches!(self, Self::Holds { .. })
    }

    /// A short explanation for people.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Holds { size, total } => format!(
                "the first {size} chained events are as the checkpoint states ({total} in all)"
            ),
            Self::Truncated { size, total } => format!(
                "the checkpoint covers {size} chained events but only {total} are there: events \
                 were deleted"
            ),
            Self::Differs { size, .. } => format!(
                "the first {size} chained events do not have the checkpoint's root: an event \
                 was edited, deleted, inserted or the log rewritten since"
            ),
            Self::NotWholeLog => "the export does not start at the log's first event; export \
                 the whole log (`openmoat audit export` with no filter) to check it"
                .to_owned(),
        }
    }
}

/// Leaves fed one by one, oldest first, and the root at the checkpoint's size.
pub(crate) struct Tally<'a> {
    checkpoint: &'a Checkpoint,
    frontier: Frontier,
    root_at_size: Option<[u8; 32]>,
}

impl<'a> Tally<'a> {
    pub(crate) fn new(checkpoint: &'a Checkpoint) -> Self {
        let frontier = Frontier::new();
        let root_at_size = (checkpoint.size == 0).then(|| frontier.root());
        Self {
            checkpoint,
            frontier,
            root_at_size,
        }
    }

    /// Add the next chained event.
    pub(crate) fn feed(&mut self, id: crate::EventId, hash: &str) -> Result<(), CheckpointError> {
        self.frontier.push(id, hash)?;
        if self.frontier.size() == self.checkpoint.size {
            self.root_at_size = Some(self.frontier.root());
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> CheckpointCheck {
        let (size, total) = (self.checkpoint.size, self.frontier.size());
        match self.root_at_size {
            None => CheckpointCheck::Truncated { size, total },
            Some(root) if root == self.checkpoint.root => CheckpointCheck::Holds { size, total },
            Some(_) => CheckpointCheck::Differs { size, total },
        }
    }
}

/// Check the export `text` against `checkpoint`. The lines' own hashes and
/// links are [`crate::verify_export`]'s to check, which the caller runs too:
/// the root commits to the chain hashes, and only that check ties each hash
/// to its line. A line that does not read is taken as the end of the export.
#[must_use]
pub fn check_export(text: &str, checkpoint: &Checkpoint) -> CheckpointCheck {
    let mut tally = Tally::new(checkpoint);
    let mut first = true;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(event) = serde_json::from_str::<ExportedEvent>(line) else {
            break;
        };
        if first && event.prev_hash != GENESIS {
            return CheckpointCheck::NotWholeLog;
        }
        first = false;
        if tally.feed(event.id, &event.hash).is_err() {
            break;
        }
    }
    tally.finish()
}
