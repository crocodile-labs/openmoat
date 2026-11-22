//! The database's side of signed checkpoints (ADR-110): the chained events as
//! Merkle leaves, read in id order.

use rusqlite::params;

use super::{EventId, Store, StoreError};
use crate::checkpoint::{Checkpoint, CheckpointCheck, CheckpointError, Frontier, Tally};

/// The chained events after an id, oldest first: the rows an export holds.
const LEAVES: &str = "SELECT id, hash FROM events WHERE hash IS NOT NULL AND prev_hash IS NOT NULL \
                      AND id > ?1 ORDER BY id";

fn decode(id: EventId, error: &CheckpointError) -> StoreError {
    StoreError::Decode {
        id,
        reason: error.to_string(),
    }
}

impl Store {
    /// Push every chained event after `frontier`'s last one onto it. When its
    /// last event is gone or has another hash now, it is rebuilt from the
    /// first event, and `true` is returned: the log changed under it, which
    /// the next checkpoint's root then shows against the earlier ones.
    pub fn extend_frontier(&self, frontier: &mut Frontier) -> Result<bool, StoreError> {
        let rebuilt = match frontier.last() {
            None => frontier.size() > 0,
            Some((id, hash)) => self.hash_of(id)?.as_deref() != Some(hash),
        };
        if rebuilt {
            *frontier = Frontier::new();
        }
        let after = frontier.last().map_or(0, |(id, _)| id.0);
        self.each_leaf(after, |id, hash| {
            frontier.push(id, hash).map_err(|e| decode(id, &e))
        })?;
        Ok(rebuilt)
    }

    /// The tree over every chained event, read from the first.
    pub fn frontier(&self) -> Result<Frontier, StoreError> {
        let mut frontier = Frontier::new();
        self.extend_frontier(&mut frontier)?;
        Ok(frontier)
    }

    /// Check this log against `checkpoint`, reading every chained event.
    pub fn check_checkpoint(&self, checkpoint: &Checkpoint) -> Result<CheckpointCheck, StoreError> {
        let mut tally = Tally::new(checkpoint);
        self.each_leaf(0, |id, hash| {
            tally.feed(id, hash).map_err(|e| decode(id, &e))
        })?;
        Ok(tally.finish())
    }

    fn each_leaf(
        &self,
        after: i64,
        mut each: impl FnMut(EventId, &str) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if !self.chained() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare(LEAVES)?;
        let mut rows = stmt.query(params![after])?;
        while let Some(row) = rows.next()? {
            let id = EventId(row.get(0)?);
            let hash: String = row.get(1)?;
            each(id, &hash)?;
        }
        Ok(())
    }
}
