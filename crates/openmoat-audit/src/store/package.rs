//! The events a package from an agent's own plugin channel decided
//! (`openmoat guard --plugin`, ADR-099), kept apart from those `openmoat
//! init`'s hook or plugin decided, so a call the package sent never counts as
//! `init`'s plugin having loaded ([`Store::host_seen_since`]).

use rusqlite::{Transaction, params};

use super::{Store, StoreError, schema};

impl Store {
    /// This handle, marking every event it records from now on as decided
    /// for a package when `yes`.
    #[must_use]
    pub fn from_package(self, yes: bool) -> Self {
        Self {
            from_package: yes,
            ..self
        }
    }

    /// The schema has the package events table (version 11).
    pub(super) fn package_events(&self) -> bool {
        self.version >= schema::PACKAGE_EVENTS_VERSION
    }
}

/// Mark the event `id`, recorded in `tx`, as a package's.
pub(super) fn mark(tx: &Transaction<'_>, id: i64) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO package_events (event_id) VALUES (?1)",
        params![id],
    )?;
    Ok(())
}
