//! Local audit log: every decision the kernel makes, append-only, redacted.
//!
//! One `SQLite` file in WAL mode. Several `moat guard` processes may write at
//! once (parallel tool calls, several agents), so each write is one short
//! `BEGIN IMMEDIATE` transaction with a busy timeout: it reads the newest event's
//! hash and appends the next event linked to it, so the hash chain never forks.

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod query;
mod redact;
mod store;
#[cfg(feature = "test-support")]
pub mod testing;

pub use query::{SessionSummary, Summary};
pub use redact::{KnownSecrets, MIN_SECRET_LEN, redact, redact_value};
pub use store::{
    AnchorCheck, BreakKind, Cached, ChainBreak, ChainReport, Event, EventId, ExportBreak,
    ExportFilter, ExportFormat, ExportReport, ExportedEvent, GENESIS, NewEvent, Store, StoreError,
    verify_export,
};
