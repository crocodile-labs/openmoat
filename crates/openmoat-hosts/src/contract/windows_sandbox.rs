//! A host's own Windows sandbox, which its settings switch between modes of
//! different strength (ADR-083). The CLI reads the host's sandbox settings
//! file ([`crate::SandboxSpec::file`]) on Windows and hands its top-level
//! object over; the reader says which mode runs and how much of the sandbox
//! OpenMoat writes it holds, as `openmoat doctor` shows it. No I/O here.

use std::fmt;

use serde_json::{Map, Value};

/// How much of the sandbox settings OpenMoat writes a mode holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WindowsSandboxLevel {
    /// The mode enforces the denied reads and writes OpenMoat writes.
    Holds,
    /// The mode does not enforce denied reads: they hold only through the
    /// hook, and the person can choose a stronger mode.
    ReadsOpen,
    /// The settings do not say which mode runs.
    Unknown,
}

/// Which mode a host's settings select, and why it is at its level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSandboxMode {
    /// How much of OpenMoat's sandbox the mode holds.
    pub level: WindowsSandboxLevel,
    /// One sentence naming the setting, what it means and, below
    /// [`WindowsSandboxLevel::Holds`], the setting that does better.
    pub text: String,
}

/// Reads which of its Windows sandbox modes a host's settings select.
pub trait WindowsSandboxReader: Sync + fmt::Debug {
    /// The mode `root`, the sandbox settings file's top-level object (a TOML
    /// file as JSON), selects.
    fn mode(&self, root: &Map<String, Value>) -> WindowsSandboxMode;
}
