//! Process exit codes (ADR-004, ADR-015). Hosts depend on these values.

use std::process::ExitCode;

use openmoat_core::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Success, or verdict `allow`.
    Ok = 0,
    /// The program `moat run` started exited with another status or was
    /// killed. Never a verdict.
    Failed = 1,
    /// Verdict `deny`. Claude Code and Codex treat exit 2 as a blocking hook result.
    Deny = 2,
    /// Verdict `ask` that was not resolved; adapters treat it as deny.
    Ask = 3,
    /// Usage or configuration error from a command a person ran. `guard` never
    /// returns it, not even for arguments it cannot parse: Claude Code and Codex
    /// treat any exit other than 0 or 2 as a non-blocking hook failure, so
    /// `guard` answers `deny` + 2 instead (ADR-015).
    Usage = 64,
}

impl From<Verdict> for Code {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Ok,
            Verdict::Ask => Self::Ask,
            // `Deny`, and any verdict added to the core later: the strictest.
            _ => Self::Deny,
        }
    }
}

impl From<Code> for ExitCode {
    fn from(code: Code) -> Self {
        Self::from(code as u8)
    }
}
