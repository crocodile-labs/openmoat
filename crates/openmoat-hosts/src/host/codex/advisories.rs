//! Codex's published security advisories that name a fixed version
//! (openai/codex security advisories, read 2026-10-25). GHSA-xrxf-jgv3-qmrm
//! names no fixed version and is left out.

use crate::contract::{Advisories, Advisory};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "codex",
    list: &[Advisory::new(
        "GHSA-w5fx-fh39-j5rw",
        "sandbox bypass from a bug in its path configuration",
        ((0, 2, 0), (0, 39, 0)),
        &[],
        "https://github.com/advisories/GHSA-w5fx-fh39-j5rw",
    )],
};
