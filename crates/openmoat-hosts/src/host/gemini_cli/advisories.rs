//! Gemini CLI's published security advisories that name a fixed version
//! (GitHub advisory database, read 2026-10-25).

use crate::contract::{Advisories, Advisory};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "gemini",
    list: &[Advisory::new(
        "GHSA-wpqr-6v78-jr5g",
        "code execution through workspace trust and tool allowlist bypasses",
        ((0, 0, 0), (0, 39, 1)),
        &[],
        "https://github.com/advisories/GHSA-wpqr-6v78-jr5g",
    )],
};
