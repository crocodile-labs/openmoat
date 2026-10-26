//! GitHub Copilot CLI's published security advisories that name a fixed
//! version (github/copilot-cli security advisories, read 2026-10-25), newest
//! fix first.

use crate::contract::{Advisories, Advisory};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "copilot",
    list: &[
        Advisory::new(
            "GHSA-9ccr-r5hg-74gf",
            "a nested bare repository runs commands through `core.fsmonitor`",
            ((0, 0, 0), (1, 0, 43)),
            &[],
            "https://github.com/advisories/GHSA-9ccr-r5hg-74gf",
        ),
        Advisory::new(
            "GHSA-g8r9-g2v8-jv6f",
            "shell expansion patterns run arbitrary code",
            ((0, 0, 0), (0, 0, 423)),
            &[],
            "https://github.com/advisories/GHSA-g8r9-g2v8-jv6f",
        ),
    ],
};
