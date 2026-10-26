//! Hermes Agent's published security advisories that name a fixed version
//! (GitHub advisory database, package `hermes-agent`, read 2026-10-25), newest
//! fix first. GHSA-xq8w-9jvx-gm3v and GHSA-pmqc-57g8-c22c name no fixed
//! version and are left out.

use crate::contract::{Advisories, Advisory};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "hermes",
    list: &[
        Advisory::new(
            "GHSA-mv8x-fg99-32mf",
            "injection",
            ((0, 0, 0), (0, 18, 0)),
            &[],
            "https://github.com/advisories/GHSA-mv8x-fg99-32mf",
        ),
        Advisory::new(
            "GHSA-4pqm-j46f-795x",
            "DNS rebinding of its WebSocket endpoints",
            ((0, 0, 0), (0, 16, 0)),
            &[],
            "https://github.com/advisories/GHSA-4pqm-j46f-795x",
        ),
        Advisory::new(
            "GHSA-99f9-j8r3-p853",
            "files holding webhook secrets created readable by every user",
            ((0, 0, 0), (0, 16, 0)),
            &[],
            "https://github.com/advisories/GHSA-99f9-j8r3-p853",
        ),
        Advisory::new(
            "GHSA-238w-f66p-w349",
            "injection",
            ((0, 0, 0), (0, 15, 0)),
            &[],
            "https://github.com/advisories/GHSA-238w-f66p-w349",
        ),
        Advisory::new(
            "GHSA-pgp4-xr4j-h5cg",
            "injection",
            ((0, 0, 0), (0, 15, 0)),
            &[],
            "https://github.com/advisories/GHSA-pgp4-xr4j-h5cg",
        ),
        Advisory::new(
            "GHSA-33qv-c5qm-799v",
            "injection",
            ((0, 0, 0), (0, 15, 0)),
            &[],
            "https://github.com/advisories/GHSA-33qv-c5qm-799v",
        ),
        Advisory::new(
            "GHSA-cv5c-mh6j-wvp9",
            "incorrect comparison",
            ((0, 0, 0), (0, 15, 0)),
            &[],
            "https://github.com/advisories/GHSA-cv5c-mh6j-wvp9",
        ),
        Advisory::new(
            "GHSA-wm96-9gfh-vvgq",
            "sandbox issue",
            ((0, 0, 0), (0, 11, 0)),
            &[],
            "https://github.com/advisories/GHSA-wm96-9gfh-vvgq",
        ),
    ],
};
