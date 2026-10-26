//! Claude Code's published security advisories that name a fixed version
//! (anthropics/claude-code security advisories, read 2026-10-25), newest fix
//! first.

use crate::contract::{Advisories, Advisory, Platform};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "claude",
    list: &[
        Advisory::new(
            "GHSA-gfvf-j8jh-jxxw",
            "managed settings not applied when a stored API key was preferred",
            ((2, 0, 68), (2, 1, 260)),
            &[],
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-gfvf-j8jh-jxxw",
        ),
        Advisory::new(
            "GHSA-pq7j-f95f-qfcv",
            "plugin commit pin bypass",
            ((0, 0, 0), (2, 1, 179)),
            &[],
            "https://github.com/advisories/GHSA-pq7j-f95f-qfcv",
        ),
        Advisory::new(
            "GHSA-fg94-h982-f3mm",
            "data sent out through a pre-approved WebFetch domain",
            ((0, 2, 54), (2, 1, 163)),
            &[],
            "https://github.com/advisories/GHSA-fg94-h982-f3mm",
        ),
        Advisory::new(
            "GHSA-5j29-h97v-84ch",
            "a symbolic link followed at write time writes any file",
            ((0, 0, 0), (2, 1, 129)),
            &[],
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-5j29-h97v-84ch",
        ),
        Advisory::new(
            "GHSA-q5hj-mxqh-vv77",
            "trust dialog bypass through a spoofed git worktree",
            ((2, 1, 63), (2, 1, 84)),
            &[],
            "https://github.com/advisories/GHSA-q5hj-mxqh-vv77",
        ),
        Advisory::new(
            "GHSA-5cwg-9f6j-9jvx",
            "system-wide configuration loaded from a place other users can write",
            ((0, 0, 0), (2, 1, 75)),
            &[Platform::Windows],
            "https://github.com/advisories/GHSA-5cwg-9f6j-9jvx",
        ),
        Advisory::new(
            "GHSA-mmgp-wc2j-qcv7",
            "trust dialog bypass through a repository's settings file",
            ((0, 0, 0), (2, 1, 53)),
            &[],
            "https://github.com/advisories/GHSA-mmgp-wc2j-qcv7",
        ),
        Advisory::new(
            "GHSA-ff64-7w26-62rf",
            "sandbox escape through settings written into settings.json",
            ((0, 0, 0), (2, 1, 2)),
            &[],
            "https://github.com/advisories/GHSA-ff64-7w26-62rf",
        ),
        Advisory::new(
            "GHSA-jh7p-qr78-84p7",
            "a repository's environment settings used before trust",
            ((0, 0, 0), (2, 0, 65)),
            &[],
            "https://github.com/advisories/GHSA-jh7p-qr78-84p7",
        ),
        Advisory::new(
            "GHSA-4fgq-fpq9-mr3g",
            "commands run before the startup trust dialog",
            ((0, 0, 0), (1, 0, 111)),
            &[],
            "https://github.com/advisories/GHSA-4fgq-fpq9-mr3g",
        ),
        Advisory::new(
            "GHSA-5hhx-v7f6-x7gv",
            "commands run before the startup trust dialog",
            ((0, 0, 0), (1, 0, 39)),
            &[],
            "https://github.com/advisories/GHSA-5hhx-v7f6-x7gv",
        ),
        Advisory::new(
            "GHSA-x5gv-jw7f-j6xj",
            "a permissive default allowlist reads files and sends them out",
            ((0, 0, 0), (1, 0, 4)),
            &[],
            "https://github.com/advisories/GHSA-x5gv-jw7f-j6xj",
        ),
    ],
};
