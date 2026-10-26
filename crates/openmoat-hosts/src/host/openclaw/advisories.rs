//! OpenClaw's published security advisories about credentials, secrets and
//! MCP configuration that name a fixed version (openclaw/openclaw security
//! advisories, read 2026-10-25), newest fix first. Its versions are dates
//! (`2026.10.7`), compared as three numbers. GHSA-g8p2-7wf7-98mq is left out:
//! it names the old `clawdbot` package.

use crate::contract::{Advisories, Advisory, Platform};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "openclaw",
    list: &[
        Advisory::new(
            "GHSA-vhpg-cq3w-v8p9",
            "provider credentials sent to the wrong endpoint",
            ((0, 0, 0), (2026, 8, 1)),
            &[],
            "https://github.com/advisories/GHSA-vhpg-cq3w-v8p9",
        ),
        Advisory::new(
            "GHSA-wwx7-573h-pqwc",
            "MCP configuration changes without the owner's authorisation",
            ((0, 0, 0), (2026, 7, 1)),
            &[],
            "https://github.com/advisories/GHSA-wwx7-573h-pqwc",
        ),
        Advisory::new(
            "GHSA-9c3v-684m-579c",
            "MCP SSE redirects forward Authorization headers",
            ((0, 0, 0), (2026, 6, 5)),
            &[],
            "https://github.com/advisories/GHSA-9c3v-684m-579c",
        ),
        Advisory::new(
            "GHSA-4pqj-3c56-5fqq",
            "a workspace's dotenv files override provider credentials",
            ((0, 0, 0), (2026, 5, 28)),
            &[],
            "https://github.com/advisories/GHSA-4pqj-3c56-5fqq",
        ),
        Advisory::new(
            "GHSA-rjxq-qqhf-8hwh",
            "MCP HTTP redirects forward custom headers to another origin",
            ((0, 0, 0), (2026, 5, 12)),
            &[],
            "https://github.com/advisories/GHSA-rjxq-qqhf-8hwh",
        ),
        Advisory::new(
            "GHSA-mj59-h3q9-ghfh",
            "a workspace's MCP server settings load dangerous startup variables",
            ((0, 0, 0), (2026, 4, 20)),
            &[],
            "https://github.com/advisories/GHSA-mj59-h3q9-ghfh",
        ),
        Advisory::new(
            "GHSA-57gh-m6rq-54cf",
            "the model reads any host file and its credentials through media roots",
            ((0, 0, 0), (2026, 3, 31)),
            &[],
            "https://github.com/advisories/GHSA-57gh-m6rq-54cf",
        ),
        Advisory::new(
            "GHSA-4564-pvr2-qq4h",
            "shell injection in the macOS keychain credential write",
            ((0, 0, 0), (2026, 2, 14)),
            &[Platform::MacOs],
            "https://github.com/advisories/GHSA-4564-pvr2-qq4h",
        ),
        Advisory::new(
            "GHSA-47q7-97xp-m272",
            "configuration writes could save resolved secrets to disk",
            ((0, 0, 0), (2026, 2, 13)),
            &[],
            "https://github.com/advisories/GHSA-47q7-97xp-m272",
        ),
    ],
};
