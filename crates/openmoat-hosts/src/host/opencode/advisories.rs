//! OpenCode's published security advisories that name a fixed version
//! (anomalyco/opencode security advisories and Pillar Security's write-up,
//! read 2026-10-25), newest fix first.

use crate::contract::{Advisories, Advisory, Platform};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "opencode",
    list: &[
        // No CVE or GHSA; fixed silently in 1.18.33 (2026-09-28). It runs in
        // OpenCode's own process during an MCP sign-in, where no hook sees it.
        Advisory::new(
            "Pillar Security, MCP OAuth",
            "a remote MCP server's sign-in address runs commands",
            ((1, 0, 137), (1, 18, 33)),
            &[Platform::Windows, Platform::Wsl],
            "https://www.pillar.security/blog/open-and-shut-remote-code-execution-in-opencode-via-mcp-oauth",
        ),
        Advisory::new(
            "GHSA-632h-h47v-g4x4",
            "a cross-site upgrade request installs any package",
            ((1, 14, 30), (1, 18, 22)),
            &[],
            "https://github.com/advisories/GHSA-632h-h47v-g4x4",
        ),
        Advisory::new(
            "GHSA-c83v-7274-4vgp",
            "script injection in the web interface runs local commands",
            ((0, 0, 0), (1, 1, 10)),
            &[],
            "https://github.com/advisories/GHSA-c83v-7274-4vgp",
        ),
        Advisory::new(
            "GHSA-vxw4-wv6m-9hhh",
            "an unauthenticated local HTTP server runs any command",
            ((0, 0, 0), (1, 0, 216)),
            &[],
            "https://github.com/advisories/GHSA-vxw4-wv6m-9hhh",
        ),
    ],
};
