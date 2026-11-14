//! Cursor in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/cursor.sh`).

use crate::contract::{
    Checked, ConfigFormat, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// Installed from the package Cursor's install script names.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "cursor",
        install: WeeklyInstall::Script {
            kind: "cursor-installer",
            binary: "cursor-agent",
        },
        checked: Checked {
            version: None,
            source: "crates/openmoat-hosts/src/host/cursor/HOST.md",
            note: Some(
                "the adapter is checked against Cursor's hooks documentation, not a CLI release",
            ),
        },
        config: &[("{CURSOR_CONFIG_DIR}/hooks.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "cursor/fixtures/beforeShellExecution.json",
            command: "/command",
            verdict: "/permission",
            allow_is_silent: false,
        }),
        why: Some("every `cursor-agent` run needs a Cursor account, so the job never starts the agent"),
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
