//! The Cline CLI in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/cline.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "cline",
        install: WeeklyInstall::Npm {
            package: "cline",
            binary: "node_modules/.bin/cline",
        },
        checked: Checked {
            version: Some("3.0.74"),
            source: "crates/openmoat-hosts/src/host/cline/HOST.md",
            note: None,
        },
        config: &[("{CLINE_DIR}/hooks/PreToolUse", ConfigFormat::Shell)],
        payload: Some(WeeklyPayload {
            fixture: "cline/fixtures/run_commands.json",
            command: "/tool_call/input/commands/0",
            verdict: "cline",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
