//! Gemini CLI in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/gemini-cli.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Runner, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun,
    WeeklyRuns,
};

pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "gemini-cli",
        install: WeeklyInstall::Npm {
            package: "@google/gemini-cli",
            binary: "node_modules/.bin/gemini",
        },
        checked: Checked {
            version: Some("0.65.0"),
            source: "crates/openmoat-hosts/src/host/gemini_cli/HOST.md",
            note: None,
        },
        config: &[("{GEMINI_CLI_HOME}/.gemini/settings.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "gemini_cli/fixtures/run_shell_command.json",
            command: "/tool_input/command",
            verdict: "/decision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        runners: &[Runner::Linux],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
