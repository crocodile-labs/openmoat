//! GitHub Copilot CLI in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/copilot-cli.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// Copilot CLI caches its packages where `COPILOT_CACHE_HOME` says.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "copilot-cli",
        install: WeeklyInstall::Npm {
            package: "@github/copilot",
            binary: "node_modules/.bin/copilot",
        },
        checked: Checked {
            version: Some("1.0.101"),
            source: "crates/openmoat-hosts/src/host/copilot_cli/HOST.md",
            note: None,
        },
        config: &[("{COPILOT_HOME}/hooks/openmoat.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "copilot_cli/fixtures/bash.json",
            command: "/toolArgs/command",
            verdict: "/permissionDecision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        ..WeeklyRun::BASE
    }]),
    env: &[("COPILOT_CACHE_HOME", "{ROOT}/copilot-cache")],
};
