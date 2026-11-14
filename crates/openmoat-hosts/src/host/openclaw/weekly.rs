//! OpenClaw in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/openclaw.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// OpenClaw reads `openclaw.json` as JSON5, so its own validator judges it.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "openclaw",
        install: WeeklyInstall::Npm {
            package: "openclaw",
            binary: "node_modules/.bin/openclaw",
        },
        checked: Checked {
            version: Some("2026.10.5"),
            source: "crates/openmoat-hosts/src/host/openclaw/fixtures/README.md",
            note: None,
        },
        dir: Some("{OPENCLAW_STATE_DIR}"),
        config: &[(
            "{OPENCLAW_STATE_DIR}/openclaw.json",
            ConfigFormat::Agent("openclaw"),
        )],
        payload: Some(WeeklyPayload {
            fixture: "openclaw/fixtures/exec.json",
            command: "/params/command",
            verdict: "/decision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        ..WeeklyRun::BASE
    }]),
    env: &[("OPENCLAW_STATE_DIR", "{HOME}/.openclaw")],
};
