//! pi in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/pi.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Runner, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun,
    WeeklyRuns,
};

pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "pi",
        install: WeeklyInstall::Npm {
            package: "@earendil-works/pi-coding-agent",
            binary: "node_modules/.bin/pi",
        },
        checked: Checked {
            version: Some("1.3.0"),
            source: "crates/openmoat-hosts/src/host/pi/HOST.md",
            note: None,
        },
        config: &[
            (
                "{PI_CODING_AGENT_DIR}/extensions/openmoat.js",
                ConfigFormat::JavaScript,
            ),
            ("{PI_CODING_AGENT_DIR}/models.json", ConfigFormat::Json),
        ],
        payload: Some(WeeklyPayload {
            fixture: "pi/fixtures/bash.json",
            command: "/input/command",
            verdict: "/decision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        runners: &[Runner::Linux],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
