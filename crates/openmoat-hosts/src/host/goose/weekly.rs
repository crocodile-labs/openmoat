//! goose in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/goose.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// Installed from the release's archive. The directory is goose's own
/// configuration directory (`config.yaml`); its plugins go in `~/.agents`.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "goose",
        install: WeeklyInstall::Script {
            kind: "goose-release",
            binary: "goose",
        },
        checked: Checked {
            version: Some("1.57.0"),
            source: "crates/openmoat-hosts/src/host/goose/HOST.md",
            note: None,
        },
        dir: Some("{XDG_CONFIG_HOME}/goose"),
        config: &[(
            "{HOME}/.agents/plugins/openmoat/hooks/hooks.json",
            ConfigFormat::Json,
        )],
        payload: Some(WeeklyPayload {
            fixture: "goose/fixtures/shell.json",
            command: "/tool_input/command",
            verdict: "goose",
            allow_is_silent: true,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
