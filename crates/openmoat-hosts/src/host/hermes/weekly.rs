//! Hermes Agent in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/hermes.sh`).

use crate::contract::{
    Checked, ConfigFormat, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// Installed by the release's own installer; Hermes reads its own
/// `config.yaml`, so its hook list judges it.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "hermes",
        install: WeeklyInstall::Script {
            kind: "hermes-installer",
            binary: "{HERMES_HOME}/hermes-agent/.hermes/bin/hermes",
        },
        checked: Checked {
            version: Some("0.22.5"),
            source: "crates/openmoat-hosts/src/host/hermes/HOST.md",
            note: None,
        },
        config: &[("{HERMES_HOME}/config.yaml", ConfigFormat::Agent("hermes"))],
        payload: Some(WeeklyPayload {
            fixture: "hermes/fixtures/terminal.json",
            command: "/tool_input/command",
            verdict: "hermes",
            allow_is_silent: false,
        }),
        why: Some(
            "`hermes hooks test` runs OpenMoat's hook through the code a session uses, but no \
             model turn dispatches to it",
        ),
        ..WeeklyRun::BASE
    }]),
    env: &[("HERMES_HOME", "{HOME}/.hermes")],
};
