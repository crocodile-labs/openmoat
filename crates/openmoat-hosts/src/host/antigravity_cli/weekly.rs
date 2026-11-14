//! Antigravity CLI in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/antigravity-cli.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// Installed by Google's install script. The directory tells OpenMoat the
/// CLI is installed; the hook goes beside it.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "antigravity-cli",
        install: WeeklyInstall::Script {
            kind: "agy-installer",
            binary: "{HOME}/.local/bin/agy",
        },
        checked: Checked {
            version: None,
            source: "crates/openmoat-hosts/src/host/antigravity_cli/HOST.md",
            note: Some(
                "built from the documentation, which states no version; the first run of this \
                 job gives the first real payload",
            ),
        },
        dir: Some("{HOME}/.gemini/antigravity-cli"),
        config: &[("{HOME}/.gemini/config/hooks.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "antigravity_cli/fixtures/run_command.json",
            command: "/toolCall/args/CommandLine",
            verdict: "/decision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        // agy's `modelProvider` for the Gemini API, which the fake API
        // stands in for, so no sign-in is asked.
        values: &[("model_provider", "gemini")],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
