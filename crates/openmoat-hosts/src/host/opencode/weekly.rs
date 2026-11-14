//! OpenCode 1 and 2 in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/opencode-1.sh`, `opencode-2.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// The directory OpenCode's first start makes.
const DIR: &str = "{XDG_CONFIG_HOME}/opencode";
/// OpenMoat's plugin, which both lines of releases load.
const PLUGIN: (&str, ConfigFormat) = (
    "{XDG_CONFIG_HOME}/opencode/plugins/openmoat.js",
    ConfigFormat::JavaScript,
);
/// Where the versions are recorded.
const SOURCE: &str = "crates/openmoat-hosts/src/host/opencode/HOST.md";

/// For both, the npm bin is a stub that only the postinstall replaces, so
/// the platform package's own binary is run.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[
        WeeklyRun {
            agent: "opencode-1",
            install: WeeklyInstall::Npm {
                package: "opencode-ai",
                binary: "node_modules/opencode-{platform}/bin/opencode",
            },
            checked: Checked {
                version: Some("1.19.4"),
                source: SOURCE,
                note: None,
            },
            dir: Some(DIR),
            config: &[
                PLUGIN,
                ("{XDG_CONFIG_HOME}/opencode/opencode.json", ConfigFormat::Json),
            ],
            payload: Some(WeeklyPayload {
                fixture: "opencode/fixtures/bash.json",
                command: "/args/command",
                verdict: "/decision",
                allow_is_silent: false,
            }),
            proves: &[Proves::Hook, Proves::HookFailure],
            ..WeeklyRun::BASE
        },
        WeeklyRun {
            agent: "opencode-2",
            install: WeeklyInstall::Npm {
                package: "@opencode/cli",
                binary: "node_modules/@opencode/cli-{platform}/bin/opencode",
            },
            checked: Checked {
                version: Some("2.2.0"),
                source: SOURCE,
                note: None,
            },
            dir: Some(DIR),
            config: &[PLUGIN],
            payload: Some(WeeklyPayload {
                fixture: "opencode/fixtures/v2-shell.json",
                command: "/input/command",
                verdict: "/decision",
                allow_is_silent: false,
            }),
            why: Some(
                "it checks only that OpenCode 2 reports OpenMoat's plugin active; no model call \
                 is driven through it yet",
            ),
            ..WeeklyRun::BASE
        },
    ]),
    env: &[],
};
