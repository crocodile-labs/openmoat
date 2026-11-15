//! Qwen Code in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/qwen-code.sh`).

use crate::contract::{
    Checked, ConfigFormat, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// The npm package's latest release, `openmoat init`, `status`, `doctor` and
/// the golden payloads; no model turn is driven through a real `qwen` yet, so
/// the record proves nothing about the hook.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "qwen-code",
        install: WeeklyInstall::Npm {
            package: "@qwen-code/qwen-code",
            binary: "node_modules/.bin/qwen",
        },
        checked: Checked {
            version: Some("0.27.3"),
            source: "crates/openmoat-hosts/src/host/qwen_code/HOST.md",
            note: None,
        },
        config: &[("{QWEN_HOME}/settings.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "qwen_code/fixtures/run_shell_command.json",
            command: "/tool_input/command",
            verdict: "/hookSpecificOutput/permissionDecision",
            allow_is_silent: false,
        }),
        why: Some(
            "a preview host: the job installs Qwen Code and checks OpenMoat's hook file and \
             replies, but no model turn is driven through a real `qwen` yet",
        ),
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
