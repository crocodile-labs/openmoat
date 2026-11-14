//! The Continue CLI in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/continue.sh`): a canary, not an install.

use crate::contract::{Checked, Runner, Weekly, WeeklyInstall, WeeklyRun, WeeklyRuns};

/// The released package is read, never run: the job fails once `cn` calls
/// its hooks, so OpenMoat can set it up.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "continue",
        install: WeeklyInstall::NpmPack {
            package: "@continuedev/cli",
        },
        checked: Checked {
            version: None,
            source: "crates/openmoat-hosts/src/host/continue_cli/HOST.md",
            note: Some(
                "not set up by openmoat init: the released cn runs no hooks; this job fails once \
                 it does",
            ),
        },
        why: Some("the released `cn` runs no hook, so `openmoat init` does not set it up"),
        runners: &[Runner::Linux],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
