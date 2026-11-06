//! Warnings about the policy's `check_diff:` section (ADR-055): a content
//! check of `openmoat policy check-diff` the policy turns off.

use super::Warning;
use crate::diffscan::Settings;
use crate::policy::Policy;

/// One warning per rule `check_diff.levels` sets to `off`.
pub(super) fn turned_off(policy: &Policy, out: &mut Vec<Warning>) {
    for id in policy.check_diff.iter().flat_map(Settings::turned_off) {
        out.push(Warning {
            rule: format!("check_diff.levels.{id}"),
            message: format!("`openmoat policy check-diff` no longer reports `{id}` findings"),
        });
    }
}
