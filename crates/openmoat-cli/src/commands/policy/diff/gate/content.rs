//! The core's content checks (`openmoat_core::diffscan`, ADR-055) as findings:
//! each at the level the policy's `check_diff.levels` gives its rule, none
//! for a rule set to `off`. A new host is one the compiled policy does not
//! allow a `net` connection to: the same allow list the hook and the proxy use.

use openmoat_core::diffscan::{self, Change, Hit, Settings};
use openmoat_core::{Action, CompiledPolicy, Verdict};

use super::{FileChange, Finding, Level};

/// `hit` in `path` as a finding, unless the policy turns its rule off.
fn finding(settings: Option<&Settings>, path: &str, hit: Hit) -> Option<Finding> {
    let level = match Settings::level(settings, &hit) {
        diffscan::Level::Off => return None,
        diffscan::Level::Review => Level::Review,
        diffscan::Level::Deny => Level::Deny,
    };
    Some(Finding {
        line: hit.line,
        ..Finding::new(level, path, hit.rule, hit.reason)
    })
}

/// The content findings of one file of the change (not its new hosts). A
/// deleted file adds nothing to check.
pub(super) fn findings(settings: Option<&Settings>, file: &FileChange) -> Vec<Finding> {
    if file.binary || file.new.is_none() {
        return Vec::new();
    }
    let Some(change) = file.content() else {
        return Vec::new();
    };
    diffscan::scan(&change)
        .into_iter()
        .filter_map(|hit| finding(settings, change.path, hit))
        .collect()
}

/// One finding per host the change's code and configuration add that the
/// policy does not allow a connection to. Deleted files count for the hosts
/// they remove: with `--base`, a moved file is a deletion and an addition.
pub(super) fn host_findings(
    policy: &CompiledPolicy<'_>,
    settings: Option<&Settings>,
    files: &[FileChange],
) -> Vec<Finding> {
    let changes: Vec<Change<'_>> = files
        .iter()
        .filter(|f| !f.binary)
        .filter_map(FileChange::content)
        .collect();
    let allowed = |host: &str| {
        let action = Action::Net {
            url: format!("https://{host}/"),
        };
        policy.decide(&action).verdict == Verdict::Allow
    };
    diffscan::new_hosts(&changes, allowed)
        .into_iter()
        .filter_map(|(index, hit)| {
            let path = changes.get(index)?.path;
            finding(settings, path, hit)
        })
        .collect()
}
