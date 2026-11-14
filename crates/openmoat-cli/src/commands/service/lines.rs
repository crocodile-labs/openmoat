//! The `doctor` and `status` lines for one user service ([`Job`]).

use super::{Job, State};
use crate::home::Home;

/// The lines for `job`'s user service: not installed is silent (opt-in),
/// installed is a line, drift / crashloop is a problem. `(ok, text)`, so the
/// caller renders the icon; `row` is the label the state line starts with,
/// and `<row> file` the label of each finding. After the state, one problem
/// line for each way the installed file differs from what the job's install
/// command writes ([`super::read_back()`]).
pub fn lines(home: &Home, job: &'static Job, row: &str) -> Vec<(bool, String)> {
    let Ok(manager) = super::manager(home, job) else {
        return Vec::new();
    };
    let (Ok(state), Ok(path)) = (manager.state(), manager.file_path()) else {
        return Vec::new();
    };
    let ok = match state {
        State::NotInstalled => return Vec::new(),
        State::Running => true,
        _ => false,
    };
    let mut lines = vec![(ok, format!("{row:<16} {}", state.describe(job, &path)))];
    lines.extend(findings(home, manager.as_ref()).into_iter().map(|finding| {
        (
            false,
            format!(
                "{:<16} {} {finding}; `{}` writes it again",
                format!("{row} file"),
                path.display(),
                job.install
            ),
        )
    }));
    lines
}

/// How the installed file differs from what `manager`'s job writes for the
/// pinned binary and this state directory; empty when it does not, or when
/// nothing is installed.
pub fn findings(home: &Home, manager: &dyn super::Manager) -> Vec<String> {
    match crate::install::hook_binary() {
        Ok(binary) => super::read_back(manager, &binary, home.root()),
        Err(e) => vec![format!("cannot be compared: {e:#}")],
    }
}
