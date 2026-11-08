//! The `doctor` and `status` lines for the proxy's user service.

use crate::home::Home;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::commands::service::{self, State};

/// `moat doctor` and `moat status` lines for the user service: not installed
/// is silent (opt-in), installed is a line, drift / crashloop is a problem.
/// Returns `(ok, text)` so the caller renders the icon. Silent on platforms
/// without a service story (Windows): `moat proxy install` refuses there, so
/// there is nothing to report under `moat doctor`.
/// After the state, one problem line for each way the installed file differs
/// from what `moat proxy install` writes ([`service::read_back()`]).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn service_lines(home: &Home) -> Vec<(bool, String)> {
    let Ok(manager) = service::manager(home) else {
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
    let mut lines = vec![(ok, format!("service          {}", state.describe(&path)))];
    let findings = match crate::install::hook_binary() {
        Ok(binary) => service::read_back(manager.as_ref(), &binary, home.root()),
        Err(e) => vec![format!("cannot be compared: {e:#}")],
    };
    lines.extend(findings.into_iter().map(|finding| {
        (
            false,
            format!(
                "service file     {} {finding}; `openmoat proxy install` writes it again",
                path.display()
            ),
        )
    }));
    lines
}

/// Windows: `moat doctor` and `moat status` have no service line.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn service_lines(_home: &Home) -> Vec<(bool, String)> {
    Vec::new()
}
