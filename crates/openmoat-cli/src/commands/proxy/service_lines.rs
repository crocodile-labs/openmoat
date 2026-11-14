//! The `doctor` and `status` lines for the proxy's user service.

use crate::home::Home;

/// `moat doctor` and `moat status` lines for the proxy's user service
/// ([`crate::commands::service::lines::lines`]). Silent on platforms without a
/// service story (Windows): `moat proxy install` refuses there, so there is
/// nothing to report under `moat doctor`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn service_lines(home: &Home) -> Vec<(bool, String)> {
    use crate::commands::service::{PROXY, lines};
    lines::lines(home, &PROXY, "service")
}

/// Windows: `moat doctor` and `moat status` have no service line.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn service_lines(_home: &Home) -> Vec<(bool, String)> {
    Vec::new()
}
