//! `openmoat guard --heartbeat`: the report of a plugin `openmoat init` wrote
//! that its host loaded it (ADR-042).

use openmoat_hosts::Host;

use crate::exit::Code;
use crate::home::Home;
use crate::{guard_relay, time};

/// No call is decided and nothing is read from stdin or written to stdout; a
/// report that cannot be written exits 2, which the plugin ignores. Inside
/// `openmoat run` the sandbox holds no state directory: the report is skipped,
/// and the run's decisions for the host show the plugin loaded instead.
pub(super) fn report(host: Host) -> Code {
    let home = Home::locate().ok();
    let env = |var: &str| std::env::var(var).ok();
    if let guard_relay::Relay::Inside(_) = guard_relay::relay(&env, home.as_ref()) {
        return Code::Ok;
    }
    match Home::locate().and_then(|home| crate::heartbeat::report(&home, host, time::now_ms())) {
        Ok(()) => Code::Ok,
        Err(error) => {
            eprintln!("moat: could not record that {host} loaded the plugin: {error:#}");
            Code::Deny
        }
    }
}
