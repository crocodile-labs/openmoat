//! The step a host needs from the person after `openmoat init` writes its
//! hook, when the host keeps a trust record of its own that OpenMoat cannot
//! see ([`InstallSpec::trust_step`](openmoat_hosts::InstallSpec::trust_step)).

use openmoat_hosts::Host;

use super::Outcome;
use crate::protection::Protection;

/// `host`'s trust step, if its spec has one.
fn step(host: Host) -> Option<&'static str> {
    host.spec().install.as_ref()?.trust_step
}

/// The line `openmoat init` prints after installing `host`'s hook with
/// `outcome`; `None` when the host needs nothing more or nothing changed.
pub fn after_install(host: Host, outcome: Outcome) -> Option<&'static str> {
    if outcome == Outcome::Unchanged {
        return None;
    }
    step(host)
}

/// `openmoat doctor`'s protection line for `agent` ([`Protection::summary`]),
/// `None` when it has none; it ends with the host's trust step when it has one.
pub fn protection_line(agent: &Protection) -> Option<String> {
    let line = format!("{:<16} protection: {}", agent.name, agent.summary()?);
    let step = Host::ALL
        .iter()
        .find(|host| host.id() == agent.host)
        .and_then(|host| step(*host));
    Some(match step {
        Some(step) => format!("{line}; {step}"),
        None => line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(host: Host) -> Protection {
        Protection {
            host: host.id(),
            name: host.display_name(),
            level: crate::protection::Level::HookOnly,
            reason: None,
            gaps: "",
        }
    }

    #[test]
    fn a_host_with_a_trust_step_gets_it_only_when_its_entry_changed() {
        let with: Vec<Host> = Host::ALL
            .iter()
            .copied()
            .filter(|h| step(*h).is_some())
            .collect();
        assert!(!with.is_empty(), "a host has a trust step");
        for host in with {
            assert!(
                after_install(host, Outcome::Installed).is_some(),
                "{host:?}"
            );
            assert!(after_install(host, Outcome::Updated).is_some(), "{host:?}");
            assert_eq!(after_install(host, Outcome::Unchanged), None, "{host:?}");
            let line = protection_line(&agent(host)).unwrap_or_default();
            assert!(line.contains("protection: hook only; "), "{line}");
            assert!(line.contains("/hooks"), "{line}");
        }
    }

    #[test]
    fn other_hosts_get_no_note() {
        for host in Host::ALL.iter().copied().filter(|h| step(*h).is_none()) {
            assert_eq!(after_install(host, Outcome::Installed), None, "{host:?}");
            let line = protection_line(&agent(host)).unwrap_or_default();
            assert!(line.ends_with("protection: hook only"), "{line}");
        }
    }
}
