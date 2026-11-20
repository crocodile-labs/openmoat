//! `openmoat watch`'s warning that an agent runs without OpenMoat seeing its
//! calls (ADR-042, ADR-104): one loud line when a set-up agent's plugin or
//! hook turns missing, one when its calls reach OpenMoat again, and nothing
//! while the state stays. It decides nothing.

use std::collections::BTreeMap;
use std::path::Path;

use openmoat_hosts::Host;

use crate::heartbeat::{self, Loaded};
use crate::home::Home;
use crate::report::{Mark, Style};
use crate::time::clock;

/// How often the agents' state is looked at, in looks at the audit log: the
/// session files are read each time, so not twice a second.
pub const EVERY: u32 = 60;

/// What the last look saw, per agent.
#[derive(Default)]
pub struct Liveness {
    missing: BTreeMap<&'static str, bool>,
}

impl Liveness {
    /// The lines for every change since the last look at the agents OpenMoat
    /// set up (only `only`, when given); nothing without a hook binary.
    pub fn look(&mut self, home: &Home, only: Option<&str>, style: Style) -> Vec<String> {
        let Ok(binary) = crate::install::hook_binary() else {
            return Vec::new();
        };
        self.changes(&binary_states(home, &binary), only, style)
    }

    fn changes(
        &mut self,
        states: &[(Host, Loaded)],
        only: Option<&str>,
        style: Style,
    ) -> Vec<String> {
        let now = crate::time::now_ms();
        let mut lines = Vec::new();
        for (host, loaded) in states {
            if only.is_some_and(|id| id != host.id()) {
                continue;
            }
            let missing = matches!(loaded, Loaded::Missing { .. });
            let before = self.missing.insert(host.id(), missing);
            // The first look reports only a missing one; a fine agent is what
            // the header already says.
            match (before.unwrap_or(false), missing) {
                (false, true) => {
                    let (_, text) = heartbeat::line(*host, loaded);
                    lines.push(format!(
                        "{} {} {}",
                        style.dim(&clock(now)),
                        style.mark(Mark::Broken),
                        style.tint(
                            Mark::Broken,
                            &format!(
                                "{}: {text}. Run `openmoat doctor` for the fix",
                                host.display_name()
                            )
                        )
                    ));
                }
                (true, false) => lines.push(format!(
                    "{} {} {}: OpenMoat sees its calls again",
                    style.dim(&clock(now)),
                    style.mark(Mark::Ok),
                    host.display_name()
                )),
                _ => {}
            }
        }
        lines
    }
}

fn binary_states(home: &Home, binary: &Path) -> Vec<(Host, Loaded)> {
    heartbeat::all(home, binary)
        .into_iter()
        .map(|one| (one.of, one.loaded))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::{Change, Since};

    fn missing() -> Loaded {
        Loaded::Missing {
            since: Since {
                change: Change::HookWritten,
                at_ms: 0,
            },
            active_ms: 10,
            sessions: 2,
        }
    }

    fn reported() -> Loaded {
        Loaded::Reported {
            since: Since {
                change: Change::HookWritten,
                at_ms: 0,
            },
            at_ms: 20,
        }
    }

    /// One line when an agent turns missing, none while it stays, one when
    /// its calls come back; a fine agent at the start says nothing.
    #[test]
    fn a_line_per_change_of_state_only() {
        let host = Host::ALL[0];
        let style = Style::new(false, None);
        let mut seen = Liveness::default();
        let none: Vec<String> = Vec::new();
        assert_eq!(seen.changes(&[(host, reported())], None, style), none);
        let lines = seen.changes(&[(host, missing())], None, style);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(host.display_name()), "{lines:?}");
        assert!(lines[0].contains("`openmoat doctor`"), "{lines:?}");
        assert_eq!(seen.changes(&[(host, missing())], None, style), none);
        let back = seen.changes(&[(host, reported())], None, style);
        assert_eq!(back.len(), 1, "{back:?}");
        assert!(back[0].contains("sees its calls again"), "{back:?}");
        // Another agent than the one watched is left out.
        let mut other = Liveness::default();
        assert_eq!(
            other.changes(&[(host, missing())], Some("no-such-agent"), style),
            none
        );
    }
}
