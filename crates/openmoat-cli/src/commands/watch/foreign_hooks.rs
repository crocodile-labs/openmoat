//! `openmoat watch`'s line for each hook command, plugin hook or git program
//! the foreign-hook ledger finds new or changed (ADR-109): one loud line when
//! one appears, with the shell classifier's verdict on its command and what
//! it does to the agent's calls, and nothing while it stays. It decides
//! nothing.

use std::collections::BTreeSet;

use crate::home::Home;
use crate::hook_ledger::{self, Review};
use crate::integrity::Lock;
use crate::report::{Mark, Style};
use crate::time::clock;

/// The entries (id and digest) the last look named.
#[derive(Default)]
pub struct ForeignHooks {
    seen: BTreeSet<(String, String)>,
}

impl ForeignHooks {
    /// The lines for every entry that is new or changed since the last look,
    /// of the agents OpenMoat set up (only `only`, when given, and git), for
    /// the current directory; nothing without a hook binary or a ledger.
    pub fn look(&mut self, home: &Home, only: Option<&str>, style: Style) -> Vec<String> {
        let Ok(binary) = crate::install::hook_binary() else {
            return Vec::new();
        };
        let Ok(lock) = Lock::load(&home.lock_path()) else {
            return Vec::new();
        };
        let cwd = std::env::current_dir().ok();
        let hosts = crate::mcp::set_up_hosts(home, &binary);
        match hook_ledger::review_here(home, &lock, &hosts, cwd.as_deref()) {
            Ok(found) => self.changes(&found, only, style, crate::time::now_ms()),
            Err(_) => Vec::new(),
        }
    }

    fn changes(
        &mut self,
        found: &Review,
        only: Option<&str>,
        style: Style,
        now: i64,
    ) -> Vec<String> {
        // A lock from before the ledger records nothing yet; `status` says so.
        if !found.recorded {
            return Vec::new();
        }
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        for change in &found.changes {
            if only.is_some_and(|id| change.found.host.is_some_and(|h| h.id() != id)) {
                continue;
            }
            let key = (change.found.id.clone(), change.found.digest.clone());
            if !self.seen.contains(&key) {
                let mark = if change.holds(found.mode) {
                    Mark::Broken
                } else {
                    Mark::Attention
                };
                let text = format!(
                    "Other hooks: {}. `openmoat hooks accept` shows it and asks; {}",
                    change.describe().replace("\n    ", ": "),
                    change.effect(found.mode)
                );
                lines.push(format!(
                    "{} {} {}",
                    style.dim(&clock(now)),
                    style.mark(mark),
                    style.tint(mark, &text)
                ));
            }
            seen.insert(key);
        }
        self.seen = seen;
        lines
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use openmoat_core::{ForeignHooks as Mode, Verdict};
    use openmoat_hosts::Host;

    use super::*;
    use crate::hook_ledger::{Change, Found};

    fn change(id: &str, verdict: Verdict) -> Change {
        Change {
            found: Found {
                id: id.to_owned(),
                host: Some(Host::ALL[0]),
                file: PathBuf::from("/h/.claude/settings.json"),
                what: "hook `SessionStart`".to_owned(),
                commands: vec!["./fmt.sh".to_owned()],
                digest: "d1".to_owned(),
            },
            changed: false,
            verdict,
            rules: Vec::new(),
        }
    }

    fn review(changes: Vec<Change>) -> Review {
        Review {
            recorded: true,
            changes,
            mode: Mode::Warn,
            ..Review::default()
        }
    }

    /// One line when an entry appears, none while it stays; one that is not
    /// denied says the calls are not held.
    #[test]
    fn a_line_per_new_entry_only() {
        let style = Style::new(false, None);
        let mut seen = ForeignHooks::default();
        let found = review(vec![change("a", Verdict::Allow)]);
        let lines = seen.changes(&found, None, style, 0);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("classifies as allow"), "{lines:?}");
        assert!(lines[0].contains("not held"), "{lines:?}");
        assert!(lines[0].contains("openmoat hooks accept"), "{lines:?}");
        assert_eq!(seen.changes(&found, None, style, 1), Vec::<String>::new());
        let denied = review(vec![
            change("a", Verdict::Allow),
            change("b", Verdict::Deny),
        ]);
        let lines = seen.changes(&denied, None, style, 2);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("calls are denied"), "{lines:?}");
        // Another agent than the one watched is left out.
        let mut other = ForeignHooks::default();
        assert_eq!(
            other.changes(&found, Some("no-such-agent"), style, 0),
            Vec::<String>::new()
        );
        // Nothing before the first record.
        let mut fresh = ForeignHooks::default();
        let unrecorded = Review {
            recorded: false,
            ..review(vec![change("a", Verdict::Allow)])
        };
        assert_eq!(
            fresh.changes(&unrecorded, None, style, 0),
            Vec::<String>::new()
        );
    }
}
