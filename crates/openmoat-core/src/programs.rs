//! Executable pinning: which binary a command name really runs.
//!
//! A policy can pin program names to absolute paths (`executables:`), and the
//! kernel records where common programs lived when it was installed. At decision
//! time the first word of every shell command is resolved through a resolver the
//! caller supplies (the core itself never touches the filesystem) and compared
//! with those pins. A `git` that now resolves somewhere else is denied before it
//! runs, which defeats planted binaries and search-path poisoning.

use std::collections::BTreeMap;

use crate::verdict::{Decision, Verdict};

pub const RULE: &str = "executables";

/// Resolves program names using a search path the kernel controls.
pub trait ProgramResolver {
    /// Absolute path `program` would run from, or `None` if it is not found.
    fn resolve(&self, program: &str) -> Option<String>;

    /// Path recorded for `program` when the kernel was installed, if any.
    fn pinned(&self, _program: &str) -> Option<String> {
        None
    }

    /// Where OpenMoat's own binary and its alias are installed. A command
    /// whose program word reaches one of these files, through a link under
    /// another name or on the search path, is decided as `openmoat` too, so
    /// the rules that keep OpenMoat's person-only commands from an agent see
    /// it. By default the pins of `openmoat` and `moat`.
    fn own_binaries(&self) -> Vec<String> {
        ["openmoat", "moat"]
            .iter()
            .filter_map(|name| self.pinned(name))
            .collect()
    }
}

/// Resolver for callers without a search path (tests, `policy check` without state).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoResolver;

impl ProgramResolver for NoResolver {
    fn resolve(&self, _program: &str) -> Option<String> {
        None
    }
}

/// In-memory resolver for tests and conformance fixtures.
#[derive(Debug, Default, Clone)]
pub struct MapResolver {
    /// Program name → path it resolves to on the search path.
    pub resolved: BTreeMap<String, String>,
    /// Program name → path recorded at install time.
    pub pins: BTreeMap<String, String>,
}

impl ProgramResolver for MapResolver {
    fn resolve(&self, program: &str) -> Option<String> {
        self.resolved.get(program).cloned()
    }

    fn pinned(&self, program: &str) -> Option<String> {
        self.pins.get(program).cloned()
    }
}

/// Check one command's program against policy pins and installation pins.
///
/// `argv0` is the command as written; `policy_pins` is the policy's
/// `executables` table. Returns a deny decision on mismatch, `None` when the
/// program is unpinned or runs from an expected path.
pub fn check(
    argv0: &str,
    policy_pins: &BTreeMap<String, Vec<String>>,
    resolver: &dyn ProgramResolver,
) -> Option<Decision> {
    let name = basename(argv0);
    let mut expected: Vec<String> = policy_pins.get(name).cloned().unwrap_or_default();
    if let Some(installed) = resolver.pinned(name)
        && !expected.contains(&installed)
    {
        expected.push(installed);
    }
    if expected.is_empty() {
        return None;
    }
    let actual = if argv0.contains('/') || argv0.contains('\\') {
        Some(argv0.replace('\\', "/"))
    } else {
        resolver.resolve(name)
    };
    let reason = match actual {
        Some(path) if expected.iter().any(|e| e == &path) => return None,
        Some(path) => format!(
            "`{name}` resolves to {path}, not a pinned path ({})",
            expected.join(", ")
        ),
        None => format!(
            "`{name}` is pinned ({}) but was not found on the kernel search path",
            expected.join(", ")
        ),
    };
    Some(Decision::single(Verdict::Deny, RULE, reason))
}

fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(name: &str, path: &str) -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([(name.to_owned(), vec![path.to_owned()])])
    }

    fn resolver(name: &str, path: &str) -> MapResolver {
        MapResolver {
            resolved: BTreeMap::from([(name.to_owned(), path.to_owned())]),
            pins: BTreeMap::new(),
        }
    }

    #[test]
    fn unpinned_programs_are_not_checked() {
        assert!(check("git", &BTreeMap::new(), &NoResolver).is_none());
        assert!(check("git", &BTreeMap::new(), &resolver("git", "/tmp/evil/git")).is_none());
    }

    #[test]
    fn pinned_program_from_expected_path_passes() {
        let p = pins("git", "/usr/bin/git");
        assert!(check("git", &p, &resolver("git", "/usr/bin/git")).is_none());
        assert!(check("/usr/bin/git", &p, &NoResolver).is_none());
    }

    #[test]
    fn planted_or_missing_binary_is_denied() {
        let p = pins("git", "/usr/bin/git");
        let d = check("git", &p, &resolver("git", "/p/node_modules/.bin/git")).unwrap();
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, [RULE]);
        assert!(d.reasons[0].contains("/p/node_modules/.bin/git"));
        let d = check("/tmp/x/git", &p, &NoResolver).unwrap();
        assert!(d.reasons[0].contains("/tmp/x/git"));
        let d = check("git", &p, &NoResolver).unwrap();
        assert!(d.reasons[0].contains("not found"));
    }

    #[test]
    fn installation_pins_count_without_policy_pins() {
        let r = MapResolver {
            resolved: BTreeMap::from([("npm".to_owned(), "/tmp/npm".to_owned())]),
            pins: BTreeMap::from([("npm".to_owned(), "/opt/homebrew/bin/npm".to_owned())]),
        };
        assert!(check("npm", &BTreeMap::new(), &r).is_some());
        let ok = MapResolver {
            resolved: BTreeMap::from([("npm".to_owned(), "/opt/homebrew/bin/npm".to_owned())]),
            ..r
        };
        assert!(check("npm", &BTreeMap::new(), &ok).is_none());
    }
}
