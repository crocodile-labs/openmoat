//! The folder rule (ADR-038): reading or writing a folder that holds paths a
//! deny rule names asks.
//!
//! A recursive read (`cp -r ~/.codex x`, `grep -r . ~/.gemini`, `tar czf a.tgz
//! ~/.hermes`) is one `fs.read` of the folder it names, and a deny rule that
//! lists files inside it (`~/.codex/{auth.json,…}`) does not match the folder.
//! An extraction into a folder (`tar xf e.tar -C ~`) is one `fs.write` of it in
//! the same way. So when the folder of an `fs.read` (or `fs.write`) atom is, or
//! is an ancestor of, the literal folder of a deny rule's `fs.read` (or
//! `fs.write`) pattern, the atom asks with [`HOLDS_PROTECTED_RULE`]. The
//! classifier has no notion of "recursive", so a plain `ls ~/.codex` asks too.
//!
//! Patterns with no literal folder (`**/.env`, `**/.claude/settings.json`)
//! contribute nothing, so a search of a project that holds a `.env` keeps its
//! verdict. The rule only adds an ask: a deny on the folder itself still wins.

use super::EvalContext;
use crate::action::AtomicAction;
use crate::kind::Kind;
use crate::pattern::{literal_folder, split_negation};
use crate::policy::RuleGroup;
use crate::verdict::{Decision, Verdict};

/// The rule id of an ask for a folder that holds paths a deny rule names.
pub const HOLDS_PROTECTED_RULE: &str = "protected-contents";

/// The literal folders of the deny rules' path patterns, per kind, compiled
/// once with the policy so that a decision is a scan of short strings.
#[derive(Debug, Default)]
pub(super) struct ProtectedFolders {
    reads: Vec<Folder>,
    writes: Vec<Folder>,
    case_insensitive: bool,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Folder {
    /// With its trailing `/`, ASCII-lowercased when paths compare without case.
    path: String,
    rule: String,
}

impl ProtectedFolders {
    /// The folders of every non-negated `fs.read` and `fs.write` pattern of
    /// `deny`, in every spelling the patterns are compiled with.
    pub(super) fn compile(deny: &[RuleGroup], ctx: &EvalContext) -> Self {
        let case_insensitive = ctx.case_insensitive_paths;
        let folders = |kind: Kind| {
            let mut out: Vec<Folder> = deny
                .iter()
                .flat_map(|group| {
                    group
                        .patterns(kind)
                        .iter()
                        .filter(|p| !split_negation(p).0)
                        .flat_map(|p| ctx.spellings(p))
                        .filter_map(|spelled| {
                            let (negated, body) = split_negation(&spelled);
                            let folder = literal_folder(body).filter(|_| !negated)?;
                            Some(Folder {
                                path: fold(folder, case_insensitive),
                                rule: group.id.clone(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            out.sort();
            out.dedup();
            out
        };
        Self {
            reads: folders(Kind::FsRead),
            writes: folders(Kind::FsWrite),
            case_insensitive,
        }
    }

    /// An ask when `atom` reads or writes a folder that holds a protected
    /// folder (or is one); `None` otherwise.
    pub(super) fn decide(&self, atom: &AtomicAction) -> Option<Decision> {
        let (path, folders, verb) = match atom {
            AtomicAction::FsRead { path } => (path, &self.reads, "reads"),
            AtomicAction::FsWrite { path } => (path, &self.writes, "writes into"),
            _ => return None,
        };
        let dir = fold(path.trim_end_matches('/'), self.case_insensitive);
        let mut rules: Vec<&str> = Vec::new();
        for folder in folders.iter().filter(|f| holds(&dir, &f.path)) {
            if !rules.contains(&folder.rule.as_str()) {
                rules.push(&folder.rule);
            }
        }
        if rules.is_empty() {
            return None;
        }
        let names: Vec<String> = rules.iter().map(|r| format!("`{r}`")).collect();
        let (names, verb_rules) = match names.as_slice() {
            [one] => (one.clone(), "denies"),
            [rest @ .., last] => (format!("{} and {last}", rest.join(", ")), "deny"),
            [] => return None,
        };
        Some(Decision::single(
            Verdict::Ask,
            HOLDS_PROTECTED_RULE,
            format!("{verb} a folder that holds paths {names} {verb_rules}: {path}"),
        ))
    }
}

/// Whether the folder `dir` (no trailing `/`; empty for the root) is
/// `folder` (which ends with `/`) or one of its ancestors.
fn holds(dir: &str, folder: &str) -> bool {
    folder.len() > dir.len() && folder.starts_with(dir) && folder.as_bytes()[dir.len()] == b'/'
}

fn fold(path: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        path.to_ascii_lowercase()
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{HOLDS_PROTECTED_RULE, ProtectedFolders, holds};
    use crate::action::AtomicAction;
    use crate::engine::EvalContext;
    use crate::policy::Policy;
    use crate::verdict::Verdict;

    fn ctx(case_insensitive_paths: bool) -> EvalContext {
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/p".into()),
            real_home: Some("/Volumes/h/me".into()),
            real_project: None,
            moved_dirs: vec![("~/.codex".into(), "/srv/codex".into())],
            cwd: "/p".into(),
            case_insensitive_paths,
        }
    }

    fn folders(case_insensitive: bool) -> ProtectedFolders {
        let policy = Policy::parse(
            r#"
version: 1
deny:
  - id: creds
    hook_only: true
    fs.read: ["~/.codex/{auth.json,x}", "**/.env", "!~/.codex/ok/**", "/", "/srv/a.key"]
    fs.write: ["~/.moat/**"]
  - id: keys
    fs.read: ["~/.ssh/**"]
"#,
        )
        .unwrap();
        ProtectedFolders::compile(&policy.deny, &ctx(case_insensitive))
    }

    fn read(path: &str) -> AtomicAction {
        AtomicAction::FsRead { path: path.into() }
    }

    fn rules(f: &ProtectedFolders, atom: &AtomicAction) -> Option<String> {
        f.decide(atom).map(|d| {
            assert_eq!(d.verdict, Verdict::Ask);
            assert_eq!(d.rules, [HOLDS_PROTECTED_RULE]);
            d.reasons.join("|")
        })
    }

    #[test]
    fn the_folders_cover_every_spelling_and_skip_rootless_patterns() {
        let f = folders(false);
        let paths: Vec<&str> = f.reads.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/Users/me/.codex/",
                "/Users/me/.ssh/",
                "/Volumes/h/me/.codex/",
                "/Volumes/h/me/.ssh/",
                "/srv/",
                "/srv/codex/",
            ]
        );
        let writes: Vec<&str> = f.writes.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(writes, ["/Users/me/.moat/", "/Volumes/h/me/.moat/"]);
    }

    #[test]
    fn a_folder_or_an_ancestor_asks_and_a_folder_below_does_not() {
        let f = folders(false);
        let codex = rules(&f, &read("/Users/me/.codex")).unwrap();
        assert_eq!(
            codex,
            "reads a folder that holds paths `creds` denies: /Users/me/.codex"
        );
        assert!(rules(&f, &read("/Users/me/.codex/")).is_some());
        assert!(rules(&f, &read("/srv/codex")).is_some());
        assert!(rules(&f, &read("/Volumes/h/me/.ssh")).is_some());
        let home = rules(&f, &read("/Users/me")).unwrap();
        assert!(home.contains("`creds` and `keys` deny"), "{home}");
        assert!(rules(&f, &read("/")).is_some());
        for below in [
            "/Users/me/.codex/sessions",
            "/Users/me/.codexx",
            "/Users/me/.cod",
            "/p",
            "/p/.env",
        ] {
            assert_eq!(rules(&f, &read(below)), None, "{below}");
        }
        // a write checks the `fs.write` folders only, and a read the `fs.read` ones
        let write = AtomicAction::FsWrite {
            path: "/Users/me/.codex".into(),
        };
        assert_eq!(rules(&f, &write), None);
        assert!(
            rules(
                &f,
                &AtomicAction::FsWrite {
                    path: "/Users/me".into()
                }
            )
            .is_some()
        );
        assert_eq!(rules(&f, &read("/Users/me/.moat")), None);
    }

    #[test]
    fn folders_compare_without_case_when_paths_do() {
        assert!(rules(&folders(true), &read("/users/ME/.Codex")).is_some());
        assert_eq!(rules(&folders(false), &read("/users/ME/.Codex")), None);
    }

    #[test]
    fn holds_is_the_folder_or_an_ancestor() {
        assert!(holds("/a/b", "/a/b/"));
        assert!(holds("/a", "/a/b/"));
        assert!(holds("", "/a/b/"));
        assert!(!holds("/a/b/c", "/a/b/"));
        assert!(!holds("/a/bc", "/a/b/"));
        assert!(!holds("/a/b", "/a/bc/"));
    }
}
