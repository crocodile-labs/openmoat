//! Other spellings of a shell command that its rules must see too.
//!
//! The `kernel-self` rules name OpenMoat's person-only commands by program
//! name (`openmoat allow`, `*/openmoat allow`). Two spellings run the same
//! binary without that name:
//!
//! - a link under another name (`ln -s …/openmoat /tmp/x; /tmp/x allow`), or a
//!   name on the search path that resolves to it: a word that reaches one of
//!   [`ProgramResolver::own_binaries`] reads as `openmoat`;
//! - another case of the name where file names ignore case (`OpenMoat allow`
//!   on macOS): the program word, and every word naming `moat` in any case
//!   (after `script`, inside `tmux new '…'`), are read lowercase.
//!
//! Each such spelling is one extra shell atom. Only a deny or ask rule it
//! matches counts ([`super::CompiledPolicy::decide_with`]), so it can make a
//! call stricter, never change what else the call is allowed.

use super::EvalContext;
use crate::action::AtomicAction;
use crate::paths;
use crate::programs::ProgramResolver;
use crate::realpath::PathResolver;

/// The name a word that runs OpenMoat's own binary reads as.
const OWN_NAME: &str = "openmoat";

/// The extra spellings of each shell atom in `atoms`, as described above.
pub(super) fn aliases(
    atoms: &[AtomicAction],
    ctx: &EvalContext,
    resolver: &dyn ProgramResolver,
    paths: &dyn PathResolver,
) -> Vec<AtomicAction> {
    let own = own_files(resolver, paths);
    if own.is_empty() && !ctx.case_insensitive_paths {
        return Vec::new();
    }
    let same = |a: &str, b: &str| {
        if ctx.case_insensitive_paths {
            a.to_lowercase() == b.to_lowercase()
        } else {
            a == b
        }
    };
    let runs_own = |at: usize, word: &str| {
        let Some(path) = program_path(at, word, ctx, resolver) else {
            return false;
        };
        let real = paths.resolve(&path);
        [Some(path), real]
            .into_iter()
            .flatten()
            .any(|p| own.iter().any(|o| same(o, &p)))
    };
    atoms
        .iter()
        .filter_map(|atom| {
            let AtomicAction::Shell { argv } = atom else {
                return None;
            };
            let alias: Vec<String> = argv
                .iter()
                .enumerate()
                .map(|(at, word)| {
                    if !own.is_empty() && runs_own(at, word) {
                        OWN_NAME.to_owned()
                    } else if ctx.case_insensitive_paths
                        && (at == 0 || word.to_lowercase().contains("moat"))
                    {
                        word.to_lowercase()
                    } else {
                        word.clone()
                    }
                })
                .collect();
            (alias != *argv).then_some(AtomicAction::Shell { argv: alias })
        })
        .collect()
}

/// [`ProgramResolver::own_binaries`] and where each resolves through links.
fn own_files(resolver: &dyn ProgramResolver, paths: &dyn PathResolver) -> Vec<String> {
    let mut own = resolver.own_binaries();
    let real: Vec<String> = own.iter().filter_map(|p| paths.resolve(p)).collect();
    own.extend(real);
    own
}

/// The file `word` would run as a program: a path as written (`/tmp/x`,
/// `./x`, `~/bin/x`), or for the program word a bare name as the search path
/// resolves it. `None` for a word that is no path: an option, a URL, a phrase.
fn program_path(
    at: usize,
    word: &str,
    ctx: &EvalContext,
    resolver: &dyn ProgramResolver,
) -> Option<String> {
    let plain = !word.is_empty()
        && !word.starts_with('-')
        && !word.contains("://")
        && !word.contains(char::is_whitespace);
    if !plain {
        return None;
    }
    if word.contains('/') {
        Some(paths::normalise(
            word,
            &ctx.home,
            ctx.project.as_deref(),
            &ctx.cwd,
        ))
    } else if at == 0 {
        resolver.resolve(word)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::programs::MapResolver;
    use crate::realpath::MapPathResolver;

    fn ctx(case_insensitive_paths: bool) -> EvalContext {
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".into(),
            case_insensitive_paths,
        }
    }

    fn shell(words: &[&str]) -> AtomicAction {
        AtomicAction::Shell {
            argv: words.iter().map(|w| (*w).to_owned()).collect(),
        }
    }

    fn installed() -> MapResolver {
        MapResolver {
            resolved: BTreeMap::from([("om".to_owned(), "/opt/bin/om".to_owned())]),
            pins: BTreeMap::from([("openmoat".to_owned(), "/usr/local/bin/openmoat".to_owned())]),
        }
    }

    fn links() -> MapPathResolver {
        MapPathResolver {
            links: BTreeMap::from([
                ("/tmp/x".to_owned(), "/usr/local/bin/openmoat".to_owned()),
                (
                    "/opt/bin/om".to_owned(),
                    "/usr/local/bin/openmoat".to_owned(),
                ),
            ]),
            files: Vec::new(),
        }
    }

    #[test]
    fn a_link_or_search_path_name_reaching_the_binary_reads_as_openmoat() {
        for words in [
            &["/tmp/x", "allow", "--last"][..],
            &["om", "allow", "--last"],
            &["script", "-q", "/dev/null", "/tmp/x", "allow"],
        ] {
            let got = aliases(&[shell(words)], &ctx(false), &installed(), &links());
            let AtomicAction::Shell { argv } = &got[0] else {
                panic!("{got:?}")
            };
            assert!(argv.iter().any(|w| w == "openmoat"), "{argv:?}");
        }
    }

    #[test]
    fn other_programs_and_words_get_no_alias() {
        for words in [
            &["/tmp/y", "allow"][..],
            &["git", "status"],
            &["echo", "om"],
            &["cat", "/usr/local/bin/openmoat-notes"],
        ] {
            assert!(
                aliases(&[shell(words)], &ctx(false), &installed(), &links()).is_empty(),
                "{words:?}"
            );
        }
        let none = MapResolver::default();
        let plain = MapPathResolver::default();
        assert!(aliases(&[shell(&["/tmp/x", "allow"])], &ctx(false), &none, &plain).is_empty());
    }

    #[test]
    fn where_names_ignore_case_the_program_and_moat_words_read_lowercase() {
        let none = MapResolver::default();
        let plain = MapPathResolver::default();
        let got = aliases(
            &[shell(&[
                "script",
                "-q",
                "/dev/null",
                "OpenMoat",
                "allow",
                "Q",
            ])],
            &ctx(true),
            &none,
            &plain,
        );
        assert_eq!(
            got,
            [shell(&[
                "script",
                "-q",
                "/dev/null",
                "openmoat",
                "allow",
                "Q"
            ])]
        );
        let path = aliases(
            &[shell(&["/usr/local/bin/OPENMOAT", "proxy", "uninstall"])],
            &ctx(true),
            &none,
            &plain,
        );
        assert_eq!(
            path,
            [shell(&["/usr/local/bin/openmoat", "proxy", "uninstall"])]
        );
        assert!(aliases(&[shell(&["OpenMoat", "allow"])], &ctx(false), &none, &plain).is_empty());
    }
}
