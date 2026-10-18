//! Commands that send local commits to a remote (`git push`, `gh pr create`)
//! and the directories they run in. `moat guard` looks at what such a command
//! would publish (docs/POLICY.md §4.2); finding the commands is the
//! classifier's work, so every spelling it reads (`git -C dir push`,
//! `cd sub && git push`, `sh -c 'git push'`) is found the same way.

use super::{ShellContext, Sink, commands, git};
use crate::action::AtomicAction;
use crate::paths;

/// At most this many pushes are listed for one command line; one more is
/// listed with an unknown directory, so the caller checks what it can and
/// asks for the rest.
const MAX_PUSHES: usize = 16;

/// Environment variables that make git use another repository or other refs
/// than the one the working directory names.
const MOVES_REPOSITORY: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
];

/// A command that publishes local commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// The command without git's global options: `git push …` or `gh pr create …`.
    pub argv: Vec<String>,
    /// Every directory the command may run in, absolute; `None` for one that
    /// is not known (`cd "$X"`, `git --git-dir=…`, a `GIT_DIR=` assignment).
    pub dirs: Vec<Option<String>>,
}

/// Note `argv` in `sink` when it is a push. `program` is its base name.
pub(super) fn note(argv: &[String], program: &str, ctx: &ShellContext<'_>, sink: &mut Sink) {
    let push = match program {
        "git" => {
            let git = git::parse(argv);
            if git.subcommand.get(1).map(String::as_str) != Some("push") {
                return;
            }
            let moved = git.keep_original || sets_repository(sink);
            let dirs = ctx
                .cwd
                .iter()
                .map(|cwd| {
                    if moved {
                        return None;
                    }
                    git.chdirs.iter().try_fold(cwd.clone()?, |dir, chdir| {
                        paths::resolve(chdir, ctx.home, super::WORD_PROJECT, Some(&dir))
                    })
                })
                .collect();
            Push {
                argv: git.subcommand,
                dirs,
            }
        }
        "gh" if argv.get(1..3).is_some_and(|s| s == ["pr", "create"]) => Push {
            argv: argv.to_vec(),
            dirs: if sets_repository(sink) {
                vec![None]
            } else {
                ctx.cwd.to_vec()
            },
        },
        _ => return,
    };
    if sink.pushes.len() > MAX_PUSHES {
        return;
    }
    if sink.pushes.len() == MAX_PUSHES {
        sink.pushes.push(Push {
            argv: push.argv,
            dirs: vec![None],
        });
    } else if !sink.pushes.contains(&push) {
        sink.pushes.push(push);
    }
}

/// Whether the line set, before this point, a variable that moves git to
/// another repository.
fn sets_repository(sink: &Sink) -> bool {
    sink.atoms.iter().any(|atom| {
        matches!(atom, AtomicAction::EnvSet { name } if MOVES_REPOSITORY.contains(&name.as_str()))
    })
}

/// The pushes in `command`, read as the classifier reads it. A part the
/// classifier stops at hides no push it would have found before.
#[must_use]
pub fn pushes(command: &str, ctx: &ShellContext<'_>) -> Vec<Push> {
    let mut sink = Sink::default();
    let _ = commands::classify_into(command, ctx, &mut sink, 0);
    let split = command.replace("${IFS}", " ").replace("$IFS", " ");
    if split != command {
        let _ = commands::classify_into(&split, ctx, &mut sink, 0);
    }
    sink.pushes
}

#[cfg(test)]
mod tests {
    use super::{Push, pushes};
    use crate::shell::ShellContext;

    fn found(command: &str) -> Vec<Push> {
        let cwd = [Some("/w/repo".to_owned())];
        let ctx = ShellContext {
            home: "/h",
            cwd: &cwd,
        };
        pushes(command, &ctx)
    }

    fn dirs(command: &str) -> Vec<Vec<Option<String>>> {
        found(command).into_iter().map(|p| p.dirs).collect()
    }

    fn at(dir: &str) -> Vec<Vec<Option<String>>> {
        vec![vec![Some(dir.to_owned())]]
    }

    #[test]
    fn every_spelling_of_a_push_is_found_with_its_directory() {
        for cmd in [
            "git push",
            "git push origin main",
            "/usr/bin/git push",
            "git --no-pager push -u origin HEAD",
            "sudo git push",
            "sh -c 'git push'",
            "echo $(git push)",
            "git status && git push",
            "gh pr create --fill",
        ] {
            assert_eq!(dirs(cmd), at("/w/repo"), "{cmd}");
        }
        assert_eq!(dirs("git -C sub push"), at("/w/repo/sub"));
        assert_eq!(dirs("git -C /x -C y push"), at("/x/y"));
        // `cd` may fail, so the command may still run where it started.
        let both = |dir: &str| vec![vec![Some("/w/repo".to_owned()), Some(dir.to_owned())]];
        assert_eq!(dirs("cd /other && git push"), both("/other"));
        assert_eq!(dirs("cd ~/r; git push"), both("/h/r"));
        assert_eq!(found("git -C sub push")[0].argv, ["git", "push"]);
    }

    #[test]
    fn a_directory_that_cannot_be_known_is_none() {
        assert_eq!(
            dirs("cd \"$X\" && git push"),
            vec![vec![Some("/w/repo".to_owned()), None]]
        );
        for cmd in [
            "git --git-dir=/elsewhere/.git push",
            "GIT_DIR=/elsewhere/.git git push",
            "export GIT_WORK_TREE=/x; git push",
            "GIT_DIR=/e gh pr create",
        ] {
            assert_eq!(dirs(cmd), vec![vec![None]], "{cmd}");
        }
    }

    #[test]
    fn other_commands_are_not_pushes() {
        for cmd in [
            "git status",
            "git log --grep push",
            "echo git push",
            "gh pr view",
            "gh pr merge 3",
            "git stash push",
        ] {
            assert!(found(cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn many_pushes_end_in_one_with_an_unknown_directory() {
        let line = (0..40)
            .map(|i| format!("git -C d{i} push"))
            .collect::<Vec<_>>()
            .join("; ");
        let all = found(&line);
        assert_eq!(all.len(), 17);
        assert_eq!(all[16].dirs, vec![None]);
    }
}
