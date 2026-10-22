//! Working directories moved to by `cd` and `pushd` within one command line.
//!
//! `cd ~/.ssh && cat id_rsa` reads `~/.ssh/id_rsa`, so relative paths after a
//! `cd` resolve against its target. Whether a later command runs before or
//! after the move (`cd x || cat y`, `false || cd x && cat y`, a failed `cd`
//! before `;`) is not tracked: every directory the command line may be in is
//! kept, and a relative path becomes one action per directory, so the
//! strictest verdict covers all of them. A subshell `( … )` restores the set
//! when it closes, and `$( … )`, `sh -c` and other nested commands start from
//! the set in effect where they appear.
//!
//! A target that cannot be known (`cd "$DIR"`, `cd -`, `cd s*`, `popd`, and
//! `eval` or `source`, which can run a `cd` of their own) adds an unknown
//! directory: relative paths after it cannot be resolved and the command asks.
//! Entering a directory reads nothing, so `cd` adds no action of its own beyond
//! what any argument gets (a path-looking target is still an `fs.read`, as
//! before); what is read after it is checked at its resolved location.
//! `CDPATH` is not consulted.

use super::tables::{CWD_PREFIXES, MAY_CHANGE_CWD};
use super::tokens::assignment_name;
use super::{ClassifyError, MAX_DIRS, ShellContext};
use crate::lexer::Word;

/// Add `moved` to the directories the command line may be in.
pub(super) fn merge(
    dirs: &mut Vec<Option<String>>,
    moved: Vec<Option<String>>,
) -> Result<(), ClassifyError> {
    for dir in moved {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    if dirs.len() > MAX_DIRS {
        return Err(ClassifyError::TooManyDirectories);
    }
    Ok(())
}

/// The directories the simple command `words`, run with `ctx`, may leave the
/// shell in; empty when it does not move it.
pub(super) fn targets(words: &[Word], ctx: &ShellContext<'_>) -> Vec<Option<String>> {
    let mut rest = words
        .iter()
        .skip_while(|w| assignment_name(&w.text).is_some())
        .skip_while(|w| CWD_PREFIXES.contains(&w.text.as_str()));
    let Some(program) = rest.next().map(|w| w.text.as_str()) else {
        return Vec::new();
    };
    if MAY_CHANGE_CWD.contains(&program) {
        return vec![None];
    }
    if program != "cd" && program != "pushd" {
        return Vec::new();
    }
    let mut options_ended = false;
    let mut physical = false;
    let target = rest.find(|w| {
        if !options_ended && w.text == "--" {
            options_ended = true;
            return false;
        }
        let operand = options_ended || !w.text.starts_with('-') || w.text == "-";
        physical |= !operand && w.text[1..].contains('P');
        operand
    });
    match target {
        None if program == "cd" => vec![Some(ctx.home.to_owned())],
        // `cd -P` resolves links before `..`, so the directory is also kept
        // in the form with its `..` for the engine to follow (`paths::traversal`)
        Some(word) if knowable(word) => ctx.paths(&word.text).map_or_else(
            |_| vec![None],
            |paths| {
                let traversals = physical.then(|| ctx.traversals(&word.text));
                paths
                    .into_iter()
                    .chain(traversals.into_iter().flatten())
                    .map(Some)
                    .collect()
            },
        ),
        _ => vec![None],
    }
}

/// A target whose text is the directory: no expansion, no glob, not `-` and
/// not a `pushd +N` stack index.
fn knowable(word: &Word) -> bool {
    word.substitutions.is_empty()
        && word.text != "-"
        && !word.text.starts_with('+')
        && !word.text.contains(['$', '`', '*', '?', '['])
}

/// Whether `command`, run in a shell that stays open for later commands (an
/// agent host's persistent shell session), may leave that shell in a directory
/// that cannot be known from the command alone: a `cd` or `pushd` to a target
/// that is not written out (`cd "$X"`, `cd -`), `popd`, or `eval`, `source` and
/// `.`, which can run a `cd` of their own, outside a subshell. A later command
/// in that shell would then be checked against the wrong directory. A command
/// line that cannot be read counts as such a move. A `cd` to a written-out
/// target is checked by the classifier itself, as a read of that directory.
#[must_use]
pub fn leaves_unknown_directory(command: &str) -> bool {
    let Ok(tokens) = crate::lexer::lex(command) else {
        return true;
    };
    let cwd = [Some("/".to_owned())];
    let ctx = ShellContext {
        home: "/",
        cwd: &cwd,
    };
    let unknown = |words: &[Word]| targets(words, &ctx).contains(&None);
    let mut subshells = 0_usize;
    let mut words: Vec<Word> = Vec::new();
    for token in &tokens {
        let crate::lexer::Token::Operator(op) = token else {
            if let crate::lexer::Token::Word(word) = token {
                words.push(word.clone());
            }
            continue;
        };
        if !(op.is_separator() || op.is_grouping()) {
            continue;
        }
        if subshells == 0 && unknown(&words) {
            return true;
        }
        words.clear();
        match op {
            crate::lexer::Operator::OpenParen => subshells += 1,
            crate::lexer::Operator::CloseParen => subshells = subshells.saturating_sub(1),
            _ => {}
        }
    }
    subshells == 0 && unknown(&words)
}

#[cfg(test)]
mod tests {
    use crate::action::AtomicAction;
    use crate::shell::{ParseOutcome, ShellContext, classify};

    fn classified(cmd: &str) -> ParseOutcome {
        let cwd = [Some("/p".to_owned())];
        let ctx = ShellContext {
            home: "/Users/me",
            cwd: &cwd,
        };
        classify(cmd, &ctx)
    }

    fn reads(cmd: &str) -> Vec<String> {
        match classified(cmd) {
            ParseOutcome::Parsed(atoms) => atoms
                .into_iter()
                .filter_map(|a| match a {
                    AtomicAction::FsRead { path } => Some(path),
                    _ => None,
                })
                .collect(),
            ParseOutcome::Unparseable { reason, .. } => panic!("`{cmd}`: {reason}"),
        }
    }

    #[test]
    fn relative_paths_follow_cd() {
        for cmd in [
            "cd ~/.ssh && cat id_rsa",
            "cd /tmp; cd ~/.ssh && head id_rsa",
            "cd -- ~/.ssh && cat id_rsa",
            "cd -P ~/.ssh || cat id_rsa",
            "builtin cd ~/.ssh; cat id_rsa",
            "{ cd ~/.ssh; }; cat id_rsa",
            "if cd ~/.ssh; then cat ./id_rsa; fi",
            "pushd ~/.ssh && cat id_rsa",
            "cd ~ && cat .ssh/id_rsa",
            "cd && cat .ssh/id_rsa",
            "cd ~/x && cd ../.ssh && cat id_rsa",
            "cd ~/.ssh && echo $(cat id_rsa)",
            "cd ~/.ssh && sh -c 'cat id_rsa'",
            "(cd ~/.ssh && cat id_rsa)",
        ] {
            let r = reads(cmd);
            assert!(
                r.contains(&"/Users/me/.ssh/id_rsa".to_owned()),
                "{cmd}: {r:?}"
            );
        }
        let r = reads("cd src && cat main.rs");
        assert!(r.contains(&"/p/src/main.rs".to_owned()), "{r:?}");
    }

    #[test]
    fn subshells_restore_and_nothing_else_moves() {
        for cmd in ["(cd ~/.ssh); cat id_rsa", "/bin/cd ~/.ssh; cat id_rsa"] {
            let r = reads(cmd);
            assert!(
                !r.contains(&"/Users/me/.ssh/id_rsa".to_owned()),
                "{cmd}: {r:?}"
            );
        }
    }

    #[test]
    fn unknown_targets_make_relative_paths_unresolvable() {
        for cmd in [
            "cd \"$DIR\" && cat id_rsa",
            "cd - && cat id_rsa",
            "cd $(dirname x) && cat id_rsa",
            "cd s* && cat id_rsa",
            "popd; cat id_rsa",
            "pushd && cat id_rsa",
            "pushd +1 && cat id_rsa",
            "source env.sh && cat id_rsa",
            "cd ~-/x && cat id_rsa",
        ] {
            assert!(
                matches!(classified(cmd), ParseOutcome::Unparseable { .. }),
                "{cmd}"
            );
        }
        reads("cd \"$DIR\" && cat /etc/hosts && cargo test");
    }

    /// A persistent shell keeps the directory a command leaves it in: one that
    /// cannot be known is reported, one in a subshell or written out is not.
    #[test]
    fn moves_a_persistent_shell_cannot_follow_are_reported() {
        for cmd in [
            "cd \"$HOME/.ssh\"",
            "cd -",
            "ls && cd $(dirname x)",
            "popd",
            "pushd",
            "source env.sh",
            ". ./env.sh",
            "true; eval \"$X\"",
            "if true; then cd \"$X\"; fi",
            "echo 'unterminated",
        ] {
            assert!(super::leaves_unknown_directory(cmd), "{cmd}");
        }
        for cmd in [
            "cd src && cargo test",
            "cd ~/.ssh",
            "cd",
            "(cd \"$X\" && ls)",
            "ls; (source env.sh); pwd",
            "cargo test --workspace",
            "echo cd \"$X\"",
        ] {
            assert!(!super::leaves_unknown_directory(cmd), "{cmd}");
        }
    }

    #[test]
    fn directory_set_is_bounded() {
        let many: Vec<String> = (0..super::MAX_DIRS).map(|i| format!("cd /d{i}")).collect();
        assert!(matches!(
            classified(&format!("{}; ls", many.join("; "))),
            ParseOutcome::Unparseable { .. }
        ));
    }
}
