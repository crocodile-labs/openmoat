//! The atoms a simple command adds for itself: its `Shell` atom in canonical
//! form, the `env.set` of an assignment word, and the `kill` of substituted pids.

use super::super::tokens::{assignment_name, inert_assignment, kill_substituted};
use super::super::{ClassifyError, ShellContext, Sink, git};
use super::{SimpleCommand, filters};
use crate::action::AtomicAction;
use crate::lexer::Word;

/// The command's own `Shell` atom: `git` without its global options
/// (`git.rs`); for a `perl -pi -e 's/a/b/' FILE…` whose program is only
/// substitutions (`in_place.rs` writes the files), the canonical
/// `perl @substitute <program>`, which `text-tools` names; an environment
/// listing piped into a filter that keeps only the names (`env | cut -d= -f1`,
/// `filters.rs`) as `env @names-only`, since it is not the listing `env-dump`
/// denies; anything else as written.
pub(super) fn push_command(
    cmd: &SimpleCommand,
    argv: &[String],
    program: &str,
    substitution: Option<usize>,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    if program == "git" {
        return git::push_shell(argv, ctx, sink);
    }
    let mut shown = match substitution {
        Some(at) => vec![
            program.to_owned(),
            "@substitute".to_owned(),
            argv[at].clone(),
        ],
        None => argv.to_vec(),
    };
    if cmd
        .consumer
        .as_deref()
        .is_some_and(|next| filters::keeps_only_names(argv, program, next))
    {
        shown.push("@names-only".to_owned());
    }
    sink.push(AtomicAction::Shell { argv: shown })
}

/// An assignment word (`NAME=value`) is an `env.set` of `NAME`, unless its
/// value changes nothing about what later commands run ([`inert_assignment`]).
pub(super) fn push_env_set(word: &Word, sink: &mut Sink) -> Result<(), ClassifyError> {
    match assignment_name(&word.text) {
        Some(name) if !inert_assignment(word) => sink.push(AtomicAction::EnvSet {
            name: name.to_owned(),
        }),
        _ => Ok(()),
    }
}

/// The second atom of a `kill` of substituted pids ([`kill_substituted`]).
pub(super) fn push_kill_substituted(
    program: &str,
    words: &[Word],
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match kill_substituted(program, words) {
        Some(argv) => sink.push(AtomicAction::Shell { argv }),
        None => Ok(()),
    }
}
