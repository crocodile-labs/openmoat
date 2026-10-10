//! Shell command classification (docs/ARCHITECTURE.md §3, docs/POLICY.md §3.1).
//!
//! A command line is lexed ([`crate::lexer`]), grouped into simple commands,
//! and each simple command is decomposed into [`AtomicAction`]s:
//!
//! | Source | Atomic action |
//! |---|---|
//! | the command itself | `Shell { argv }`; for `git`, without its global options (`git.rs`) |
//! | every pipeline / list suffix with ≥ 2 commands | `Pipeline { argv }` |
//! | a decoder stage piped into an interpreter reading stdin (`decoders.rs`) | canonical `Pipeline { <decoder> -d \| <interpreter> }` |
//! | leading `VAR=value`, `export`/`declare`/`set` assignments | `EnvSet` |
//! | `$VAR` / `${VAR}` references, `printenv NAME` | `EnvRead` |
//! | path-looking arguments, relative operands (`operands.rs`), `<` targets, `source`/`.` files | `FsRead`, one per directory `cd` may have moved to (`cwd.rs`); also listed as a glob when unquoted `* ? [` make the shell expand it (`crate::expand`) |
//! | `>`/`>>`/`&>` targets, `tee`, destructive/destination args | `FsWrite` |
//! | URLs with any host, bare dotted names under a known TLD, IPv4 literals (`crate::host`) | `Net` |
//! | `$( … )`, backticks, `sh -c` (any option spelling, `invocation.rs`), `eval`, `xargs`, `sudo`, `env`, … | nested classification |
//! | `python -c`, `node -e`, `perl -e`, … payloads | URL/path scan of the payload |
//! | `find -exec/-execdir/-ok/-okdir` commands, `--output=FILE` (`options.rs`) | nested classification, `FsWrite` |
//! | `make --eval`, `-e`, `SHELL=`, `X!=cmd`, `$(shell …)` (`make.rs`) | `make <arg>` `Shell` atom + nested classification |
//! | text tool options (`text.rs`): `sort -o FILE`, `uniq in out`; an unknown option | `FsWrite`; `<program> @<option>` `Shell` atom |
//! | `sed` scripts (`sed/`): `r FILE`, `w FILE`; `e`, anything not understood | `FsRead`, `FsWrite`; `sed @<script>` `Shell` atom |
//! | `awk` programs (`awk.rs`) with `system`, `\|`, `getline`, `ENVIRON`, `ARGV`, `@`, `print … >` | `awk @<program>` `Shell` atom |
//!
//! Classification is conservative by design: when the input cannot be parsed
//! safely the result is [`ParseOutcome::Unparseable`], which the engine maps to
//! `ask`, never `allow`. A simple command (or a path in it) that cannot be
//! classified does not stop the others: their atoms are kept, so a `deny` among
//! them still wins over the `ask`. `<<<` here-strings and here-document bodies are data,
//! except that the substitutions and variables the shell expands in them are
//! classified and a shell or interpreter reading stdin runs them as its program.
//!
//! Module layout: `commands` groups tokens and classifies each simple command;
//! `tokens` recognises assignments and variable references inside one word;
//! `invocation` parses a shell's own options (`bash -lc`, `sh -ec`, `--login`);
//! `git` takes git's global options out of the command;
//! `operands` decides which plain arguments name files, and `copy` where a copy
//! or a move writes (`cp f ~/` writes `~/f`);
//! `decoders`, `make` and `options` handle constructs that hide a command or a
//! write (decoded pipelines, make arguments, `find -exec`, `--output=`);
//! `text` reads the options of text tools, whose values are data, not files,
//! and `sed` and `awk` their programs;
//! `tables` holds the program lists that drive all of them.

mod awk;
mod commands;
mod copy;
mod cwd;
mod decoders;
pub(crate) mod git;
mod invocation;
mod make;
mod operands;
mod options;
mod sed;
pub(crate) mod tables;
#[cfg(test)]
mod tests;
mod text;
pub(crate) mod tokens;

use crate::action::AtomicAction;
use crate::lexer::{LexError, Token};
use crate::paths;

/// Result of classifying a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Parsed(Vec<AtomicAction>),
    /// Some part could not be classified (`reason`); `atoms` are the parts that
    /// were, still decided so that a `deny` among them is not lost.
    Unparseable {
        reason: String,
        atoms: Vec<AtomicAction>,
    },
}

impl ParseOutcome {
    /// The atoms classified, and why the rest could not be, if anything was left.
    #[must_use]
    pub fn into_parts(self) -> (Vec<AtomicAction>, Option<String>) {
        match self {
            Self::Parsed(atoms) => (atoms, None),
            Self::Unparseable { reason, atoms } => (atoms, Some(reason)),
        }
    }
}

/// Context needed to normalise paths inside a command. No I/O.
#[derive(Debug, Clone, Copy)]
pub struct ShellContext<'a> {
    pub home: &'a str,
    pub project: Option<&'a str>,
    /// Every directory the command may be running in: the session's working
    /// directory, plus wherever an earlier `cd` may have moved (`cwd.rs`).
    /// `None` is a directory that cannot be known (`cd "$X"`, `cd -`).
    pub cwd: &'a [Option<String>],
}

impl ShellContext<'_> {
    /// Every canonical path a shell word may name: one per possible working
    /// directory for a relative word. An error when one of them is not known
    /// (`~-`, or a relative word after `cd "$X"`), which makes the command `ask`.
    pub(crate) fn paths(&self, word: &str) -> Result<Vec<String>, ClassifyError> {
        if let Some(path) = paths::resolve(word, self.home, self.project, None) {
            return Ok(vec![path]);
        }
        self.cwd
            .iter()
            .map(|cwd| {
                paths::resolve(word, self.home, self.project, cwd.as_deref())
                    .ok_or_else(|| ClassifyError::UnknownDirectory(word.to_owned()))
            })
            .collect()
    }
}

/// Maximum nesting of `$( … )`, `sh -c`, `eval` and wrapper commands.
pub const MAX_DEPTH: u8 = 4;
/// Upper bound on atomic actions per command line, to bound work on hostile input.
pub const MAX_ATOMS: usize = 2048;
/// Upper bound on the directories one command line may be running in after `cd`.
pub const MAX_DIRS: usize = 16;

/// Classify a shell command string into atomic actions.
#[cfg(test)]
#[must_use]
pub fn classify(command: &str, ctx: &ShellContext<'_>) -> ParseOutcome {
    classify_globs(command, ctx).0
}

/// Classify a shell command string into atomic actions, and list the reads
/// and writes among them whose path is a glob the shell expands
/// (`crate::expand`).
#[must_use]
pub fn classify_globs(command: &str, ctx: &ShellContext<'_>) -> (ParseOutcome, Vec<AtomicAction>) {
    let mut sink = Sink::default();
    let stopped = commands::classify_into(command, ctx, &mut sink, 0).err();
    let outcome = match sink.skipped.or(stopped) {
        Some(e) => ParseOutcome::Unparseable {
            reason: e.to_string(),
            atoms: sink.atoms,
        },
        None if sink.atoms.is_empty() => ParseOutcome::Unparseable {
            reason: "no command found".to_owned(),
            atoms: Vec::new(),
        },
        None => ParseOutcome::Parsed(sink.atoms),
    };
    (outcome, sink.globs)
}

/// Why a command line could not be classified safely; the engine turns it into `ask`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClassifyError {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error("command nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("command expands to more than {MAX_ATOMS} actions")]
    TooManyActions,
    #[error("cannot interpret `{option}` for `{program}`")]
    ShellOption { program: String, option: String },
    #[error("`{0}` names a path relative to a directory that is not known")]
    UnknownDirectory(String),
    #[error("`cd` may lead to more than {MAX_DIRS} directories")]
    TooManyDirectories,
    #[error("unbalanced parentheses")]
    UnbalancedParens,
    #[error("the shell runs text from `{0}` that the command line does not show")]
    UnknownStdin(String),
}

/// Accumulates atomic actions with de-duplication and a hard size bound.
///
/// Every classifier function writes through a `&mut Sink`, never a bare
/// `Vec`, so no code path can exceed [`MAX_ATOMS`].
#[derive(Debug, Default)]
pub(crate) struct Sink {
    atoms: Vec<AtomicAction>,
    /// The first part classification went past without understanding it.
    skipped: Option<ClassifyError>,
    /// Words of the command line, nested commands included, that the shell
    /// expands as globs ([`crate::lexer::Word::glob`]).
    glob_words: Vec<String>,
    /// Read and write atoms whose path is one of those globs: the engine
    /// evaluates every file it matches as well as the literal path.
    globs: Vec<AtomicAction>,
}

impl Sink {
    pub(crate) fn push(&mut self, atom: AtomicAction) -> Result<(), ClassifyError> {
        if self.atoms.contains(&atom) {
            return Ok(());
        }
        if self.atoms.len() >= MAX_ATOMS {
            return Err(ClassifyError::TooManyActions);
        }
        self.atoms.push(atom);
        Ok(())
    }

    /// Note a part that could not be classified and carry on with the rest:
    /// the command still asks, and what else it does is still decided.
    pub(crate) fn skip(&mut self, error: ClassifyError) {
        self.skipped.get_or_insert(error);
    }

    /// Every path `word` may name, or none when one of them is not known (skipped).
    fn paths(&mut self, ctx: &ShellContext<'_>, word: &str) -> Vec<String> {
        ctx.paths(word).unwrap_or_else(|e| {
            self.skip(e);
            Vec::new()
        })
    }

    /// Remember the words of `tokens` the shell expands as globs.
    pub(crate) fn note_globs(&mut self, tokens: &[Token]) {
        for token in tokens {
            if let Token::Word(w) = token
                && w.glob
                && !self.glob_words.contains(&w.text)
            {
                self.glob_words.push(w.text.clone());
            }
        }
    }

    /// An `FsRead` for every path `word` may name.
    pub(crate) fn read(&mut self, ctx: &ShellContext<'_>, word: &str) -> Result<(), ClassifyError> {
        self.fs(ctx, word, |path| AtomicAction::FsRead { path })
    }

    /// An `FsWrite` for every path `word` may name.
    pub(crate) fn write(
        &mut self,
        ctx: &ShellContext<'_>,
        word: &str,
    ) -> Result<(), ClassifyError> {
        self.fs(ctx, word, |path| AtomicAction::FsWrite { path })
    }

    /// An atom for every path `word` may name, also kept as a glob when `word`
    /// is, or ends, a word the shell expands (`@file` and `--out=FILE` keep
    /// the glob of their word). An operand with the text of a glob elsewhere
    /// in the command line is expanded too: stricter, never looser.
    fn fs(
        &mut self,
        ctx: &ShellContext<'_>,
        word: &str,
        atom: fn(String) -> AtomicAction,
    ) -> Result<(), ClassifyError> {
        let glob =
            word.contains(['*', '?', '[']) && self.glob_words.iter().any(|w| w.ends_with(word));
        for path in self.paths(ctx, word) {
            let atom = atom(path);
            if glob && !self.globs.contains(&atom) {
                self.globs.push(atom.clone());
            }
            self.push(atom)?;
        }
        Ok(())
    }
}
