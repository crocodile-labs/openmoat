//! Whole pipelines and lists as `Pipeline` atoms, so a rule such as `curl * | sh`
//! sees across `|`, `&&` and `;`; the canonical form of a pipeline whose
//! consumer runs its stdin as its program; and the same canonical form for a
//! command substitution whose output a shell runs as its program
//! (`sh -c "$(curl URL)"`, `eval "$(curl URL)"` → `curl URL | sh`).

use super::super::decoders::{self, pipe_chains, stdin_interpreter};
use super::recover::lex_like_bash;
use crate::action::AtomicAction;
use crate::lexer::{Operator, Token, Word};
use crate::shell::{ClassifyError, Sink};

/// The atoms of `<inner> | <interpreter>` for every command substitution in
/// `code`, those of the words a shell runs as its program: the outer shell replaces
/// `$( … )` there with what the inner command prints before `interpreter`
/// parses it, so `sh -c "$(curl URL)"`, `bash -c "$(wget -qO- URL)"` and
/// `eval "$(curl URL)"` run downloaded text exactly as `curl URL | sh` does
/// and get its canonical pipeline atoms (and a decoder's, `base64 -d | sh`).
/// Each command of the substitution's list counts as a producer, since its
/// output is part of the text. Single quotes keep `$( … )` from the outer
/// shell (`sh -c '$(curl URL)'`): the word holds no substitution, and the
/// inner shell's own expansion is classified as a command of its own. A
/// substitution the lexer cannot read adds nothing here; classifying it
/// already failed and was reported.
pub(super) fn push_substituted_code<'w>(
    code: impl IntoIterator<Item = &'w [String]>,
    interpreter: &str,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    for inner in code.into_iter().flatten() {
        let Ok(tokens) = lex_like_bash(inner) else {
            continue;
        };
        let piped = piped_into(tokens, interpreter);
        push_stdin_consumers(&piped, sink)?;
        decoders::push(&piped, sink)?;
    }
    Ok(())
}

/// `tokens` with `| <interpreter>` after every command list item that has a
/// word: `a; b | c` → `a | sh; b | c | sh`.
fn piped_into(tokens: Vec<Token>, interpreter: &str) -> Vec<Token> {
    let consumer = || {
        [
            Token::Operator(Operator::Pipe),
            Token::Word(Word {
                text: interpreter.to_owned(),
                unquoted: std::iter::once(0..interpreter.len()).collect(),
                ..Word::default()
            }),
        ]
    };
    let mut out = Vec::with_capacity(tokens.len() + 2);
    let mut has_word = false;
    for token in tokens {
        match &token {
            Token::Word(_) => has_word = true,
            Token::Operator(op)
                if !matches!(op, Operator::Pipe) && !op.is_redirect() && has_word =>
            {
                out.extend(consumer());
                has_word = false;
            }
            Token::Operator(Operator::Pipe) => has_word = false,
            Token::Operator(_) | Token::HereDoc { .. } => {}
        }
        out.push(token);
    }
    if has_word {
        out.extend(consumer());
    }
    out
}

/// Emit a `Pipeline` atom for every suffix of a pipeline/list with ≥ 2 commands
/// so prefix rules such as `curl * | sh` match at any boundary.
pub(super) fn push(tokens: &[Token], sink: &mut Sink) -> Result<(), ClassifyError> {
    let mut flat: Vec<String> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut at_command_start = true;
    // Separators pushed since the last word. Counted from the tokens, not by
    // comparing text: an escaped word `\&` has the same text as the operator.
    let mut trailing_separators = 0;
    for token in tokens {
        match token {
            Token::Word(w) => {
                if at_command_start {
                    starts.push(flat.len());
                    at_command_start = false;
                }
                flat.push(w.text.clone());
                trailing_separators = 0;
            }
            Token::Operator(op) if op.is_separator() => {
                if !at_command_start {
                    flat.push(op.symbol().to_owned());
                    trailing_separators += 1;
                }
                at_command_start = true;
            }
            Token::Operator(op) if op.is_redirect() => {
                flat.push(op.symbol().to_owned());
                trailing_separators = 0;
            }
            Token::Operator(_) | Token::HereDoc { .. } => {}
        }
    }
    flat.truncate(flat.len() - trailing_separators);
    if starts.len() < 2 {
        return Ok(());
    }
    for &start in &starts[..starts.len() - 1] {
        sink.push(AtomicAction::Pipeline {
            argv: flat[start..].to_vec(),
        })?;
    }
    push_stdin_consumers(tokens, sink)
}

/// A stage that runs its stdin as its program, after each run of the stages
/// before it in the same pipe chain, as `<stages> | <interpreter>` with the
/// consumer's options dropped: `curl URL | tee x | sh -s -- --yes` is also
/// `curl URL | tee x | sh` and `tee x | sh`. A rule anchored on the consumer
/// (`curl * | sh $`) then matches it whatever its options, and not an
/// interpreter given its program on the line (`curl URL | python3 -c CODE`),
/// which reads the stream as data.
fn push_stdin_consumers(tokens: &[Token], sink: &mut Sink) -> Result<(), ClassifyError> {
    for chain in pipe_chains(tokens) {
        for (consumer, stage) in chain.iter().enumerate().skip(1) {
            let Some(interpreter) = stdin_interpreter(stage) else {
                continue;
            };
            for first in 0..consumer {
                let mut argv: Vec<String> = Vec::new();
                for producer in &chain[first..consumer] {
                    argv.extend(producer.iter().map(|w| (*w).to_owned()));
                    argv.push("|".to_owned());
                }
                argv.push(interpreter.to_owned());
                sink.push(AtomicAction::Pipeline { argv })?;
            }
        }
    }
    Ok(())
}
