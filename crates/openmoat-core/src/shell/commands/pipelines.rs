//! Whole pipelines and lists as `Pipeline` atoms, so a rule such as `curl * | sh`
//! sees across `|`, `&&` and `;`; and the canonical form of a pipeline whose
//! consumer runs its stdin as its program.

use super::super::decoders::{pipe_chains, stdin_interpreter};
use crate::action::AtomicAction;
use crate::lexer::Token;
use crate::shell::{ClassifyError, Sink};

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
