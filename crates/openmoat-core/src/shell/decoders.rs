//! Decoded content piped into an interpreter.
//!
//! `base64 -d payload | sh` runs code nobody can read in the command line. The
//! decoder can be spelled many ways (`-D`, `--decode`, `openssl enc -d`,
//! `xxd -r`, `gunzip -c`) and sit anywhere earlier in the pipe chain, so the
//! classifier emits one canonical `<decoder> -d | <interpreter>` pipeline atom
//! for every decoder stage that feeds an interpreter reading its program from
//! stdin. Policy rules such as `* -d | sh` then match every spelling.

use super::tables::{INLINE_INTERPRETERS, SHELLS, SOURCE_BUILTINS, STREAM_SOURCES};
use super::tokens::basename;
use super::{ClassifyError, Sink, invocation};
use crate::action::AtomicAction;
use crate::lexer::{Operator, Token};

/// Interpreters that execute a program read from stdin when given no script.
const STDIN_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "node", "perl", "ruby", "php", "deno", "bun", "pwsh",
];

/// Whether `program` is a language runtime that runs a program read from
/// stdin when given no script: one of [`STDIN_INTERPRETERS`] or any
/// `python…` (`python2.7`, `python3.12`, `pythonw`), as the default policy's
/// `python*` names them, so a version suffix does not drop the canonical
/// pipeline atom once another command follows the pipeline.
fn is_stdin_interpreter(program: &str) -> bool {
    STDIN_INTERPRETERS.contains(&program) || program.starts_with("python")
}

/// Programs that only ever decode or decompress.
const ALWAYS_DECODE: &[&str] = &[
    "uudecode", "gunzip", "zcat", "gzcat", "bunzip2", "bzcat", "unxz", "xzcat", "unzstd",
    "zstdcat", "unlzma", "lzcat",
];

/// Programs that decode when given a flag whose short form is in the string.
const DECODE_FLAGS: &[(&str, &str, &str)] = &[
    // (program, short option letters, long option)
    ("base64", "dD", "--decode"),
    ("base32", "d", "--decode"),
    ("basenc", "d", "--decode"),
    ("openssl", "d", "-d"),
    ("xxd", "r", "-revert"),
    ("gzip", "d", "--decompress"),
    ("bzip2", "d", "--decompress"),
    ("xz", "d", "--decompress"),
    ("zstd", "d", "--decompress"),
    ("lzma", "d", "--decompress"),
];

/// Push a canonical pipeline atom for every decoder stage that feeds a later
/// interpreter stage of the same pipe chain.
pub(super) fn push(tokens: &[Token], sink: &mut Sink) -> Result<(), ClassifyError> {
    for chain in pipe_chains(tokens) {
        for (i, stage) in chain.iter().enumerate() {
            let Some(decoder) = decoder(stage) else {
                continue;
            };
            for later in &chain[i + 1..] {
                if let Some(interpreter) = stdin_interpreter(later) {
                    sink.push(AtomicAction::Pipeline {
                        argv: vec![
                            decoder.to_owned(),
                            "-d".to_owned(),
                            "|".to_owned(),
                            interpreter.to_owned(),
                        ],
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// Stages (argv without redirections) of every `a | b | c` chain.
pub(super) fn pipe_chains(tokens: &[Token]) -> Vec<Vec<Vec<&str>>> {
    let mut chains = vec![vec![Vec::new()]];
    let mut skip_target = false;
    // A newline right after `|` continues the pipe (`curl URL |⏎ruby`), as
    // `pipelines::push` reads it; a `;` there is a syntax error the shell
    // refuses, read the same way, which only keeps a chain.
    let mut after_pipe = false;
    for token in tokens {
        let pipe = matches!(token, Token::Operator(Operator::Pipe));
        if after_pipe
            && matches!(token, Token::Operator(op) if op.is_separator() && *op != Operator::Pipe)
        {
            continue;
        }
        after_pipe = pipe;
        match token {
            Token::Word(_) if skip_target => skip_target = false,
            Token::Word(w) => {
                if let Some(stage) = chains.last_mut().and_then(|c| c.last_mut()) {
                    stage.push(w.text.as_str());
                }
            }
            Token::Operator(Operator::Pipe) => {
                if let Some(chain) = chains.last_mut() {
                    chain.push(Vec::new());
                }
            }
            Token::Operator(op) if op.is_redirect() => skip_target = true,
            // A group's parentheses neither start nor end a chain, as in
            // `pipelines::push`: `(curl URL) | sh` pipes what `curl` prints,
            // and a `)` that closes nothing (`curl URL) | sh ; true`, which
            // the shell refuses) cannot hide the stage before it.
            Token::Operator(op) if op.is_grouping() => {}
            Token::Operator(_) => chains.push(vec![Vec::new()]),
            Token::HereDoc { .. } => {}
        }
    }
    chains.retain(|c| c.len() >= 2);
    chains
}

/// The decoder's program name when `stage` decodes or decompresses.
fn decoder<'a>(stage: &[&'a str]) -> Option<&'a str> {
    let program = basename(stage.first()?);
    if ALWAYS_DECODE.contains(&program) {
        return Some(program);
    }
    let (_, letters, long) = DECODE_FLAGS.iter().find(|(p, _, _)| *p == program)?;
    stage[1..]
        .iter()
        .any(|arg| {
            *arg == *long
                || arg.strip_prefix('-').is_some_and(|cluster| {
                    !cluster.starts_with('-')
                        && !cluster.is_empty()
                        && cluster.len() <= 4
                        && cluster.chars().any(|c| letters.contains(c))
                })
        })
        .then_some(program)
}

/// The interpreter's name when `stage` runs a program read from stdin: a shell
/// or language runtime with no script argument (or `-`) and no inline code;
/// `source`/`.` of the standard input; or `xargs` starting one of them, which
/// runs the files the stream names.
pub(super) fn stdin_interpreter<'a>(stage: &[&'a str]) -> Option<&'a str> {
    let program = basename(stage.first()?);
    if SOURCE_BUILTINS.contains(&program) {
        let file = stage.get(1)?;
        return (STREAM_SOURCES.contains(file) && *file != "/dev/null").then_some(program);
    }
    if program == "xargs" {
        // `xargs sh` runs `sh` on the files the stream names, `xargs -I {} sh -c
        // '{}'` the stream itself: any shell or interpreter counts
        let owned: Vec<String> = stage.iter().map(|w| (*w).to_owned()).collect();
        let rest = super::commands::wrapped_command(&owned, program)?;
        let inner = basename(stage[stage.len() - rest.len()]);
        let interpreter = SHELLS.contains(&inner) || is_stdin_interpreter(inner);
        return interpreter.then_some(inner);
    }
    if SHELLS.contains(&program) {
        // Options the parser cannot read make the whole command unparseable
        // before this runs, so `Err` never decides a verdict here.
        let run = invocation::parse(program, stage).ok()?;
        return run.reads_stdin.then_some(program);
    }
    if !is_stdin_interpreter(program) {
        return None;
    }
    let inline: &[&str] = INLINE_INTERPRETERS
        .iter()
        .find(|(name, _)| *name == program)
        .map_or(&["-c"], |(_, flags)| flags);
    let args = &stage[1..];
    if args.iter().any(|a| inline.contains(a)) {
        return None;
    }
    let script = args.iter().find(|a| !a.starts_with('-') || **a == "-");
    matches!(script, None | Some(&"-")).then_some(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoders_in_all_spellings() {
        for stage in [
            &["base64", "-d"][..],
            &["base64", "-D", "x"],
            &["base64", "--decode"],
            &["/usr/bin/base64", "-di"],
            &["openssl", "enc", "-d", "-base64"],
            &["xxd", "-r", "-p"],
            &["xxd", "-rp"],
            &["gunzip", "-c"],
            &["gzip", "-dc"],
            &["zcat", "x.gz"],
        ] {
            assert!(decoder(stage).is_some(), "{stage:?}");
        }
        for stage in [
            &["base64", "x"][..],
            &["gzip", "-c"],
            &["xxd", "x"],
            &["cat"],
        ] {
            assert!(decoder(stage).is_none(), "{stage:?}");
        }
    }

    #[test]
    fn interpreters_reading_stdin() {
        for stage in [
            &["sh"][..],
            &["bash", "-s", "--"],
            &["bash", "-o", "pipefail"],
            &["sh", "-s", "arg"],
            &["python3", "-"],
            &["python3", "-I"],
            &["python3.12"],
            &["python2.7"],
            &["node"],
            &["node", "-"],
            &["perl"],
            &["ruby"],
            &["source", "/dev/stdin"],
            &[".", "/dev/fd/0"],
            &["xargs", "sh"],
            &["xargs", "-0", "-n", "1", "python3"],
            &["xargs", "-I", "{}", "sh", "-c", "{}"],
        ] {
            assert!(stdin_interpreter(stage).is_some(), "{stage:?}");
        }
        for stage in [
            &["bash", "build.sh"][..],
            &["sh", "-c", "echo"],
            &["bash", "-lc", "echo"],
            &["python3", "-c", "print(1)"],
            &["python3", "-I", "-c", "print(1)"],
            &["node", "-e", "1"],
            &["node", "-p", "1"],
            &["perl", "-e", "1"],
            &["ruby", "-e", "1"],
            &["jq", "."],
            &["source", "setup.sh"],
            &["source", "/dev/null"],
            &["xargs", "cat"],
            &["xargs", "-n", "1", "grep", "sh"],
            &["tar", "x"],
            &["grep", "sh"],
        ] {
            assert!(stdin_interpreter(stage).is_none(), "{stage:?}");
        }
    }
}
