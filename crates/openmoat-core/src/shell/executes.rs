//! The files a command runs as code (ADR-039): a script an interpreter runs
//! (`python3 x.py`, `node x.mjs`, `bash x.sh`, `source x`, `go run x.go`,
//! `pwsh -File x.ps1`, `npx tsx x.ts`), a file it loads first (`node -r
//! ./setup.js`), a program named by a path (`./x`, `bin/x`, `/p/bin/x`), and a
//! file a shell or interpreter reads its program from (`sh < x.sh`).
//!
//! `moat guard` asks before such a file runs when the same session wrote it and
//! no OS sandbox holds the command. Finding the files is the classifier's work,
//! so every spelling it reads (`env python3 x.py`, `time ./x`, `bash -c 'node
//! x.js'`, `cd sub && python x.py`) is found the same way. A test runner, a
//! build tool or a package script (`pytest`, `cargo test`, `npm test`, `make`,
//! `go run .`) runs the project's code by design and names no file here.

mod inline;
mod interpreters;
#[cfg(test)]
mod tests;

use super::{ShellContext, Sink, commands, tables};

/// Note in `sink` the files the simple command `argv` runs as code. `program`
/// is its base name; `reads` are its `<` redirections.
pub(super) fn note(
    argv: &[String],
    program: &str,
    reads: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) {
    let Some(first) = argv.first() else {
        return;
    };
    // A program named by a path, or a bare script name a runner hands on
    // (`uv run x.py`): the shell or the runner runs that file.
    if first.contains('/') || interpreters::file_like(first) {
        sink.execute(ctx, first);
    }
    let Some(run) = interpreters::program(program, &argv[1..]) else {
        return;
    };
    for file in &run.files {
        sink.execute(ctx, file);
        // `node x` runs `x.js`, `x.mjs`, `x.cjs` or `x/index.js` when there is no `x`.
        if matches!(program, "node" | "nodejs")
            && !file.rsplit('/').next().is_some_and(|n| n.contains('.'))
        {
            for candidate in [".js", ".mjs", ".cjs", "/index.js"] {
                sink.execute(ctx, &format!("{file}{candidate}"));
            }
        }
    }
    // `python -m tool` runs `tool.py` or `tool/__main__.py` of the working
    // directory before an installed one.
    if let Some(module) = run.module.filter(|m| is_module_name(m)) {
        let path = module.replace('.', "/");
        sink.execute(ctx, &format!("{path}.py"));
        sink.execute(ctx, &format!("{path}/__main__.py"));
    }
    if run.stdin {
        stdin_files(reads, ctx, sink);
    }
}

/// The files a shell runs (`invocation.rs` reads its options): its script
/// operand, or, when it reads its program from stdin, the files it is
/// redirected from (`sh < x.sh`).
pub(super) fn shell_files(
    script: Option<&str>,
    from_stdin: bool,
    reads: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) {
    match script {
        Some(script) => sink.execute(ctx, script),
        None if from_stdin => stdin_files(reads, ctx, sink),
        None => {}
    }
}

/// A program read from stdin runs the files it is redirected from.
fn stdin_files(reads: &[String], ctx: &ShellContext<'_>, sink: &mut Sink) {
    for file in reads {
        if !tables::STREAM_SOURCES.contains(&file.as_str()) {
            sink.execute(ctx, file);
        }
    }
}

/// Note the files inline code `program` runs loads as code: a module of the
/// working directory it imports or a program file it names (`inline.rs`).
pub(crate) fn inline(code: &str, program: &str, ctx: &ShellContext<'_>, sink: &mut Sink) {
    for word in inline::loads(program, code) {
        sink.execute(ctx, &word);
    }
}

/// A dotted Python module name (`pkg.tool`), not a path or an option.
fn is_module_name(word: &str) -> bool {
    !word.is_empty()
        && word.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// The files `command` runs as code, read as the classifier reads it, each
/// with whether its word is a glob the shell expands. A part the classifier
/// stops at hides no file it would have found before; a word whose value is
/// not known (`python3 $f`) names none.
#[must_use]
pub fn executed(command: &str, ctx: &ShellContext<'_>) -> Vec<(String, bool)> {
    let mut sink = Sink::default();
    let _ = commands::classify_into(command, ctx, &mut sink, 0);
    let split = command.replace("${IFS}", " ").replace("$IFS", " ");
    if split != command {
        let _ = commands::classify_into(&split, ctx, &mut sink, 0);
    }
    sink.executed
}
