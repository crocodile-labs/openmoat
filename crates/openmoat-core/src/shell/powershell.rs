//! A minimal, deterministic reader of PowerShell command lines (ADR-116).
//!
//! The agents whose shell tool runs PowerShell on Windows send its lines as
//! `Action::ForeignShell` with the shell [`POWERSHELL`] (their specs say which:
//! `crates/openmoat-hosts`), and a POSIX line can start PowerShell itself
//! (`powershell -Command …`, `pwsh -EncodedCommand …`, [`nested`]). The reader
//! turns each statement it can read into the POSIX command that does the same
//! (`cmdlets.rs`: `Remove-Item -Recurse -Force ~` is `rm -r -f ~`,
//! `iwr URL | iex` is `curl URL | sh`, `$env:GITHUB_TOKEN` is `$GITHUB_TOKEN`),
//! and classifies that line, so the default policy's rules decide it as they
//! decide the POSIX command. An external program (`git`, `npm`, `dotnet`)
//! keeps its arguments.
//!
//! What it cannot read gives no atom of its own and is noted as not
//! classified: a statement with a parenthesis, a brace, a bracket or an array
//! (`ForEach-Object { … }`, `(Get-Item x).Length`); the literal paths and the
//! `$env:` variables such a statement names are still read. Code built at run
//! time gets `@opaque-code powershell`, which the `opaque-code` rule holds for
//! review: `iex`/`Invoke-Expression` of anything but piped input,
//! `Invoke-Command`, `[scriptblock]`, `.Invoke(`, `Add-Type`,
//! `[Convert]::FromBase64String`, `-EncodedCommand`; a download such a line
//! names is also classified as `curl URL | sh`, and the text an encoded
//! command or a base64 literal decodes to is read as PowerShell too. A line
//! written to hide what it runs gets `@obfuscated` (`crate::obfuscation`).
//!
//! A PowerShell line is never allowed on this reading alone: the engine keeps
//! it `unparseable` (the agent's own prompt under the default policy, ADR-025)
//! unless a rule denies or holds what it does. The reader only adds atoms.

mod cmdlets;
mod encoded;
mod lex;
mod statement;
#[cfg(test)]
mod tests;

use super::{ClassifyError, MAX_DEPTH, ShellContext, Sink};
use crate::action::AtomicAction;
use crate::obfuscation::{Dialect, assess};

/// The name the host adapters give PowerShell in `Action::ForeignShell`.
pub const POWERSHELL: &str = "PowerShell";

/// Whether a foreign shell's name is PowerShell's.
#[must_use]
pub fn is_powershell(shell: &str) -> bool {
    shell.eq_ignore_ascii_case(POWERSHELL)
}

/// Commands that run text or a looked-up command as code.
const EVALUATORS: &[&str] = &[
    "iex",
    "invoke-expression",
    "icm",
    "invoke-command",
    "add-type",
    "start-job",
    "invoke-item",
];

/// Text that builds code when the line runs.
const BUILDERS: &[&str] = &[
    "[scriptblock]",
    ".invoke(",
    "frombase64string",
    "newscriptblock",
    "downloadstring(",
    "downloadfile(",
];

/// Classify a PowerShell command line: the atoms of what the reader read,
/// always as `unparseable` (never `allow` on this reading alone), with the
/// reads and writes whose path is a glob.
#[must_use]
pub fn classify(
    command: &str,
    ctx: &ShellContext<'_>,
) -> (super::ParseOutcome, Vec<(AtomicAction, bool)>) {
    let mut sink = Sink::default();
    let stopped = classify_into(command, ctx, &mut sink, 0).err();
    let needs_review =
        sink.needs_review || stopped.as_ref().is_some_and(ClassifyError::needs_review);
    let reason = sink.skipped.or(stopped).map_or_else(
        || {
            "PowerShell is read in preview: a line is never allowed on that reading alone"
                .to_owned()
        },
        |e| e.to_string(),
    );
    let outcome = super::ParseOutcome::Unparseable {
        reason,
        atoms: sink.atoms,
        needs_review,
    };
    (outcome, sink.globs)
}

/// Classify the PowerShell line `command` into `sink`, at nesting `depth`.
pub(super) fn classify_into(
    command: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    if depth > MAX_DEPTH {
        return Err(ClassifyError::TooDeep);
    }
    let assessed = assess(command, Dialect::PowerShell);
    if assessed.obfuscated() {
        sink.push(super::obfuscated_atom(&assessed))?;
    }
    let lower = command.to_ascii_lowercase();
    // an open quote may hide the rest of the line: as for POSIX, that needs review
    let tokens = lex::lex(command).map_err(|e| {
        ClassifyError::Lex(match e {
            lex::LexError::Single => crate::lexer::LexError::UnterminatedSingleQuote,
            _ => crate::lexer::LexError::UnterminatedDoubleQuote,
        })
    })?;
    let evaluates = BUILDERS.iter().any(|b| lower.contains(b))
        || tokens.iter().any(|t| {
            matches!(t, lex::Tok::Word(w) if w.literal().is_some_and(|l| {
                EVALUATORS.contains(&l.to_ascii_lowercase().as_str())
            }))
        });
    let piped_only = statement::evaluates_piped_input_only(&tokens);
    if evaluates && !piped_only {
        opaque(sink)?;
        // `iex (iwr https://x/i.ps1)`, `(New-Object Net.WebClient).DownloadString(…)`
        for url in urls(command) {
            let line = format!("curl -fsSL {} | sh", statement::quote(&url));
            super::commands::classify_into(&line, ctx, sink, depth + 1)?;
        }
    }
    for decoded in encoded::base64_literals(command) {
        if let Err(e) = classify_into(&decoded, ctx, sink, depth + 1) {
            sink.skip(e);
        }
    }
    let posix = statement::translate(&tokens, ctx, sink, depth)?;
    if !posix.trim().is_empty() {
        super::commands::classify_into(&posix, ctx, sink, depth)?;
    }
    Ok(())
}

/// `@opaque-code powershell`: what the line runs is built when it runs.
fn opaque(sink: &mut Sink) -> Result<(), ClassifyError> {
    sink.push(AtomicAction::Shell {
        argv: vec!["@opaque-code".to_owned(), "powershell".to_owned()],
    })
}

/// The `http://` and `https://` URLs in `text`, as written.
fn urls(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for scheme in ["https://", "http://"] {
        for (at, _) in lower.match_indices(scheme) {
            let end = text[at..]
                .find(|c: char| c.is_whitespace() || "'\"`)(;|,".contains(c))
                .map_or(text.len(), |e| at + e);
            let url = text[at..end].to_owned();
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    out
}

/// A POSIX command whose program is PowerShell (`powershell -c 'Remove-Item
/// -Recurse ~'`, `pwsh -EncodedCommand …`): the line it runs is read as
/// PowerShell too. `-File` runs a script (`executes.rs` already notes it);
/// `-Command -` and no command read standard input, which the POSIX classifier
/// decides as a shell reading it.
pub(super) fn nested(argv: &[String], ctx: &ShellContext<'_>, sink: &mut Sink, depth: u8) {
    if !argv
        .first()
        .is_some_and(|first| is_powershell_program(first))
    {
        return;
    }
    let before = sink.skipped.take();
    let read = match statement::cli_command(&argv[1..]) {
        statement::Cli::Command(line) => classify_into(&line, ctx, sink, depth + 1),
        statement::Cli::Encoded(text) => opaque(sink).and_then(|()| {
            encoded::utf16le_base64(&text)
                .map_or(Ok(()), |line| classify_into(&line, ctx, sink, depth + 1))
        }),
        statement::Cli::Nothing => Ok(()),
    };
    // The POSIX classifier decides the `pwsh` command itself, as it did
    // before the reader: what the reader read only adds atoms. A part it did
    // not read leaves the POSIX line as it was; a line it could not read in
    // full, or a limit it reached, still needs review.
    let kept = sink
        .skipped
        .take()
        .into_iter()
        .chain(read.err())
        .find(ClassifyError::needs_review);
    sink.skipped = before;
    if let Some(error) = kept {
        sink.skip(error);
    }
}

/// `powershell`, `pwsh`, `powershell.exe`, `C:\…\pwsh.exe`, any case.
pub(super) fn is_powershell_program(word: &str) -> bool {
    let name = word
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(word)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    matches!(name, "powershell" | "pwsh" | "powershell_ise")
}
