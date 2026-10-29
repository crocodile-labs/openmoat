//! Inline interpreter code (`python3 -c`, `node -e`, a here-document fed to an
//! interpreter's stdin) is not shell, so it is scanned for the paths, hosts and
//! variables it names rather than parsed.

mod environ;
mod opaque;
mod writes;

use crate::action::AtomicAction;
use crate::host;
use crate::paths;
use crate::shell::tokens::env_refs;
use crate::shell::{ClassifyError, ShellContext, Sink, mailbox};

/// Mine inline interpreter code for the resources it names. The payload is
/// not shell, so it is scanned rather than parsed. Code that writes a file
/// writes every file name it shows (`writes.rs`). Code `program` runs that
/// reaches files, the network, the environment or other programs through text
/// it builds at run time is `@opaque-code <program>`, which `opaque-code` asks
/// for: what it opens is not on the command line.
pub(super) fn scan_payload(
    payload: &str,
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let is_separator =
        |c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | '\'' | '"' | '`');
    // Code that writes writes any file it names, as far as the scan can tell.
    let written = writes::written(payload);
    let mut rest = payload;
    while let Some(start) = rest.find(|c: char| !is_separator(c)) {
        let tail = &rest[start..];
        let end = tail.find(is_separator).unwrap_or(tail.len());
        let raw = &tail[..end];
        // In a string (`urlopen('evil.com')`), not a bare dotted word.
        let quote = rest[..start]
            .chars()
            .last()
            .filter(|c| matches!(c, '\'' | '"' | '`'));
        rest = &tail[end..];
        let in_string = quote.is_some_and(|q| rest.starts_with(q));
        // A word followed by `(` is a call (`subprocess.run(`, `app.dev(`), never a
        // host: a host in code is a string, so a quote or an operator follows it.
        let called = rest.starts_with('(');
        // In code a `~` is an operator or a regex delimiter (`~x`, `=~`, perl's
        // `s~a~b~`, a trailing `~s`), not a login name: only `~/…` is a path.
        let tilde_operator = raw.starts_with('~') && !raw.starts_with("~/");
        if !tilde_operator && paths::looks_like_path(raw) {
            sink.read(ctx, raw)?;
            if written.is_some() {
                sink.write(ctx, raw)?;
            }
        } else if let Some(host) = host::of_word(raw).filter(|_| !called) {
            // Code names a host it contacts as a URL or a string; a bare dotted word
            // is more often an attribute (`config.dev`), and a string that is a mail
            // address (`"me@example.com"`) more often data, so they only look like one.
            sink.push(
                if raw.contains("://") || (in_string && !mailbox::is_mailbox(raw)) {
                    AtomicAction::Net { host }
                } else {
                    AtomicAction::NetWord { host }
                },
            )?;
        }
        for name in env_refs(raw) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
    }
    for file in written.iter().flatten() {
        sink.write(ctx, file)?;
    }
    let (names, whole) = environ::reads(payload);
    for name in names {
        sink.push(AtomicAction::EnvRead { name })?;
    }
    // every variable, secrets included: `@env-dump <expression>`, which `env-dump` denies
    if let Some(expression) = whole {
        sink.push(AtomicAction::Shell {
            argv: vec!["@env-dump".to_owned(), expression.to_owned()],
        })?;
    }
    let targets = writes::targets(payload);
    crate::shell::executes::inline(payload, (program, &targets), ctx, sink);
    if opaque::opaque(payload) {
        sink.push(AtomicAction::Shell {
            argv: vec!["@opaque-code".to_owned(), program.to_owned()],
        })?;
    }
    Ok(())
}
