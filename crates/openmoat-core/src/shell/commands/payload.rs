//! Inline interpreter code (`python3 -c`, `node -e`, a here-document fed to an
//! interpreter's stdin) is not shell, so it is scanned for the paths, hosts and
//! variables it names rather than parsed.

use crate::action::AtomicAction;
use crate::host;
use crate::paths;
use crate::shell::tokens::env_refs;
use crate::shell::{ClassifyError, ShellContext, Sink};

/// Mine inline interpreter code for the resources it names. The payload is
/// not shell, so it is scanned rather than parsed.
pub(super) fn scan_payload(
    payload: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let is_separator =
        |c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | '\'' | '"' | '`');
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
        if paths::looks_like_path(raw) {
            sink.read(ctx, raw)?;
        } else if let Some(host) = host::of_word(raw).filter(|_| !called) {
            // Code names a host it contacts as a URL or a string; a bare dotted word
            // is more often an attribute (`config.dev`), so it only looks like one.
            sink.push(if raw.contains("://") || in_string {
                AtomicAction::Net { host }
            } else {
                AtomicAction::NetWord { host }
            })?;
        }
        for name in env_refs(raw) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
    }
    Ok(())
}
