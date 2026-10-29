//! `pkill` and `killall` patterns that could stop an OpenMoat process.
//!
//! `pkill PATTERN` stops every process whose name (with `-f`, whose command
//! line) the extended regular expression `PATTERN` matches anywhere; `-x`
//! wants the whole name. `killall NAME` stops the processes named exactly
//! `NAME`, or matching it as a regular expression with `-r`. A policy pattern
//! cannot read a regular expression, so the classifier does: for each of
//! OpenMoat's own process names the pattern could match, it emits
//! `@kills <name>`, which the `stops-openmoat` rule asks for.
//!
//! A pattern cannot match a name when one of its literal runs (the text
//! between metacharacters, less a character a quantifier makes optional) is
//! not a substring of the name: every run has to appear in what the pattern
//! matches. A pattern whose text holds the name matches a command line that
//! holds it (`pkill -f /usr/local/bin/openmoat`), so it could as well. What
//! the analysis does not read (a group, an alternation, a class, an escaped
//! letter) ends a run or counts as able to match anything, so it only makes
//! the pattern look able to match more. With `-f`, a pattern naming only an
//! argument of the process (`pkill -f proxy`) is not seen; a policy can name
//! it as a plain `pkill` pattern.

use super::{ClassifyError, Sink};
use crate::action::AtomicAction;

/// The names OpenMoat's own processes run under (`programs.rs` pins the same
/// two binaries).
const OWN_NAMES: &[&str] = &["openmoat", "moat"];

/// Emit `@kills <name>` for each of OpenMoat's process names a `pkill` or
/// `killall` pattern of `argv` could match.
pub(super) fn note(argv: &[String], program: &str, sink: &mut Sink) -> Result<(), ClassifyError> {
    if !matches!(program, "pkill" | "killall") {
        return Ok(());
    }
    // Every word that is not an option is read as a pattern, option values
    // included (`-u me`): a value that could match the names only adds an ask.
    let patterns = argv[1..].iter().filter(|w| !w.starts_with('-'));
    for name in OWN_NAMES {
        if patterns.clone().any(|p| could_match(p, name)) {
            sink.push(AtomicAction::Shell {
                argv: vec!["@kills".to_owned(), (*name).to_owned()],
            })?;
        }
    }
    Ok(())
}

/// Whether the extended regular expression `pattern` could match `name`, or
/// a command line holding it. False only when a literal run of the pattern
/// cannot appear in `name`.
fn could_match(pattern: &str, name: &str) -> bool {
    if pattern.contains(['(', '|']) {
        return true;
    }
    let mut runs: Vec<String> = Vec::new();
    let mut run = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // an escaped punctuation character is itself; `\d`, `\w` are classes
            '\\' => match chars.next() {
                Some(escaped) if !escaped.is_ascii_alphanumeric() => run.push(escaped),
                _ => end_run(&mut runs, &mut run),
            },
            // a bracket expression matches one character of its own
            '[' => {
                end_run(&mut runs, &mut run);
                if chars.peek() == Some(&'^') {
                    chars.next();
                }
                // a `]` first in the expression is a member, not its end
                if chars.peek() == Some(&']') {
                    chars.next();
                }
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                }
            }
            // the character before `*`, `?` or `{m,n}` may not appear at all
            '*' | '?' | '{' => {
                run.pop();
                end_run(&mut runs, &mut run);
                if c == '{' {
                    for inner in chars.by_ref() {
                        if inner == '}' {
                            break;
                        }
                    }
                }
            }
            '.' | '+' | '^' | '$' => end_run(&mut runs, &mut run),
            _ => run.push(c),
        }
    }
    end_run(&mut runs, &mut run);
    runs.iter().any(|r| r.contains(name)) || runs.iter().all(|r| name.contains(r.as_str()))
}

fn end_run(runs: &mut Vec<String>, run: &mut String) {
    if !run.is_empty() {
        runs.push(std::mem::take(run));
    }
}

#[cfg(test)]
mod tests {
    use super::could_match;

    #[test]
    fn patterns_that_could_stop_openmoat() {
        for pattern in [
            "moat",
            "openmoat",
            "open.*",
            ".",
            "o.*t",
            "m.at",
            "openmoat proxy",
            "/usr/local/bin/openmoat",
            "^moat$",
            "mo+at",
            "(open)?moat",
            "vite|moat",
            "[om]+",
            "openx?moat",
            // holds a name: a command line with it matches (conservative)
            "moatx",
        ] {
            assert!(
                could_match(pattern, "openmoat") || could_match(pattern, "moat"),
                "{pattern}"
            );
        }
    }

    #[test]
    fn patterns_that_cannot() {
        for pattern in [
            "latency-compare.py",
            "my-server.js",
            "node .*vite",
            "python3",
            "node",
            "nginx",
            "boat",
            "m\\.at",
            "mo.t\\.py",
            "[a-z]+-server",
        ] {
            assert!(
                !could_match(pattern, "openmoat") && !could_match(pattern, "moat"),
                "{pattern}"
            );
        }
    }
}
