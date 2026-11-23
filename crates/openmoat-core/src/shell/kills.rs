//! `pkill`, `killall` and `kill` of processes the agent did not start: an
//! OpenMoat process, or one the system needs.
//!
//! `pkill PATTERN` stops every process whose name (with `-f`, whose command
//! line) the extended regular expression `PATTERN` matches anywhere; `-x`
//! wants the whole name. `killall NAME` stops the processes named exactly
//! `NAME`, or matching it as a regular expression with `-r`. A policy pattern
//! cannot read a regular expression, so the classifier does: for each of
//! OpenMoat's own process names the pattern could match, it emits
//! `@kills <name>`, which the `stops-openmoat` rule holds for review.
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
//!
//! The system's own processes ([`SYSTEM_NAMES`]: `init`, `launchd`, `sshd`,
//! the login window, …) give `@kills-system <name>`, which `stops-system`
//! holds for review, read more narrowly so that a developer's `pkill -f
//! "node server"` or `pkill -f initdb` stays as it was: each alternative of
//! the pattern must be able to match the name itself, or end in `/<name>`
//! (`pkill -f /usr/sbin/sshd`). So do every process of `root` (`pkill -u
//! root`, `@kills-system user-root`), `kill 1` (`pid-1`), `kill -9 -1`, which
//! signals every process the user may (`every-process`), and `kill` of the
//! pids `pgrep` or `pidof` looks up for one of those names (`kill $(pgrep
//! sshd)`). `kill <pid>` of the agent's own jobs gives nothing.

use super::{ClassifyError, Sink};
use crate::action::AtomicAction;
use crate::lexer::Word;

/// The names OpenMoat's own processes run under (`programs.rs` pins the same
/// two binaries).
const OWN_NAMES: &[&str] = &["openmoat", "moat"];

/// Processes the operating system or the login session needs: the first
/// process, the service managers and schedulers, remote login, logging, the
/// message bus, authentication and the graphical session (Linux and macOS).
const SYSTEM_NAMES: &[&str] = &[
    "init",
    "launchd",
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolved",
    "sshd",
    "cron",
    "crond",
    "syslogd",
    "rsyslogd",
    "dbus-daemon",
    "polkitd",
    "auditd",
    "kernel_task",
    "loginwindow",
    "WindowServer",
    "securityd",
    "opendirectoryd",
    "mDNSResponder",
    "configd",
    "gdm",
    "sddm",
    "lightdm",
    "Xorg",
];

/// First word of the atoms for a process the system needs.
const SYSTEM_ATOM: &str = "@kills-system";

/// Emit `@kills <name>` for each of OpenMoat's process names a `pkill` or
/// `killall` pattern of `argv` could match, and `@kills-system <what>` for
/// what it stops that the system needs; for `kill`, the latter only.
pub(super) fn note(
    argv: &[String],
    program: &str,
    words: &[Word],
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match program {
        "pkill" | "killall" => {
            // Every word that is not an option is read as a pattern, option
            // values included (`-u me`): a value that could match the names
            // only adds a review.
            let patterns: Vec<&str> = argv[1..]
                .iter()
                .filter(|w| !w.starts_with('-'))
                .map(String::as_str)
                .collect();
            for name in OWN_NAMES {
                if patterns.iter().any(|p| could_match(p, name)) {
                    push(sink, "@kills", name)?;
                }
            }
            system_patterns(&patterns, sink)?;
            if targets_root(argv) {
                push(sink, SYSTEM_ATOM, "user-root")?;
            }
        }
        "kill" => kill(argv, words, sink)?,
        _ => {}
    }
    Ok(())
}

fn push(sink: &mut Sink, first: &str, what: &str) -> Result<(), ClassifyError> {
    sink.push(AtomicAction::Shell {
        argv: vec![first.to_owned(), what.to_owned()],
    })
}

/// `@kills-system <name>` for each system process a pattern could stop.
fn system_patterns(patterns: &[&str], sink: &mut Sink) -> Result<(), ClassifyError> {
    for name in SYSTEM_NAMES {
        if patterns.iter().any(|p| could_be(p, name)) {
            push(sink, SYSTEM_ATOM, name)?;
        }
    }
    Ok(())
}

/// `-u`/`-U`/`--euid`/`--uid` (`pkill`, `pgrep`) or `--user` (`killall`)
/// naming `root` or uid 0, alone or in a comma list, attached or not.
fn targets_root(argv: &[String]) -> bool {
    let root_list = |value: &str| value.split(',').any(|u| u == "root" || u == "0");
    argv.iter().enumerate().skip(1).any(|(i, word)| {
        let next = argv.get(i + 1).map(String::as_str);
        match word.as_str() {
            "-u" | "-U" | "--euid" | "--uid" | "--user" => next.is_some_and(root_list),
            w => ["-u", "-U", "--euid=", "--uid=", "--user="]
                .iter()
                .any(|opt| w.strip_prefix(opt).is_some_and(root_list)),
        }
    })
}

/// `kill`'s operands, after its options: `1` and `-1`, and the pids a
/// substitution looks up with `pgrep` or `pidof`.
fn kill(argv: &[String], words: &[Word], sink: &mut Sink) -> Result<(), ClassifyError> {
    if argv
        .iter()
        .any(|w| matches!(w.as_str(), "-l" | "-L" | "--list"))
    {
        return Ok(());
    }
    let mut i = 1;
    // a first `-SIGNAL` (`-9`, `-KILL`, `-1`) or `-s`/`-n` with its value
    match argv.get(1).map(String::as_str) {
        Some("-s" | "-n") => i = 3,
        Some("--") => i = 2,
        Some(w) if w.starts_with('-') => {
            i = 2;
            if argv.get(2).is_some_and(|w| w == "--") {
                i = 3;
            }
        }
        _ => {}
    }
    for operand in argv.iter().skip(i) {
        match operand.as_str() {
            "1" => push(sink, SYSTEM_ATOM, "pid-1")?,
            "-1" => push(sink, SYSTEM_ATOM, "every-process")?,
            _ => {}
        }
    }
    for text in words.iter().flat_map(|w| &w.substitutions) {
        let looked_up = quoted_words(text);
        let Some((first, rest)) = looked_up.split_first() else {
            continue;
        };
        let finder = first.rsplit('/').next().unwrap_or(first);
        if matches!(finder, "pgrep" | "pidof") {
            let patterns: Vec<&str> = rest
                .iter()
                .filter(|w| !w.starts_with('-'))
                .map(String::as_str)
                .collect();
            system_patterns(&patterns, sink)?;
            if targets_root(&looked_up) {
                push(sink, SYSTEM_ATOM, "user-root")?;
            }
        }
    }
    Ok(())
}

/// The words of a substituted command, a quoted run one word (`pgrep -f 'next
/// dev'` is `pgrep`, `-f`, `next dev`).
fn quoted_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    for c in text.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if c.is_whitespace() => end_run(&mut words, &mut word),
            (_, c) => word.push(c),
        }
    }
    end_run(&mut words, &mut word);
    words
}

/// Whether the extended regular expression `pattern` could match `name`, or
/// a command line holding it. False only when a literal run of the pattern
/// cannot appear in `name`.
fn could_match(pattern: &str, name: &str) -> bool {
    if pattern.contains(['(', '|']) {
        return true;
    }
    let runs = literal_runs(pattern);
    runs.iter().any(|r| r.contains(name)) || runs.iter().all(|r| name.contains(r.as_str()))
}

/// Whether some alternative of `pattern` could match the process name `name`
/// itself, or names its program by path (`/usr/sbin/sshd`): narrower than
/// [`could_match`], so a word that only holds the name (`initdb`) is not it.
fn could_be(pattern: &str, name: &str) -> bool {
    pattern.split('|').any(|alternative| {
        let alternative: String = alternative
            .chars()
            .filter(|c| !matches!(c, '(' | ')'))
            .collect();
        let runs = literal_runs(&alternative);
        runs.iter().all(|r| name.contains(r.as_str()))
            || runs
                .iter()
                .any(|r| r.strip_suffix(name).is_some_and(|dir| dir.ends_with('/')))
    })
}

/// The literal runs of an extended regular expression: the text between its
/// metacharacters, less a character a quantifier makes optional.
fn literal_runs(pattern: &str) -> Vec<String> {
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
    runs
}

fn end_run(runs: &mut Vec<String>, run: &mut String) {
    if !run.is_empty() {
        runs.push(std::mem::take(run));
    }
}

#[cfg(test)]
mod tests;
