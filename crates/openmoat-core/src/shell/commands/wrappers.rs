//! Wrappers that run the rest of their arguments as a command (`sudo`, `env`,
//! `xargs`, `timeout`, `nice`, …).
//!
//! `env -S 'cmd args'` (`--split-string`) splits its value into words itself,
//! options included, and runs them with the words after it, so the value is
//! classified as the start of an `env` command line. `xargs` adds the words of
//! input the command line shows to the command it runs (`xargs.rs`). The
//! launchers of `launchers.rs` (`taskset`, `unshare`, `systemd-run`, …) are
//! read the same way. `at` and `batch` run the text on their stdin later, as a
//! shell would run it now, and read `-f FILE` instead.

mod launchers;
mod xargs;

use super::super::options;
use super::super::tables::{
    WRAPPER_OPTIONS_WITH_VALUE, WRAPPER_SUBCOMMANDS, WRAPPERS, WRAPPERS_WITH_VALUE,
};
use super::super::tokens::assignment_name;
use super::super::{ClassifyError, ShellContext, Sink};
use super::piped::Piped;
use super::{SimpleCommand, classify_into, classify_wrapped};

/// Classify what the wrapper `program` runs; `None` when it is no wrapper or
/// runs nothing.
pub(super) fn classify(
    cmd: &SimpleCommand,
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Option<Result<(), ClassifyError>> {
    if program == "env"
        && let Some(line) = split_string(argv)
    {
        return Some(classify_into(&line, ctx, sink, depth + 1));
    }
    if matches!(program, "at" | "batch") {
        return Some(later(cmd, argv, ctx, sink, depth));
    }
    let inner = wrapped_command(argv, program);
    let start = inner.map(|inner| argv.len() - inner.len());
    let more = launchers::runs(argv, program, start);
    if inner.is_none() && more.is_empty() {
        return None;
    }
    let mut classify = || {
        // a launcher's own options are checked as any other program's are
        if launchers::is_launcher(program) {
            options::classify(argv, program, ctx, sink, depth)?;
        }
        for run in &more {
            classify_wrapped(run, ctx, sink, depth)?;
        }
        let Some(inner) = inner else {
            return Ok(());
        };
        if program == "xargs" {
            for run in xargs::runs(cmd, argv, inner)? {
                classify_wrapped(&run, ctx, sink, depth)?;
            }
        }
        classify_wrapped(inner, ctx, sink, depth)
    };
    Some(classify())
}

/// `echo cmd | at now`, `at now <<< cmd`, `at -f FILE now`: the job is the
/// text on stdin, classified as a command line, or the file it is read from.
fn later(
    cmd: &SimpleCommand,
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    let piped = cmd.piped.iter().filter_map(Piped::text);
    for text in cmd.stdin_texts().chain(piped) {
        classify_into(text, ctx, sink, depth + 1)?;
    }
    let mut words = argv[1..].iter();
    while let Some(arg) = words.next() {
        if arg == "--" {
            break;
        }
        if let Some(cluster) = arg.strip_prefix('-')
            && let Some(at) = cluster.find('f')
        {
            let attached = &cluster[at + 1..];
            let file = if attached.is_empty() {
                words.next().map(String::as_str)
            } else {
                Some(attached)
            };
            if let Some(file) = file {
                sink.read(ctx, file)?;
            }
        }
    }
    options::classify(argv, "at", ctx, sink, depth)
}

/// `env [OPTION]… -S STRING [ARG]…` as the command line env runs:
/// `env STRING ARG…`, the words after the string quoted. `None` without `-S`.
fn split_string(argv: &[String]) -> Option<String> {
    let mut i = 1;
    let mut value = None;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, v)) => (name, Some(v.to_owned())),
                None => (long, None),
            };
            // getopt takes any unambiguous prefix (`--split`)
            let is = |option: &str| !name.is_empty() && option.starts_with(name);
            if name.is_empty() {
                break;
            }
            if is("split-string") {
                value = attached.or_else(|| argv.get(i).cloned());
                i += 1;
                break;
            }
            i += usize::from(attached.is_none() && (is("unset") || is("chdir")));
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            break;
        };
        for (pos, c) in cluster.char_indices() {
            let rest = &cluster[pos + c.len_utf8()..];
            if matches!(c, 'S' | 'u' | 'C' | 'P') {
                if rest.is_empty() {
                    i += 1;
                }
                if c == 'S' {
                    value = Some(rest.to_owned())
                        .filter(|r| !r.is_empty())
                        .or_else(|| argv.get(i - 1).cloned());
                }
                break;
            }
        }
        if value.is_some() {
            break;
        }
    }
    let value = value?;
    let rest = argv.get(i..).unwrap_or_default().iter().map(|w| quote(w));
    Some(
        std::iter::once(format!("env {value}"))
            .chain(rest)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// `word` in single quotes, so the shell reads it back as written.
fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// For `sudo -u x cmd …`, `env A=1 cmd …`, `xargs -0 cmd …`, `timeout 5 cmd …`
/// return the wrapped argv.
pub(crate) fn wrapped_command<'a>(argv: &'a [String], program: &str) -> Option<&'a [String]> {
    if let Some((_, subcommands)) = WRAPPER_SUBCOMMANDS
        .iter()
        .find(|(name, _)| *name == program)
    {
        if !subcommands.contains(&argv.get(1)?.as_str()) {
            return None;
        }
        let mut i = 2;
        while let Some(arg) = argv.get(i) {
            if arg == "--" {
                i += 1;
                break;
            }
            if !arg.starts_with('-') {
                break;
            }
            i += 1;
        }
        return argv.get(i..).filter(|rest| !rest.is_empty());
    }
    let launcher = launchers::options(program);
    let wrapper = WRAPPERS.contains(&program) || launcher.is_some();
    if !wrapper || options::only_describes(argv, program) {
        return None;
    }
    // without `-u`, runuser's first operand is a user, as in `su`
    if program == "runuser" && !argv.iter().any(|a| a == "-u" || a.starts_with("--user")) {
        return None;
    }
    let options_with_value = WRAPPER_OPTIONS_WITH_VALUE
        .iter()
        .find(|(name, _)| *name == program)
        .map(|(_, opts)| *opts)
        .or(launcher)
        .unwrap_or_default();
    let mut i = 1;
    let mut value_pending =
        WRAPPERS_WITH_VALUE.contains(&program) || launchers::takes_value(program);
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        if options_with_value.contains(&arg.as_str()) {
            i += 2;
            continue;
        }
        let is_env_assignment = program == "env" && assignment_name(arg).is_some();
        if arg.starts_with('-') || is_env_assignment {
            i += 1;
            continue;
        }
        if value_pending {
            value_pending = false;
            i += 1;
            continue;
        }
        break;
    }
    argv.get(i..).filter(|rest| !rest.is_empty())
}
