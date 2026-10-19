//! Wrappers that run the rest of their arguments as a command (`sudo`, `env`,
//! `xargs`, `timeout`, `nice`, …).
//!
//! `env -S 'cmd args'` (`--split-string`) splits its value into words itself,
//! options included, and runs them with the words after it, so the value is
//! classified as the start of an `env` command line. `xargs` adds the words of
//! input the command line shows to the command it runs (`xargs.rs`).

mod xargs;

use super::super::options;
use super::super::tables::{
    WRAPPER_OPTIONS_WITH_VALUE, WRAPPER_SUBCOMMANDS, WRAPPERS, WRAPPERS_WITH_VALUE,
};
use super::super::tokens::assignment_name;
use super::super::{ClassifyError, ShellContext, Sink};
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
    let inner = wrapped_command(argv, program)?;
    let mut classify = || {
        if program == "xargs" {
            for run in xargs::runs(cmd, argv, inner)? {
                classify_wrapped(&run, ctx, sink, depth)?;
            }
        }
        classify_wrapped(inner, ctx, sink, depth)
    };
    Some(classify())
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
pub(super) fn wrapped_command<'a>(argv: &'a [String], program: &str) -> Option<&'a [String]> {
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
    if !WRAPPERS.contains(&program) || options::only_describes(argv, program) {
        return None;
    }
    let options_with_value = WRAPPER_OPTIONS_WITH_VALUE
        .iter()
        .find(|(name, _)| *name == program)
        .map_or(&[][..], |(_, opts)| *opts);
    let mut i = 1;
    let mut value_pending = WRAPPERS_WITH_VALUE.contains(&program);
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
