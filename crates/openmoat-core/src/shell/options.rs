//! Options of ordinary programs that run another command or write a file.
//!
//! `find . -exec cmd {} \;` runs `cmd`; `git diff --output=FILE` writes `FILE`.
//! `python -m venv dir` creates `dir`; `gofmt -w f.go` rewrites `f.go`. None of these shows up as a separate
//! command or a path-looking token, so they are surfaced here: the `-exec`
//! command is classified as a command of its own, and the `--output` value and
//! the venv directory and the files `gofmt` rewrites become `fs.write`s.

pub(super) mod transfer;

use super::commands::classify_wrapped;
use super::{ClassifyError, ShellContext, Sink};

/// `find` actions whose arguments, up to `;` or `+`, are a command to run.
const FIND_EXEC: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    // `python -m venv DIR…` creates each `DIR`, a plain name included. An option
    // value (`--prompt NAME`) is treated as a directory too: stricter, never looser.
    if program.starts_with("python")
        && matches!(argv.get(1..3), Some([m, venv]) if m == "-m" && venv == "venv")
    {
        for dir in argv[3..].iter().filter(|a| !a.starts_with('-')) {
            sink.write(ctx, dir)?;
        }
    }
    if program == "gofmt" {
        gofmt(argv, ctx, sink)?;
    }
    super::upload::classify(argv, program, ctx, sink)?;
    super::in_place::classify(argv, program, ctx, sink)?;
    // curl and wget: every spelling of an output (`-sSo f`, `-oF`, `wget -qO f`),
    // under `--output-dir`/`-P`, and the remote file name `-O` and wget save under
    let client = transfer::Client::of(program);
    if let Some(client) = client {
        for file in transfer::written(argv, client) {
            sink.write(ctx, &file)?;
        }
    }
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if program == "find" && FIND_EXEC.contains(&arg.as_str()) {
            let rest = &argv[i..];
            let end = rest
                .iter()
                .position(|a| a == ";" || a == "+")
                .unwrap_or(rest.len());
            if end > 0 {
                classify_wrapped(&rest[..end], ctx, sink, depth)?;
            }
            i += end + 1;
            continue;
        }
        if client.is_some() {
            continue;
        }
        let target = match arg
            .strip_prefix("--output=")
            .or_else(|| arg.strip_prefix("--output-document="))
        {
            Some(value) => Some(value),
            None if arg == "--output" || arg == "--output-document" => {
                argv.get(i).map(String::as_str)
            }
            None => None,
        };
        if let Some(path) = target.filter(|p| !p.is_empty() && *p != "-") {
            sink.write(ctx, path)?;
        }
    }
    Ok(())
}

/// `fd` flags that take no value, so the word after them is still the pattern.
const FD_FLAGS: &str = "HIuisgFalLp01q";
const FD_LONG_FLAGS: &[&str] = &[
    "--hidden",
    "--no-ignore",
    "--no-ignore-vcs",
    "--unrestricted",
    "--ignore-case",
    "--case-sensitive",
    "--glob",
    "--regex",
    "--fixed-strings",
    "--absolute-path",
    "--list-details",
    "--follow",
    "--full-path",
    "--print0",
    "--quiet",
    "--prune",
    "--show-errors",
    "--one-file-system",
];

/// The index of `fd`'s pattern, its first operand: a regex such as `\.rs$`,
/// not a path. Only when every word before it is a flag without a value; after
/// any other option the word stays a possible path (stricter).
pub(super) fn fd_pattern(argv: &[String], program: &str) -> Option<usize> {
    if program != "fd" {
        return None;
    }
    let at = argv.iter().skip(1).position(|a| !a.starts_with('-'))? + 1;
    let flag = |a: &String| {
        FD_LONG_FLAGS.contains(&a.as_str())
            || a.strip_prefix('-')
                .is_some_and(|f| !f.is_empty() && f.chars().all(|c| FD_FLAGS.contains(c)))
    };
    argv[1..at].iter().all(flag).then_some(at)
}

/// `grep` flags that take no value (GNU and BSD), so the word after them is
/// still the pattern.
const GREP_FLAGS: &str = "abcEFGhHiIlLnoPqrRsTUvVwxyzZ";
const GREP_LONG_FLAGS: &[&str] = &[
    "--count",
    "--ignore-case",
    "--no-ignore-case",
    "--line-number",
    "--recursive",
    "--dereference-recursive",
    "--files-with-matches",
    "--files-without-match",
    "--only-matching",
    "--quiet",
    "--silent",
    "--no-messages",
    "--invert-match",
    "--word-regexp",
    "--line-regexp",
    "--with-filename",
    "--no-filename",
    "--extended-regexp",
    "--fixed-strings",
    "--basic-regexp",
    "--perl-regexp",
    "--null",
    "--null-data",
    "--text",
    "--byte-offset",
    "--initial-tab",
    "--color",
    "--colour",
];

/// The index of the pattern of `grep`, `egrep` or `fgrep`: its first operand,
/// text such as `\.env` or `a/b`, which grep never opens. Only when every word
/// before it is a flag without a value (or a `--name=value`), and no word of the
/// command gives the pattern another way: with `-e` or `-f` (in any cluster, or
/// `--regexp`/`--file` in any abbreviation) every operand is a file, and GNU grep
/// finds them anywhere on the line (`grep ~/.ssh/id_rsa -e x` reads the key).
pub(super) fn grep_pattern(argv: &[String], program: &str) -> Option<usize> {
    if !matches!(program, "grep" | "egrep" | "fgrep") {
        return None;
    }
    let end = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    let names_pattern = |a: &String| match a.strip_prefix("--") {
        Some(long) => {
            let name = long.split('=').next().unwrap_or(long);
            name.is_empty() || "regexp".starts_with(name) || "file".starts_with(name)
        }
        None => a.len() > 1 && a.starts_with('-') && a[1..].contains(['e', 'f']),
    };
    if argv[1..end].iter().any(names_pattern) {
        return None;
    }
    let at = argv[1..end]
        .iter()
        .position(|a| !a.starts_with('-'))
        .map(|i| i + 1)
        .or_else(|| (end + 1 < argv.len()).then_some(end + 1))?;
    let flag = |a: &String| {
        a == "--"
            || GREP_LONG_FLAGS.contains(&a.as_str())
            || (a.starts_with("--") && a.contains('='))
            || a.strip_prefix('-')
                .is_some_and(|f| !f.is_empty() && f.chars().all(|c| GREP_FLAGS.contains(c)))
    };
    argv[1..at].iter().all(flag).then_some(at)
}

/// `command -v name` and `command -V name` print how the shell would find
/// `name` and run nothing.
pub(super) fn only_describes(argv: &[String], program: &str) -> bool {
    program == "command"
        && argv[1..]
            .iter()
            .take_while(|a| a.starts_with('-') && *a != "--")
            .any(|a| a.contains(['v', 'V']))
}

/// `gofmt -w` rewrites every file operand in place, and `-cpuprofile FILE`
/// writes `FILE`. Go's flag package takes `-name` and `--name`, with `=VALUE`
/// or the next word. Any `-w` counts, `-w=false` included: stricter, never looser.
fn gofmt(argv: &[String], ctx: &ShellContext<'_>, sink: &mut Sink) -> Result<(), ClassifyError> {
    let rewrites = argv[1..].iter().any(|a| go_flag(a) == Some("w"));
    let mut words = argv[1..].iter();
    while let Some(arg) = words.next() {
        match go_flag(arg) {
            Some("cpuprofile") => {
                let value = arg
                    .split_once('=')
                    .map(|(_, v)| v)
                    .or_else(|| words.next().map(String::as_str));
                if let Some(file) = value {
                    sink.write(ctx, file)?;
                }
            }
            None if rewrites => sink.write(ctx, arg)?,
            Some(_) | None => {}
        }
    }
    Ok(())
}

/// The name of a Go flag (`-w`, `--cpuprofile=f` → `w`, `cpuprofile`), or
/// `None` for an operand.
fn go_flag(arg: &str) -> Option<&str> {
    let flag = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'))?;
    Some(flag.split_once('=').map_or(flag, |(name, _)| name))
}
