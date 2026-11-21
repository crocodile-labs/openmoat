//! `ps` and `pargs` asked to print the environments of other processes.
//!
//! `/proc/<pid>/environ` is a file read (`engine/atoms.rs`); these programs
//! print the same variables, secrets included, from their own options:
//!
//! - procps-ng (Linux) and the BSDs read a word without a dash as a cluster of
//!   BSD options, where `e` shows the environment after the command (`ps eww`,
//!   `ps auxe`). macOS reads the first such word as if it had a dash; there `e`
//!   is either the environment or every process, depending on the
//!   compatibility mode, so it counts.
//! - macOS's `-E` shows the environment in a dash cluster (`ps -axwwE`).
//! - `-e` with a dash is "every process" on Linux and macOS and does not
//!   count (`ps -e`, `ps -ef`). FreeBSD's `ps -e` shows the environment and
//!   is not seen (docs/LIMITS.md).
//! - Neither procps-ng nor macOS has an output column for the environment;
//!   `env`, `environ` and `environment` in a format list (`-o`, `-O`, `o`,
//!   `O`, `--format`) count anyway, since no listing uses them.
//! - Solaris and illumos `pargs -e` prints a process's environment.
//!
//! An option that takes a value (`-o pid,user`, `-u Edward`, `axo user`)
//! takes the rest of its cluster or the next word, so the letters of a value
//! are not read as options. Each finding is the atom
//! `@process-environ <program> <word>`, which `env-dump` denies.

use super::{ClassifyError, Sink};
use crate::action::AtomicAction;

/// Dash options that take a value, in procps-ng and macOS `ps`.
const DASH_VALUE: &str = "CGgOopqstUu";
/// BSD options (no dash) that take a value, in procps-ng `ps`.
const BSD_VALUE: &str = "OopktU";
/// Long options of procps-ng `ps` whose value may be the next word.
const LONG_VALUE: &[&str] = &[
    "cols",
    "columns",
    "format",
    "group",
    "Group",
    "lines",
    "pid",
    "ppid",
    "quick-pid",
    "rows",
    "sid",
    "sort",
    "tty",
    "user",
    "User",
    "width",
];
/// Output column names that would print the environment.
const ENV_COLUMNS: &[&str] = &["env", "environ", "environment"];

/// Emit `@process-environ <program> <word>` when `argv` asks `ps` or `pargs`
/// to print other processes' environments.
pub(super) fn note(argv: &[String], program: &str, sink: &mut Sink) -> Result<(), ClassifyError> {
    let options = argv.get(1..).unwrap_or_default();
    let word = match program {
        "ps" => ps_environment(options),
        "pargs" => options
            .iter()
            .find(|w| w.len() > 1 && w.starts_with('-') && !w.starts_with("--") && w.contains('e')),
        _ => None,
    };
    if let Some(word) = word {
        sink.push(AtomicAction::Shell {
            argv: vec![
                "@process-environ".to_owned(),
                program.to_owned(),
                word.clone(),
            ],
        })?;
    }
    Ok(())
}

/// The word of `ps`'s arguments that asks for the environment, if any.
fn ps_environment(args: &[String]) -> Option<&String> {
    let mut words = args.iter();
    while let Some(word) = words.next() {
        let found = if let Some(long) = word.strip_prefix("--") {
            long_option(long, &mut words)
        } else if let Some(cluster) = word.strip_prefix('-') {
            cluster_option(cluster, 'E', DASH_VALUE, &mut words)
        } else if !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric()) {
            cluster_option(word, 'e', BSD_VALUE, &mut words)
        } else {
            false
        };
        if found {
            return Some(word);
        }
    }
    None
}

/// Whether the long option `long` (without its `--`) asks for the
/// environment; takes its value from `rest` when it has no `=`.
fn long_option<'a>(long: &str, rest: &mut impl Iterator<Item = &'a String>) -> bool {
    let (name, value) = match long.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None if LONG_VALUE.contains(&long) => (long, rest.next().map(String::as_str)),
        None => (long, None),
    };
    name == "format" && value.is_some_and(names_env_column)
}

/// Whether the option cluster `cluster` holds `env_letter` before an option
/// that takes a value, or gives a format option a list naming an environment
/// column. A value-taking option takes the rest of the cluster or, when it is
/// last, the next word of `rest`.
fn cluster_option<'a>(
    cluster: &str,
    env_letter: char,
    takes_value: &str,
    rest: &mut impl Iterator<Item = &'a String>,
) -> bool {
    for (at, letter) in cluster.char_indices() {
        if letter == env_letter {
            return true;
        }
        if takes_value.contains(letter) {
            let attached = &cluster[at + letter.len_utf8()..];
            let value = if attached.is_empty() {
                rest.next().map(String::as_str)
            } else {
                Some(attached)
            };
            return matches!(letter, 'o' | 'O') && value.is_some_and(names_env_column);
        }
    }
    false
}

/// Whether a `ps` format list (`pid,user=USER,args:40`) names an
/// environment column.
fn names_env_column(format: &str) -> bool {
    format
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|item| item.split(['=', ':']).next().unwrap_or_default())
        .any(|name| ENV_COLUMNS.contains(&name.to_ascii_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::ps_environment;

    fn asks(line: &str) -> bool {
        let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        ps_environment(&args).is_some()
    }

    #[test]
    fn listings_that_print_environments() {
        for line in [
            "eww",
            "auxeww",
            "e -p 1",
            "-ef e",
            "-p 123 e",
            "axe",
            "-E",
            "-axwwE",
            "-Eww -p 1",
            "-o pid,env",
            "-opid,environ",
            "-O ENV",
            "axo pid,environment",
            "--format=pid,env",
            "--format pid,env=E",
        ] {
            assert!(asks(line), "{line}");
        }
    }

    #[test]
    fn listings_that_do_not() {
        for line in [
            "",
            "aux",
            "-ef",
            "-e",
            "-A",
            "-o pid,comm",
            "-p 123",
            "axo pid,ppid,command",
            "axo user,pid",
            "-eo pid,user,etime,command",
            "-eopid,user",
            "-u Edward",
            "-C sleeper",
            "U steve",
            "-eo pid,rss --sort=-rss",
            "--sort -pcpu",
            "--user steve",
            "-p1 -o args=",
            "123",
            "-o pid,envy",
        ] {
            assert!(!asks(line), "{line}");
        }
    }
}
