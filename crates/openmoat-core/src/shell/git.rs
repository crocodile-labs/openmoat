//! git's global options come before the subcommand: `git -C dir push --force` and
//! `git -c k=v reset --hard` are `git push --force` and `git reset --hard`, so the
//! `Shell` atom is reported without them and rules written as `git <subcommand> …`
//! match. Directories they name are reads.
//!
//! A config value can name a program git runs (`core.sshCommand`, `core.fsmonitor`,
//! `core.hooksPath`, `alias.*`, `credential.helper`, `include.path`, …); the list is
//! open-ended, so any key not known to be inert, an `--exec-path=` and any option
//! git does not document also keep the command line as written. That atom matches
//! no `git <subcommand>` allow, so the command cannot ride on `dev-shell`.
//! `--git-dir` does the same: git takes its config and hooks from the directory it
//! names, which may be one planted in the project with ordinary file writes.
//!
//! `git restore PATH` rewrites `PATH` in the working tree, so each path is an `fs.write`.

use super::tables::GIT_HOST_SUBCOMMANDS;
use super::{ClassifyError, ShellContext, Sink};
use crate::action::AtomicAction;

const FLAGS: &[&str] = &[
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-advice",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];
const GIT_DIR: &str = "--git-dir";
const DIRECTORIES: &[&str] = &["-C", GIT_DIR, "--work-tree"];
const CONFIG: &[&str] = &["-c", "--config-env"];
const OTHER_VALUES: &[&str] = &["--namespace", "--super-prefix", "--attr-source"];

/// Config keys (lowercase; a trailing `.` is a whole section) that never name a program.
const INERT_CONFIG: &[&str] = &[
    "color.",
    "column.",
    "advice.",
    "log.",
    "user.name",
    "user.email",
    "core.quotepath",
    "core.autocrlf",
    "core.abbrev",
    "init.defaultbranch",
    "pull.rebase",
];

/// `git config` options whose value is the next word unless given with `=`.
const CONFIG_VALUED: &[&str] = &[
    "-f",
    "--file",
    "--blob",
    "-t",
    "--type",
    "--default",
    "--comment",
    "--value",
    "--url",
];
/// The word before the name in `git config get user.name` (git 2.46).
const CONFIG_SUBCOMMANDS: &[&str] = &[
    "get",
    "set",
    "unset",
    "list",
    "edit",
    "rename-section",
    "remove-section",
];

/// git's argv with its global options taken apart.
pub(crate) struct GitCommand<'a> {
    /// `git` as written, then the subcommand and its arguments.
    pub subcommand: Vec<String>,
    /// Values of `-C`, `--git-dir` and `--work-tree`.
    pub directories: Vec<&'a str>,
    /// Values of `-C` alone, in order: git changes into each before it runs.
    pub chdirs: Vec<&'a str>,
    /// True when an option can run a program, names the git directory or is not
    /// understood: the command line as written must be judged too.
    pub keep_original: bool,
}

/// Split `argv` (`argv[0]` is git) into its global options and the subcommand.
pub(crate) fn parse(argv: &[String]) -> GitCommand<'_> {
    let mut directories = Vec::new();
    let mut chdirs = Vec::new();
    let mut keep_original = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i).filter(|a| a.starts_with('-')) {
        i += 1;
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (arg.as_str(), None),
        };
        if inline.is_none() && FLAGS.contains(&name) {
            continue;
        }
        if ![DIRECTORIES, CONFIG, OTHER_VALUES]
            .iter()
            .any(|options| options.contains(&name))
        {
            keep_original = true;
            continue;
        }
        let Some(value) = inline.or_else(|| argv.get(i).map(String::as_str)) else {
            keep_original = true;
            break;
        };
        i += usize::from(inline.is_none());
        if DIRECTORIES.contains(&name) {
            directories.push(value);
            if name == "-C" {
                chdirs.push(value);
            }
            keep_original |= name == GIT_DIR;
        } else if CONFIG.contains(&name) {
            let key = value
                .split_once('=')
                .map_or(value, |(k, _)| k)
                .to_ascii_lowercase();
            keep_original |= !INERT_CONFIG
                .iter()
                .any(|k| key == *k || (k.ends_with('.') && key.starts_with(k)));
        }
    }
    GitCommand {
        subcommand: argv[..1].iter().chain(&argv[i..]).cloned().collect(),
        directories,
        chdirs,
        keep_original,
    }
}

/// True when the subcommand, past git's global options (`git -C dir push`), names a
/// remote host in its arguments ([`GIT_HOST_SUBCOMMANDS`]).
pub(super) fn names_hosts(argv: &[String]) -> bool {
    parse(argv)
        .subcommand
        .get(1)
        .is_some_and(|s| GIT_HOST_SUBCOMMANDS.contains(&s.as_str()))
}

/// The argv index of the name in `git config [<subcommand>] <name> …`. A config
/// key reads like a host under a known top-level domain (`user.name`,
/// `user.email`), but git only looks it up in its config files, so it is data.
pub(super) fn config_name(argv: &[String]) -> Option<usize> {
    let start = argv.len() + 1 - parse(argv).subcommand.len();
    if argv.get(start).map(String::as_str) != Some("config") {
        return None;
    }
    let mut i = start + 1;
    let mut subcommand_seen = false;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if arg.starts_with('-') {
            i += usize::from(CONFIG_VALUED.contains(&arg.as_str()));
        } else if !subcommand_seen && CONFIG_SUBCOMMANDS.contains(&arg.as_str()) {
            subcommand_seen = true;
        } else {
            return Some(i - 1);
        }
    }
    None
}

pub(super) fn push_shell(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let git = parse(argv);
    for dir in git.directories {
        sink.read(ctx, dir)?;
    }
    // `git restore PATH` rewrites `PATH` from the index or a commit. Every word
    // that is not an option is taken as one, a `--source` value included:
    // stricter, never looser.
    if git.subcommand.get(1).is_some_and(|s| s == "restore") {
        let mut options = true;
        for word in &git.subcommand[2..] {
            if options && word == "--" {
                options = false;
            } else if !options || !word.starts_with('-') {
                sink.write(ctx, word)?;
            }
        }
    }
    sink.push(AtomicAction::Shell {
        argv: git.subcommand,
    })?;
    if git.keep_original {
        sink.push(AtomicAction::Shell {
            argv: argv.to_vec(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{config_name, parse};

    fn argv(cmd: &str) -> Vec<String> {
        cmd.split(' ').map(str::to_owned).collect()
    }

    fn keeps_original(cmd: &str) -> bool {
        parse(&argv(cmd)).keep_original
    }

    #[test]
    fn a_named_git_directory_keeps_the_command_as_written() {
        assert!(keeps_original("git --git-dir=evil status"));
        assert!(keeps_original("git --git-dir evil log"));
        assert!(!keeps_original("git -C sub status"));
        assert!(!keeps_original("git --work-tree=sub status"));
    }

    #[test]
    fn the_config_name_is_found_past_options_and_subcommands() {
        for (cmd, name) in [
            ("git config --get user.name", Some(3)),
            ("git -C sub config --global user.email", Some(5)),
            ("git config -f .gitmodules --get-regexp path", Some(5)),
            ("git config --file=x --get user.name", Some(4)),
            ("git config get --show-origin user.name", Some(4)),
            ("git config --list", None),
            ("git log user.name", None),
            ("git", None),
        ] {
            assert_eq!(config_name(&argv(cmd)), name, "{cmd}");
        }
    }
}
