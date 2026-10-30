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
//! `git restore PATH` rewrites `PATH` in the working tree, so each path is an `fs.write`;
//! so is each pathspec of `git checkout [<tree-ish>] [--] <pathspec>…` (`checkout_paths`).
//! A local repository that `clone`, `fetch`, `pull`, `ls-remote` or `archive --remote`
//! names is an `fs.read`; the directory `clone` creates and a local repository
//! `push` updates are `fs.write`s (`remote_paths`).

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

/// Config keys (lowercase; a trailing `.` is a whole section) that never name a
/// program: identity, output, line endings, and how pull, push, fetch, rebase,
/// merge, diff and gc behave. `user.signingkey` and `commit.gpgsign` (except
/// `=false`, [`inert_config`]) make git run a signing program, so they are not here.
const INERT_CONFIG: &[&str] = &[
    "color.",
    "column.",
    "advice.",
    "log.",
    "i18n.",
    "user.name",
    "user.email",
    "core.quotepath",
    "core.autocrlf",
    "core.safecrlf",
    "core.abbrev",
    "init.defaultbranch",
    "pull.rebase",
    "pull.ff",
    "push.default",
    "push.autosetupremote",
    "fetch.prune",
    "rebase.autostash",
    "rebase.autosquash",
    "merge.conflictstyle",
    "diff.renames",
    "status.short",
    "gc.auto",
];

/// Whether a `-c`/`--config-env` value (`KEY[=VALUE]`) cannot make git run a
/// program: its key is in [`INERT_CONFIG`], or it turns signing off.
fn inert_config(value: &str) -> bool {
    let (key, setting) = value
        .split_once('=')
        .map_or((value, None), |(k, v)| (k, Some(v)));
    let key = key.to_ascii_lowercase();
    INERT_CONFIG
        .iter()
        .any(|k| key == *k || (k.ends_with('.') && key.starts_with(k)))
        || (key == "commit.gpgsign" && setting.is_some_and(|v| v.eq_ignore_ascii_case("false")))
}

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
    /// The argv indices of the words holding those directories: local paths,
    /// read by [`push_shell`], never hosts (`git -C site.dev fetch`).
    pub directory_words: Vec<usize>,
    /// True when an option can run a program, names the git directory or is not
    /// understood: the command line as written must be judged too.
    pub keep_original: bool,
}

/// Split `argv` (`argv[0]` is git) into its global options and the subcommand.
pub(crate) fn parse(argv: &[String]) -> GitCommand<'_> {
    let mut directories = Vec::new();
    let mut chdirs = Vec::new();
    let mut directory_words = Vec::new();
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
            directory_words.push(i - 1);
            if name == "-C" {
                chdirs.push(value);
            }
            keep_original |= name == GIT_DIR;
        } else if CONFIG.contains(&name) {
            keep_original |= !inert_config(value);
        }
    }
    GitCommand {
        subcommand: argv[..1].iter().chain(&argv[i..]).cloned().collect(),
        directories,
        chdirs,
        directory_words,
        keep_original,
    }
}

/// The argv indices of words that are no file or host for the argument scan:
/// the name `git config` looks up ([`config_name`]) and, for `git`, the
/// directories its global options name, which [`push_shell`] reads
/// ([`GitCommand::directory_words`]).
pub(super) fn data_words(argv: &[String], program: &str) -> Vec<usize> {
    let mut words: Vec<usize> = config_name(argv).into_iter().collect();
    if program == "git" {
        words.extend(parse(argv).directory_words);
    }
    words
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
    for path in checkout_paths(&git.subcommand) {
        sink.write(ctx, path)?;
    }
    for (path, writes) in remote_paths(&git.subcommand) {
        if writes {
            sink.write(ctx, path)?;
        } else {
            sink.read(ctx, path)?;
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

/// `git checkout` options whose value is the next word unless given with `=`.
const CHECKOUT_VALUED: &[&str] = &["-b", "-B", "--orphan", "--pathspec-from-file"];

/// The pathspecs a subcommand (`git` first) rewrites in the working tree when it
/// is `git checkout [<tree-ish>] [--] <pathspec>…`: every word after `--`; without
/// `--`, every operand after the first (git reads a second operand as a path) and
/// a first one that can only be a path, since no ref name starts with `.`, `/` or
/// `~` or holds `*`, `?` or `[` (`git checkout .claude/hooks/x.sh`). A plain
/// `git checkout main` writes nothing here. `--pathspec-from-file` names the paths
/// in a file: the working tree (`.`) is written.
fn checkout_paths(sub: &[String]) -> Vec<&str> {
    if sub.get(1).map(String::as_str) != Some("checkout") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut operands = Vec::new();
    let mut words = sub[2..].iter();
    while let Some(word) = words.next() {
        if word == "--" {
            out.extend(words.by_ref().map(String::as_str));
        } else if word.starts_with("--pathspec-from-file") {
            out.push(".");
            if !word.contains('=') {
                words.next();
            }
        } else if CHECKOUT_VALUED.contains(&word.as_str()) {
            words.next();
        } else if !word.starts_with('-') {
            operands.push(word.as_str());
        }
    }
    let only_a_path = |w: &&str| w.starts_with(['.', '/', '~']) || w.contains(['*', '?', '[']);
    if let Some((first, rest)) = operands.split_first() {
        out.extend(Some(*first).filter(only_a_path));
        out.extend(rest);
    }
    out
}

/// Options of `clone`, `fetch`, `pull`, `push`, `ls-remote` and `archive` whose
/// value is the next word unless given with `=`.
const REMOTE_VALUED: &[&str] = &[
    "-o",
    "--origin",
    "-b",
    "--branch",
    "-u",
    "--upload-pack",
    "--receive-pack",
    "--exec",
    "--reference",
    "--reference-if-able",
    "--separate-git-dir",
    "--depth",
    "--deepen",
    "--shallow-since",
    "--shallow-exclude",
    "-c",
    "--config",
    "--template",
    "-j",
    "--jobs",
    "--filter",
    "--server-option",
    "--bundle-uri",
    "--revision",
    "--ref-format",
    "--negotiation-tip",
    "--refmap",
    "--repo",
    "--push-option",
    "--sort",
    "--format",
    "--prefix",
    "--output",
    "--remote",
];

/// The local repositories a subcommand (`git` first) uses, with true when it
/// writes them: the repository of `clone`, `fetch`, `pull` and `ls-remote` and
/// the value of `git archive --remote` are read, the directory `clone` creates
/// and the repository `push` updates are written. A URL, `host:path` and a bare
/// name (a configured remote such as `origin`) are not local paths.
fn remote_paths(sub: &[String]) -> Vec<(&str, bool)> {
    let Some(name) = sub.get(1).map(String::as_str) else {
        return Vec::new();
    };
    let mut operands = Vec::new();
    let mut remote = None;
    let mut words = sub[2..].iter();
    let mut options = true;
    while let Some(word) = words.next() {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') {
            // `fetch -u` and `pull -u` are `--update-head-ok`, a flag
            let flag = word == "-u" && matches!(name, "fetch" | "pull");
            let (option, value) = match word.split_once('=') {
                Some((option, value)) => (option, Some(value)),
                None if !flag && REMOTE_VALUED.contains(&word.as_str()) => {
                    (word.as_str(), words.next().map(String::as_str))
                }
                None => (word.as_str(), None),
            };
            if option == "--remote" {
                remote = value;
            }
        } else {
            operands.push(word.as_str());
        }
    }
    let mut paths = Vec::new();
    match name {
        "clone" => {
            paths.extend(operands.first().map(|r| (*r, false)));
            paths.extend(operands.get(1).map(|d| (*d, true)));
        }
        "fetch" | "pull" | "ls-remote" => paths.extend(operands.first().map(|r| (*r, false))),
        "push" => paths.extend(operands.first().map(|r| (*r, true))),
        "archive" => paths.extend(remote.map(|r| (r, false))),
        _ => {}
    }
    let is_dest = |path: &str, writes: bool| name == "clone" && writes && !path.is_empty();
    paths.retain(|&(path, writes)| is_dest(path, writes) || is_local_repository(path));
    paths
}

/// A repository git reaches as a path: not a URL, not `host:path` (a `:` before
/// any `/`), and not a bare name, which git takes for a configured remote.
fn is_local_repository(remote: &str) -> bool {
    let head = remote.split('/').next().unwrap_or(remote);
    !remote.is_empty()
        && !remote.contains("://")
        && !head.contains(':')
        && (remote.contains('/') || remote.starts_with(['.', '~']))
}

#[cfg(test)]
mod tests {
    use super::{checkout_paths, config_name, parse, remote_paths};

    #[test]
    fn checkout_pathspecs_are_written() {
        for (cmd, paths) in [
            (
                "git checkout -- .claude/hooks/x.sh",
                &[".claude/hooks/x.sh"][..],
            ),
            ("git checkout main -- a b", &["a", "b"]),
            (
                "git checkout HEAD~2 -- .pre-commit-config.yaml",
                &[".pre-commit-config.yaml"],
            ),
            (
                "git checkout main .github/workflows/ci.yml",
                &[".github/workflows/ci.yml"],
            ),
            ("git checkout main src/main.rs", &["src/main.rs"]),
            ("git checkout .claude/hooks/x.sh", &[".claude/hooks/x.sh"]),
            ("git checkout ./a ~/b", &["./a", "~/b"]),
            ("git checkout '*.rs'", &["'*.rs'"]),
            ("git checkout .", &["."]),
            ("git checkout --pathspec-from-file=list main", &["."]),
            ("git checkout --pathspec-from-file list main", &["."]),
            ("git checkout main", &[]),
            ("git checkout origin/feature", &[]),
            ("git checkout -b feature", &[]),
            ("git checkout -b feature origin/feature", &[]),
            ("git checkout -B f --track origin/f", &[]),
            ("git checkout --orphan gh-pages", &[]),
            ("git checkout -", &[]),
            ("git restore a", &[]),
        ] {
            assert_eq!(checkout_paths(&argv(cmd)), paths, "{cmd}");
        }
    }

    #[test]
    fn local_remotes_are_read_and_clone_and_push_targets_written() {
        for (cmd, paths) in [
            ("git clone ../r", &[("../r", false)][..]),
            (
                "git clone --depth 1 /srv/r ~/.claude",
                &[("/srv/r", false), ("~/.claude", true)],
            ),
            ("git clone https://x.example/r d", &[("d", true)]),
            ("git clone host:r", &[]),
            ("git fetch origin main", &[]),
            ("git fetch ~/.ssh/r", &[("~/.ssh/r", false)]),
            ("git fetch -u ../r", &[("../r", false)]),
            ("git ls-remote -u up .", &[(".", false)]),
            ("git push ../mirror main", &[("../mirror", true)]),
            ("git push origin main", &[]),
            ("git archive --remote=../r HEAD", &[("../r", false)]),
            ("git archive --remote ~/r HEAD", &[("~/r", false)]),
            ("git log ../r", &[]),
        ] {
            let argv = argv(cmd);
            assert_eq!(remote_paths(&argv), paths, "{cmd}");
        }
    }

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
