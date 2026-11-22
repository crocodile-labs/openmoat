//! `rtk` (Rust Token Killer, <https://github.com/rtk-ai/rtk>): runs a command
//! and shortens its output for an agent.
//!
//! Its subcommands are read from its command table (`Commands` in `src/lib.rs`,
//! and `RTK_META_COMMANDS` in `src/core/constants.rs`, at commit `d0f0399a`,
//! 2026-11-19). Most run the program of their name (`rtk git status` runs
//! `git status`), and a name rtk does not know is run as a command too
//! (`run_fallback`: `rtk cat F` runs `cat F`). Its own subcommands are not
//! programs: `rtk read F` reads `F` itself, and read as the shell builtin
//! `read` it would name no file. So `bypass` (alias `proxy`), `err`, `test`,
//! `summary` and `run` are read as the command they run, the file readers as
//! `cat` of their files, `env` as `printenv`, and rtk's own state commands
//! (`init`, `gain`, …) stay an rtk command whose arguments are checked as any
//! program's.

/// What `rtk` runs, as a command line, and where its words came from.
pub(super) struct Run {
    /// The command it runs, or the one that reads what it reads.
    pub words: Vec<String>,
    /// The index in rtk's argv of each word of `words`, `None` for a word
    /// made up here (`cat`, `-c`), so substitutions follow the words they
    /// were written in (`rtk err --shell sh "$(curl URL)"`).
    pub from: Vec<Option<usize>>,
}

impl Run {
    fn tail(argv: &[String], start: usize) -> Option<Self> {
        let words = argv.get(start..).filter(|rest| !rest.is_empty())?.to_vec();
        let from = (start..argv.len()).map(Some).collect();
        Some(Self { words, from })
    }

    fn made(head: &[&str], argv: &[String], kept: &[usize]) -> Self {
        let words = head
            .iter()
            .map(|w| (*w).to_owned())
            .chain(kept.iter().map(|&i| argv[i].clone()))
            .collect();
        let from = head
            .iter()
            .map(|_| None)
            .chain(kept.iter().copied().map(Some))
            .collect();
        Self { words, from }
    }
}

/// rtk's own subcommands that run no program of their name: they read or
/// change rtk's settings, statistics and the agents' hook files. Left as an
/// rtk command, with its arguments checked as before.
const OWN: &[&str] = &[
    "gain",
    "discover",
    "learn",
    "init",
    "config",
    "recall",
    "hook",
    "hook-audit",
    "pipe",
    "cc-economics",
    "verify",
    "trust",
    "untrust",
    "session",
    "rewrite",
    "telemetry",
    "llm-proxy",
    "pipeline",
    "methods",
    "tasks",
    "plugins",
    // runs prettier, black or ruff, whichever the project's files name
    "format",
];

/// Subcommands that read the files (or, for `deps`, the directory) they
/// name, with the options of each that take a value.
const READERS: &[(&str, &[&str])] = &[
    (
        "read",
        &[
            "-l",
            "--level",
            "-m",
            "--max-lines",
            "--head-lines",
            "--tail-lines",
        ],
    ),
    ("smart", &["-m", "--model"]),
    ("json", &["-d", "--depth"]),
    ("diff", &[]),
    ("log", &[]),
    ("deps", &[]),
];

/// Subcommands that run a program of another name.
const RENAMED: &[(&str, &[&str])] = &[
    ("lint", &["eslint"]),
    ("npm", &["npm", "run"]),
    ("phpt", &["php", "run-tests.php"]),
];

/// `rtk grep`'s own options, which grep never sees; `--max-len` and `--max`
/// take a value.
const GREP_OWN: &[&str] = &["--max-len", "--max", "--context-only"];

/// The command `rtk …` runs; `None` for rtk's own state commands and a bare
/// `rtk`.
pub(super) fn command(argv: &[String]) -> Option<Run> {
    // rtk's options before the subcommand take no value (`-v`, `-u`, `--skip-env`)
    let at = (1..argv.len()).find(|&i| !argv[i].starts_with('-'))?;
    let sub = argv[at].as_str();
    let rest = at + 1;
    if OWN.contains(&sub) {
        return None;
    }
    if let Some((_, with_value)) = READERS.iter().find(|(name, _)| *name == sub) {
        let files = operands(argv, rest, with_value);
        return (!files.is_empty()).then(|| Run::made(&["cat", "--"], argv, &files));
    }
    if let Some((_, head)) = RENAMED.iter().find(|(name, _)| *name == sub) {
        return Some(Run::made(
            head,
            argv,
            &(rest..argv.len()).collect::<Vec<_>>(),
        ));
    }
    match sub {
        // `rtk env [-f NAME]` prints the environment, filtered by name
        "env" => Some(Run::made(&["printenv"], argv, &[])),
        "grep" => Some(Run::made(&["grep"], argv, &grep_operands(argv, rest))),
        "bypass" | "proxy" => Run::tail(argv, rest + usize::from(is(argv, rest, "--"))),
        "err" | "summary" | "test" => runner(argv, rest, sub == "test"),
        "run" => run(argv, rest),
        // a typed proxy (`git`, `cargo`, `ls`, …), `find` (rtk's own, which takes
        // find's syntax: read as find, `-exec` included), or a name rtk runs as is
        _ => Run::tail(argv, at),
    }
}

fn is(argv: &[String], i: usize, word: &str) -> bool {
    argv.get(i).is_some_and(|w| w == word)
}

/// The indices of the operands from `start` on: not an option, nor the
/// value of one of `with_value`.
fn operands(argv: &[String], start: usize, with_value: &[&str]) -> Vec<usize> {
    let mut kept = Vec::new();
    let mut i = start;
    let mut options = true;
    while let Some(word) = argv.get(i) {
        i += 1;
        if options && word == "--" {
            options = false;
        } else if options && with_value.contains(&word.as_str()) {
            i += 1;
        } else if !options || !word.starts_with('-') || word == "-" {
            kept.push(i - 1);
        }
    }
    kept
}

/// `rtk grep`'s words without its own options: grep's options, pattern and
/// paths, as grep is run with them.
fn grep_operands(argv: &[String], start: usize) -> Vec<usize> {
    let mut kept = Vec::new();
    let mut i = start;
    while let Some(word) = argv.get(i) {
        i += 1;
        let name = word.split_once('=').map_or(word.as_str(), |(n, _)| n);
        if GREP_OWN.contains(&name) {
            i += usize::from(name != "--context-only" && !word.contains('='));
            continue;
        }
        kept.push(i - 1);
    }
    kept
}

/// The value of `--shell` (`--shell SH`, `--shell=SH`) at `i`, and where the
/// next word is.
fn shell_option(argv: &[String], i: usize) -> Option<(&str, usize)> {
    let word = argv.get(i)?;
    if word == "--shell" {
        return Some((argv.get(i + 1)?.as_str(), i + 2));
    }
    word.strip_prefix("--shell=").map(|shell| (shell, i + 1))
}

/// `rtk err|summary|test [--shell SH] COMMAND…`: the command, or with
/// `--shell` the one script `SH -c` runs. `rtk test` with an expression
/// (`rtk test -f Cargo.toml`) runs the `test` program.
fn runner(argv: &[String], mut i: usize, test: bool) -> Option<Run> {
    let mut shell = None;
    if let Some((sh, next)) = shell_option(argv, i) {
        shell = Some(sh);
        i = next;
    }
    i += usize::from(is(argv, i, "--"));
    if let Some(shell) = shell {
        return script(argv, shell, i);
    }
    if test {
        let mut first = i;
        while matches!(argv.get(first).map(String::as_str), Some("!" | "(")) {
            first += 1;
        }
        if argv.get(first)?.starts_with('-') {
            return Some(Run::made(
                &["test"],
                argv,
                &(i..argv.len()).collect::<Vec<_>>(),
            ));
        }
        // `rtk test ! cmd` negates the status of `cmd`
        i = first;
    }
    Run::tail(argv, i)
}

/// `rtk run [-c SCRIPT [--shell SH]] [ARGS…]`.
fn run(argv: &[String], mut i: usize) -> Option<Run> {
    let mut shell = "sh";
    let mut code = None;
    while let Some(word) = argv.get(i) {
        if let Some((sh, next)) = shell_option(argv, i) {
            shell = sh;
            i = next;
        } else if word == "-c" || word == "--command" {
            code = Some(i + 1);
            i += 2;
        } else if let Some(text) = word.strip_prefix("--command=") {
            return Some(Run {
                words: vec![shell.to_owned(), "-c".to_owned(), text.to_owned()],
                from: vec![None, None, Some(i)],
            });
        } else {
            break;
        }
    }
    match code {
        Some(at) => script(argv, shell, at),
        None => Run::tail(argv, i + usize::from(is(argv, i, "--"))),
    }
}

/// `SH -c` of the script from word `at` on: rtk takes one word; more are
/// joined, as a shell would read them.
fn script(argv: &[String], shell: &str, at: usize) -> Option<Run> {
    let words = argv.get(at..).filter(|rest| !rest.is_empty())?;
    let one = words.len() == 1;
    Some(Run {
        words: vec![shell.to_owned(), "-c".to_owned(), words.join(" ")],
        from: vec![None, None, one.then_some(at)],
    })
}
