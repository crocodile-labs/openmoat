//! Shell commands that start a program reading its commands from its input.
//!
//! Codex's `write_stdin` types into a process an earlier shell call started,
//! and "doesn't run `PreToolUse` again" (<https://learn.chatgpt.com/docs/hooks>).
//! A shell, REPL, editor or remote login started with no script or command of
//! its own then runs whatever is typed later, unseen. Such a start is told by
//! its arguments: `bash`, `python3`, `node`, `sqlite3 db` and `ssh host` read
//! their input; `bash x.sh`, `python3 -c …`, `node x.js`, `sqlite3 db 'select
//! 1'` and `ssh host cmd` run what the call shows. A program whose input is a
//! pipe, a file, a here-document or nothing (`&`) cannot be typed into.

use openmoat_core::lexer::{Operator, Token, lex};

/// How one program's arguments tell whether it reads its commands from its input.
type Reads = fn(&[&str]) -> bool;

/// Programs that read commands from their input, and how to tell when they do.
const PROGRAMS: &[(&[&str], Reads)] = &[
    (
        &[
            "bash", "sh", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh",
        ],
        shell,
    ),
    (&["python", "python2", "python3", "pypy", "pypy3"], python),
    (&["node", "nodejs"], node),
    (&["ruby", "perl", "php", "lua", "luajit", "julia"], interpreter),
    (&["irb", "ghci", "bc", "telnet", "ftp"], always),
    (&["deno", "bun"], repl_subcommand),
    (&["sqlite3"], sqlite),
    (&["psql"], psql),
    (&["mysql", "mariadb"], mysql),
    (&["mongosh", "mongo"], mongo),
    (&["ssh"], ssh),
    (&["sftp"], sftp),
    (&["su"], su),
    (&["vi", "vim", "nvim", "view", "nano", "pico", "ed", "ex"], editor),
    (&["emacs"], emacs),
    (&["tmux"], tmux),
    (&["screen"], screen),
    (&["script"], script),
    (&["docker", "podman"], container),
    (&["kubectl"], kubectl),
];

/// The program a simple command of `command` starts that reads its commands
/// from its input, when one does; `None` for a command line that cannot be
/// read (it needs review as `unparseable` anyway).
pub(super) fn reads_commands(command: &str) -> Option<String> {
    let tokens = lex(command).ok()?;
    let mut simple = Simple::default();
    let mut redirect_target = false;
    for token in &tokens {
        match token {
            Token::Word(_) if redirect_target => redirect_target = false,
            Token::Word(word) => simple.words.push(word.text.as_str()),
            Token::HereDoc { .. } => simple.input_set = true,
            Token::Operator(op) if op.is_redirect() => {
                redirect_target = true;
                if matches!(
                    op,
                    Operator::RedirectIn | Operator::RedirectReadWrite | Operator::HereString
                ) {
                    simple.input_set = true;
                }
            }
            Token::Operator(op) => {
                if *op != Operator::Background
                    && let Some(program) = simple.reads()
                {
                    return Some(program);
                }
                simple = Simple {
                    input_set: *op == Operator::Pipe,
                    ..Simple::default()
                };
            }
        }
    }
    simple.reads()
}

/// One simple command: its words, and whether its input is not the
/// terminal Codex types into (a pipe, a file, a here-document).
#[derive(Default)]
struct Simple<'a> {
    words: Vec<&'a str>,
    input_set: bool,
}

impl Simple<'_> {
    fn reads(&self) -> Option<String> {
        if self.input_set {
            return None;
        }
        let words = unwrapped(&self.words);
        let (program, args) = words.split_first()?;
        let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
        let reads = PROGRAMS
            .iter()
            .find(|(names, _)| names.contains(&name) || is_versioned_python(name, names))
            .map(|(_, reads)| *reads)?;
        reads(args).then(|| name.to_owned())
    }
}

/// `python3.12` is `python3`.
fn is_versioned_python(name: &str, names: &[&str]) -> bool {
    names.contains(&"python3")
        && name
            .strip_prefix("python3.")
            .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
}

/// Programs that run the rest of their arguments as a command, and their
/// options that take the next word as a value.
const WRAPPERS: &[(&str, &[&str])] = &[
    ("env", &["-u", "-C", "-S"]),
    ("exec", &["-a"]),
    ("command", &[]),
    ("time", &[]),
    ("nice", &["-n"]),
    (
        "sudo",
        &["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"],
    ),
    ("doas", &["-u", "-C"]),
];

/// `words` without leading variable assignments and the wrappers that run
/// the rest as a command (`env`, `exec`, `command`, `sudo`, `nice`, `time`),
/// with their own options. `sudo -i` and `sudo -s` start a shell themselves,
/// so they stand for one.
fn unwrapped<'a>(mut words: &'a [&'a str]) -> Vec<&'a str> {
    loop {
        while words.first().is_some_and(|w| is_assignment(w)) {
            words = &words[1..];
        }
        let Some((first, rest)) = words.split_first() else {
            return Vec::new();
        };
        let name = first.rsplit('/').next().unwrap_or(first);
        let Some((_, takes_value)) = WRAPPERS.iter().find(|(wrapper, _)| *wrapper == name) else {
            return words.to_vec();
        };
        if name == "command" && rest.iter().any(|w| matches!(*w, "-v" | "-V")) {
            return Vec::new();
        }
        if matches!(name, "sudo" | "doas") && rest.iter().any(|w| matches!(*w, "-i" | "-s")) {
            return vec!["sh"];
        }
        let mut i = 0;
        while let Some(word) = rest.get(i) {
            if *word == "--" {
                i += 1;
                break;
            }
            if !word.starts_with('-') || *word == "-" {
                break;
            }
            i += if takes_value.contains(word) { 2 } else { 1 };
        }
        words = rest.get(i..).unwrap_or_default();
    }
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.as_bytes()[0].is_ascii_digit()
    })
}

/// The arguments that are not options, `values` naming the options that take
/// the next word as theirs; `--` ends the options.
fn operands<'a>(args: &[&'a str], values: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if *word == "--" {
            out.extend(words.by_ref().copied());
            break;
        }
        if word.len() > 1 && (word.starts_with('-') || word.starts_with('+')) {
            if values.contains(word) {
                words.next();
            }
            continue;
        }
        out.push(*word);
    }
    out
}

fn has(args: &[&str], flags: &[&str]) -> bool {
    args.iter().any(|a| {
        flags.contains(a)
            || flags
                .iter()
                .any(|f| f.starts_with("--") && a.starts_with(&format!("{f}=")))
    })
}

/// A cluster of short options (`-lc`), not a long one or `-`.
fn is_short(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1
}

fn always(_args: &[&str]) -> bool {
    true
}

/// A shell reads its input unless given `-c` (alone or in a cluster such as
/// `-lc`) or a script; `-s` reads it even with arguments.
fn shell(args: &[&str]) -> bool {
    if args.iter().any(|a| is_short(a) && a.contains('c')) || has(args, &["--command"]) {
        return false;
    }
    if args.iter().any(|a| is_short(a) && a.contains('s')) {
        return true;
    }
    if has(args, &["--version", "--help"]) {
        return false;
    }
    operands(args, &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]).is_empty()
}

/// Python reads its input with no script, with `-` or with `-i`.
fn python(args: &[&str]) -> bool {
    if has(args, &["-i"]) {
        return true;
    }
    if has(args, &["-c", "-m", "-V", "--version", "-h", "--help"]) {
        return false;
    }
    match operands(args, &["-W", "-X", "-Q"]).first() {
        None | Some(&"-") => true,
        Some(_) => false,
    }
}

/// Node reads its input with no script, with `-` or with `-i`.
fn node(args: &[&str]) -> bool {
    if has(args, &["-i", "--interactive"]) {
        return true;
    }
    let runs = [
        "-e", "--eval", "-p", "--print", "-c", "--check", "-v", "--version", "-h", "--help",
    ];
    if has(args, &runs) {
        return false;
    }
    let values = ["-r", "--require", "--import", "--loader", "--experimental-loader"];
    match operands(args, &values).first() {
        None | Some(&"-") => true,
        Some(_) => false,
    }
}

/// Ruby, Perl, PHP, Lua and Julia read a script, or their REPL's commands,
/// from their input when given none (`-` too). Inline code is `-e` or a
/// cluster holding it (`perl -pe`, `-ne`) and PHP's `-r`.
fn interpreter(args: &[&str]) -> bool {
    if args.iter().any(|a| is_short(a) && a.contains(['e', 'E']))
        || has(args, &["-r", "-v", "--version", "-h", "--help"])
    {
        return false;
    }
    match operands(args, &["-I"]).first() {
        None | Some(&"-") => true,
        Some(_) => false,
    }
}

/// `deno` and `bun` start their REPL with no arguments (`deno`) or `repl`.
fn repl_subcommand(args: &[&str]) -> bool {
    args.first().is_none_or(|first| *first == "repl")
}

/// `sqlite3 [db]` reads SQL from its input; `sqlite3 db 'sql'` runs the SQL.
fn sqlite(args: &[&str]) -> bool {
    if has(args, &["-version", "--version", "-help", "--help"]) {
        return false;
    }
    let values = [
        "-cmd", "-separator", "-newline", "-nullvalue", "-init", "-vfs", "-mmap", "-maxsize",
    ];
    operands(args, &values).len() <= 1
}

/// `psql` reads SQL from its input unless given `-c`, `-f` or `-l`.
fn psql(args: &[&str]) -> bool {
    let runs = ["--command", "--file", "--list", "-l", "-V", "--version", "--help"];
    !(has(args, &runs) || args.iter().any(|a| a.starts_with("-c") || a.starts_with("-f")))
}

/// `mysql` reads SQL from its input unless given `-e`.
fn mysql(args: &[&str]) -> bool {
    let runs = ["--execute", "-V", "--version", "--help"];
    !(has(args, &runs) || args.iter().any(|a| a.starts_with("-e")))
}

/// The MongoDB shell reads its input unless given `--eval` or a script.
fn mongo(args: &[&str]) -> bool {
    if has(args, &["--eval", "-f", "--file", "--version", "--help"]) {
        return false;
    }
    !args.iter().any(|a| {
        std::path::Path::new(a)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
    })
}

/// `ssh host` logs in and reads its input; `ssh host cmd` runs `cmd`, and `-N`
/// runs nothing.
fn ssh(args: &[&str]) -> bool {
    if has(args, &["-N", "-V", "-G", "-Q"]) {
        return false;
    }
    let values = [
        "-b", "-B", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
        "-p", "-R", "-S", "-W", "-w",
    ];
    operands(args, &values).len() <= 1
}

/// `sftp` reads commands from its input unless given a batch file (`-b`).
fn sftp(args: &[&str]) -> bool {
    !args.iter().any(|a| a.starts_with("-b"))
}

/// `su` starts a shell unless given `-c`.
fn su(args: &[&str]) -> bool {
    !(has(args, &["-c", "--command"]) || args.iter().any(|a| a.starts_with("-c")))
}

/// An editor reads its keys from its input, and runs a shell on `:!`.
fn editor(args: &[&str]) -> bool {
    !has(args, &["--version", "-h", "--help"])
}

/// Emacs is an editor too, except in batch mode.
fn emacs(args: &[&str]) -> bool {
    !has(args, &["--batch", "-batch", "--script", "--version", "--help"])
}

/// `tmux` and `tmux new`/`attach` open a terminal of their own, unless `-d`.
fn tmux(args: &[&str]) -> bool {
    let opens = ["new", "new-session", "attach", "attach-session", "a", "at"];
    match args.first() {
        None => true,
        Some(first) => opens.contains(first) && !has(args, &["-d"]),
    }
}

/// `screen` opens a terminal of its own unless started detached or asked
/// about its sessions.
fn screen(args: &[&str]) -> bool {
    !args.iter().any(|a| {
        a.starts_with("-d") || matches!(*a, "-ls" | "-list" | "-v" | "-Q" | "-X" | "-wipe")
    })
}

/// `script` runs a shell unless given a command (`-c`, or after the file on macOS).
fn script(args: &[&str]) -> bool {
    !(has(args, &["-c", "--command"]) || operands(args, &["-t", "-T", "-I", "-O", "-B"]).len() > 1)
}

/// `docker run -i` and `docker exec -i` pass their input to the container's
/// program; `-d` detaches it.
fn container(args: &[&str]) -> bool {
    let stdin = ["-i", "-it", "-ti", "--interactive"];
    matches!(args.first(), Some(&("run" | "exec")))
        && has(args, &stdin)
        && !has(args, &["-d", "--detach", "-itd", "-dit"])
}

/// `kubectl exec -i`, `run -i` and `attach -i` pass their input to the pod.
fn kubectl(args: &[&str]) -> bool {
    let stdin = ["-i", "-it", "-ti", "--stdin"];
    matches!(args.first(), Some(&("exec" | "run" | "attach"))) && has(args, &stdin)
}
