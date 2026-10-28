//! Which words of an interpreter's command line name a file it runs as code:
//! the program operand (`python3 -u x.py`), a file it loads before it (`node
//! -r ./setup.js x.js`), a file option (`pwsh -File x.ps1`, `php -f x.php`), or a
//! module of the working directory (`python -m tool`). Options are read the
//! way each interpreter reads them, so an option's value is never taken for
//! the program (`python -W ignore x.py`, `node --env-file .env x.js`).
//!
//! Inline code (`-c`, `-e`) runs no file; it is scanned as text
//! (`commands/payload.rs`). The shells' own options are `invocation.rs`'s.

mod grammars;

use grammars::{
    BUN, Cluster, DENO_RUN, DENO_SUBCOMMANDS, GO_RUN_VALUES, Grammar, LUA, NODE, OSASCRIPT, PERL,
    PHP, PWSH, PYTHON, RSCRIPT, RUBY, TS_NODE, TSX,
};

/// What an interpreter's command line runs from files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Program<'a> {
    /// Words naming files run as code, in order.
    pub files: Vec<&'a str>,
    /// `python -m <module>`: a module, which may be a file of the working directory.
    pub module: Option<&'a str>,
    /// Neither a file nor inline code: the program is read from stdin (`python3 < x.py`).
    pub stdin: bool,
}

/// Extensions of program files, for an operand that has to look like one.
pub(super) const SCRIPT_EXTENSIONS: &[&str] = &[
    "py",
    "pyw",
    "js",
    "mjs",
    "cjs",
    "ts",
    "mts",
    "cts",
    "tsx",
    "jsx",
    "rb",
    "pl",
    "pm",
    "php",
    "sh",
    "bash",
    "zsh",
    "ksh",
    "fish",
    "ps1",
    "lua",
    "r",
    "go",
    "scpt",
    "applescript",
];

/// The files `program` (an interpreter's base name) runs given `args`, its
/// arguments; `None` when `program` is not an interpreter this module knows.
pub(super) fn program<'a>(program: &str, args: &'a [String]) -> Option<Program<'a>> {
    let grammar = match base(program) {
        "python" | "python3" | "python2" | "pypy" | "pypy3" => &PYTHON,
        "perl" => &PERL,
        "ruby" => &RUBY,
        "node" | "nodejs" => &NODE,
        "php" => &PHP,
        "pwsh" | "powershell" => &PWSH,
        "tsx" => return Some(scan(&TSX, skip(args, &["watch"]))),
        "ts-node" | "ts-node-esm" | "ts-node-script" | "ts-node-transpile-only" => &TS_NODE,
        "lua" | "luajit" => &LUA,
        "Rscript" => &RSCRIPT,
        "osascript" => &OSASCRIPT,
        "deno" => return Some(deno(args)),
        "bun" => return Some(scan(&BUN, skip(args, &["run"]))),
        "go" => return Some(go_run(args)),
        _ => return None,
    };
    Some(scan(grammar, args))
}

/// `program` without a version (`python3.12` is `python3`, `ruby3.3` is
/// `ruby`, `python2.7` is `python2`), as `tables::inline_flags` reads it.
fn base(program: &str) -> &str {
    let trimmed = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if trimmed.len() == program.len() {
        return program;
    }
    match trimmed {
        "python" => {
            let version = &program[trimmed.len()..];
            if version.starts_with('2') {
                "python2"
            } else {
                "python3"
            }
        }
        other => other,
    }
}

/// `args` without a leading subcommand in `words` (`bun run x.ts`, `tsx watch x.ts`).
fn skip<'a>(args: &'a [String], words: &[&str]) -> &'a [String] {
    match args.first() {
        Some(first) if words.contains(&first.as_str()) => &args[1..],
        _ => args,
    }
}

/// `deno run [options] FILE`, `deno serve FILE`, and Deno 2's `deno FILE`.
fn deno(args: &[String]) -> Program<'_> {
    match args.first().map(String::as_str) {
        Some("run" | "serve") => scan(&DENO_RUN, &args[1..]),
        Some(first) if !first.starts_with('-') && !DENO_SUBCOMMANDS.contains(&first) => {
            scan(&DENO_RUN, args)
        }
        _ => Program::default(),
    }
}

/// `go run [build flags] a.go b.go [arguments]`: the `.go` files named first.
/// A package (`go run .`, `go run ./cmd/x`) is built from the project like
/// `go build`, which runs the project's code by design, so it names no file.
fn go_run(args: &[String]) -> Program<'_> {
    let mut program = Program::default();
    let Some(("run", rest)) = args.split_first().map(|(f, r)| (f.as_str(), r)) else {
        return program;
    };
    let mut i = 0;
    while let Some(arg) = rest.get(i) {
        let flag = arg
            .strip_prefix('-')
            .map(|f| format!("-{}", f.trim_start_matches('-')));
        match flag {
            Some(flag) if !flag.contains('=') && GO_RUN_VALUES.contains(&flag.as_str()) => i += 2,
            Some(_) => i += 1,
            None => break,
        }
    }
    for arg in rest.get(i..).unwrap_or_default() {
        let go = std::path::Path::new(arg)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("go"));
        if !go {
            break;
        }
        program.files.push(arg);
    }
    program
}

/// Read `args` by `grammar`: options until the first operand, which is the
/// program file; `--` ends the options and `-` reads the program from stdin.
fn scan<'a>(grammar: &Grammar, args: &'a [String]) -> Program<'a> {
    let mut program = Program::default();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        i += 1;
        let option = if grammar.any_case {
            arg.to_ascii_lowercase()
        } else {
            arg.clone()
        };
        let named = |list: &[&str]| list.contains(&option.as_str());
        if option == "--" {
            program.files.extend(args.get(i).map(String::as_str));
            return program;
        }
        if option == "-" {
            program.stdin = true;
            return program;
        }
        if !option.starts_with('-') {
            if !grammar.file_like_only || file_like(arg) {
                program.files.push(arg);
            }
            return program;
        }
        if named(grammar.file_options) {
            program.files.extend(args.get(i).map(String::as_str));
            return program;
        }
        if let Some((name, value)) = arg.split_once('=')
            && name.starts_with("--")
        {
            if grammar.preloads.contains(&name) {
                program.files.push(value);
            }
            if grammar.no_file.contains(&name) {
                return program;
            }
            continue;
        }
        if named(grammar.no_file) {
            return program;
        }
        if named(grammar.preloads) {
            program.files.extend(args.get(i).map(String::as_str));
            i += 1;
            continue;
        }
        if named(grammar.values) {
            i += 1;
            continue;
        }
        if let Some(cluster) = grammar.cluster
            && !arg.starts_with("--")
        {
            match letters(cluster, arg, args.get(i).map(String::as_str), &mut program) {
                Letters::Options => {}
                Letters::TookNext => i += 1,
                Letters::NoFile => return program,
            }
        }
    }
    program.stdin = program.module.is_none();
    program
}

/// What reading one cluster of one-letter options found.
enum Letters {
    /// Options only; the next word is read as usual.
    Options,
    /// The last letter took the next word as its value.
    TookNext,
    /// A letter after which no program file runs.
    NoFile,
}

/// Read the cluster `arg` (`-uBW`), with `next` the word after it.
fn letters<'a>(
    cluster: Cluster,
    arg: &'a str,
    next: Option<&'a str>,
    program: &mut Program<'a>,
) -> Letters {
    let body = &arg[1..];
    for (at, letter) in body.char_indices() {
        let rest = &body[at + letter.len_utf8()..];
        let module = cluster.module == Some(letter);
        if cluster.no_file.contains(letter) {
            return Letters::NoFile;
        }
        if module || cluster.value.contains(letter) {
            let (value, took) = if rest.is_empty() {
                (next, true)
            } else {
                (Some(rest), false)
            };
            if module {
                program.module = value;
                return Letters::NoFile;
            }
            if cluster.preload.contains(letter) {
                program.files.extend(value.filter(|v| file_like(v)));
            }
            return if took {
                Letters::TookNext
            } else {
                Letters::Options
            };
        }
        if cluster.glued.contains(letter) {
            return Letters::Options;
        }
    }
    Letters::Options
}

/// Whether `word` looks like a file rather than a name: it has a directory
/// or a program file's extension.
pub(super) fn file_like(word: &str) -> bool {
    word.contains('/')
        || word
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && has_script_extension(ext))
}

fn has_script_extension(ext: &str) -> bool {
    SCRIPT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
}
