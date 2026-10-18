//! Differential test of the shell lexer against bash (#461).
//!
//! Every classifier decision rests on the lexer splitting a command line into
//! the words bash would pass each command. This test runs each line under a
//! real bash and compares the argv bash builds for every simple command with
//! the lexer's words, so a divergence becomes a failing case instead of a
//! silent bypass.
//!
//! Nothing runs: bash gets an empty `PATH`, so every command is "not found"
//! and its `command_not_found_handle` records the argv instead. Lines whose
//! words bash would expand (variables, substitutions, globs, braces, `~`),
//! whose commands are builtins or paths, or that redirect outside the scratch
//! directory are skipped, and the test reports how many it checked.
//!
//! Lines: `tests/lexer_vs_bash/lines.txt` and every `shell:` action of the
//! conformance fixtures. It needs bash, so it is ignored by default; CI runs
//! it on Linux:
//!
//! ```text
//! cargo test -p openmoat-core --test lexer_vs_bash -- --ignored
//! ```

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use openmoat_core::lexer::{Operator, Token, Word, lex};
use serde::Deserialize;

/// The argv of each simple command, in a line.
type Commands = Vec<Vec<String>>;

/// How long one line may run under bash.
const LINE_TIMEOUT: Duration = Duration::from_secs(5);

/// Fewer checked lines than this means the filters skip too much to be a test.
const MIN_CHECKED: usize = 100;

/// Records each command's argv as `count\0arg\0…`; `PATH` is empty, so every
/// command lands here. The line itself is `$1`, so it is parsed exactly once.
const PRELUDE: &str = r#"command_not_found_handle() { printf '%s\0' "$#" "$@" >> "$OPENMOAT_ARGV_LOG"; }
eval "$1"
wait"#;

#[test]
#[ignore = "needs bash; CI runs it with --ignored"]
fn the_lexer_splits_words_as_bash_does() {
    // An absolute path: bash itself runs with an empty `PATH`.
    let bash = std::env::var("OPENMOAT_BASH").unwrap_or_else(|_| "/bin/bash".to_owned());
    let probe = vec![vec!["probe".to_owned(), "a b".to_owned()]];
    assert!(
        matches!(under_bash(&bash, "probe 'a b'", &[]), Outcome::Ran(c) if c == probe),
        "{bash} did not report a command to its command_not_found_handle; \
         the test needs bash 4.0 or newer (set OPENMOAT_BASH)"
    );
    let skip_programs = bash_builtins(&bash);
    let mut checked = 0;
    let mut skipped = 0;
    let mut report = String::new();
    let mut divergent = Vec::new();
    for line in lines() {
        let Some(expected) = lexed(&line, &skip_programs) else {
            skipped += 1;
            continue;
        };
        match under_bash(&bash, &line, &expected.files) {
            // Bash refused the line before running anything: nothing to compare,
            // and nothing an agent could run past the classifier.
            Outcome::Rejected => skipped += 1,
            Outcome::Ran(actual) if actual == sorted(expected.commands.clone()) => checked += 1,
            outcome => {
                checked += 1;
                write_divergence(&mut report, &line, &expected.commands, &outcome);
                divergent.push(line);
            }
        }
    }
    eprintln!("lexer vs bash: {checked} lines checked, {skipped} skipped");
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        // Annotations show on the run without reading its log; Actions keeps
        // the first ten errors of a step.
        println!("::notice title=lexer vs bash::{checked} lines checked, {skipped} skipped");
        for line in divergent.iter().take(10) {
            let quoted = serde_json::to_string(line).unwrap();
            println!("::error title=lexer and bash disagree::{quoted}");
        }
    }
    assert!(report.is_empty(), "the lexer and bash disagree:\n{report}");
    assert!(
        checked >= MIN_CHECKED,
        "only {checked} lines were checked ({skipped} skipped); the filters skip too much"
    );
}

/// The test's own lines, then every conformance `shell:` action.
fn lines() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let own = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lexer_vs_bash/lines.txt"),
    )
    .unwrap();
    let mut out: Vec<String> = own
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("# "))
        .map(str::to_owned)
        .collect();
    out.extend(conformance_lines(&root.join("tests/conformance")));
    out
}

#[derive(Deserialize)]
struct Fixture {
    action: FixtureAction,
}

#[derive(Deserialize)]
struct FixtureAction {
    shell: Option<String>,
}

fn conformance_lines(dir: &Path) -> Vec<String> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|f| {
            let fixtures: Vec<Fixture> =
                serde_saphyr::from_str(&fs::read_to_string(f).unwrap()).unwrap();
            fixtures.into_iter().filter_map(|x| x.action.shell)
        })
        .collect()
}

/// Bash's builtins and reserved words: they run inside bash instead of
/// reaching the handler, so a line that uses one is skipped.
fn bash_builtins(bash: &str) -> BTreeSet<String> {
    let out = Command::new(bash)
        .args(["--norc", "--noprofile", "-c", "compgen -b; compgen -k"])
        .env_clear()
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "compgen failed");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What the lexer makes of a line.
struct Lexed {
    commands: Commands,
    /// Files the line redirects from or to. They exist before bash runs it:
    /// a missing one makes bash skip the command, which is no word split.
    files: Vec<String>,
}

/// The lexer's view of `line`, or `None` when bash would expand or run
/// something the comparison cannot see.
fn lexed(line: &str, skip_programs: &BTreeSet<String>) -> Option<Lexed> {
    let tokens = lex(line).ok()?;
    let mut commands = Vec::new();
    let mut files = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut redirect: Option<Operator> = None;
    for token in tokens {
        match token {
            Token::Word(word) => {
                if !plain(&word) {
                    return None;
                }
                match redirect.take() {
                    // Here-string data is stdin, and a duplicated descriptor
                    // is a number: neither names a file.
                    Some(Operator::HereString | Operator::DuplicateDescriptor) => {}
                    Some(_) if !scratch_path(&word.text) => return None,
                    Some(_) => files.push(word.text),
                    None => current.push(word.text),
                }
            }
            // `a || b`: the handler succeeds, so bash never runs `b`.
            Token::Operator(Operator::Or) => return None,
            Token::Operator(op) if op.is_redirect() => redirect = Some(op),
            Token::Operator(_) => commands.extend(finish(&mut current)),
            Token::HereDoc { body, literal } => {
                if !literal && !plain(&body) {
                    return None;
                }
            }
        }
    }
    commands.extend(finish(&mut current));
    let runs_elsewhere = |argv: &Vec<String>| {
        let program = &argv[0];
        skip_programs.contains(program) || program.contains('/') || program.contains('=')
    };
    (!commands.is_empty() && !commands.iter().any(runs_elsewhere))
        .then_some(Lexed { commands, files })
}

fn finish(current: &mut Vec<String>) -> Option<Vec<String>> {
    (!current.is_empty()).then(|| std::mem::take(current))
}

/// A word bash passes on as the lexer spells it: no substitution, glob,
/// expandable `$`, unquoted brace or tilde.
fn plain(word: &Word) -> bool {
    let in_ranges =
        |ranges: &[std::ops::Range<usize>], i: usize| ranges.iter().any(|r| r.contains(&i));
    word.substitutions.is_empty()
        && !word.glob
        && word.text.char_indices().all(|(i, c)| match c {
            '$' => in_ranges(&word.literal, i),
            '{' | '}' | '~' => !in_ranges(&word.unquoted, i),
            _ => true,
        })
}

/// A redirect target inside the scratch directory bash runs in.
fn scratch_path(target: &str) -> bool {
    !target.is_empty() && !target.starts_with('/') && !target.split('/').any(|part| part == "..")
}

/// What bash did with a line.
#[derive(Debug)]
enum Outcome {
    /// The commands it ran, sorted: a pipeline's commands run at the same
    /// time, so the order they reach the handler is not fixed.
    Ran(Commands),
    /// A syntax error before any command ran.
    Rejected,
    /// The run itself went wrong (timeout, unreadable log).
    Failed(String),
}

/// Run `line` in a fresh scratch directory holding `files` (empty), each a
/// path [`scratch_path`] accepted.
fn under_bash(bash: &str, line: &str, files: &[String]) -> Outcome {
    let scratch = tempfile::tempdir().unwrap();
    let empty_path = scratch.path().join("bin");
    let cwd = scratch.path().join("work");
    fs::create_dir(&empty_path).unwrap();
    fs::create_dir(&cwd).unwrap();
    for file in files {
        let path = cwd.join(file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // A target such as `.` or `dir/` is a directory already.
        if !path.is_dir() {
            fs::File::create(&path).unwrap();
        }
    }
    let log = scratch.path().join("argv");
    // A file, not a pipe: nothing reads a pipe while bash runs, so a full one
    // would stall it.
    let errors = scratch.path().join("stderr");
    let mut child = Command::new(bash)
        .args(["--norc", "--noprofile", "-c", PRELUDE, "bash", line])
        .env_clear()
        .env("PATH", &empty_path)
        .env("HOME", &cwd)
        .env("LC_ALL", "C")
        .env("OPENMOAT_ARGV_LOG", &log)
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&errors).unwrap())
        .spawn()
        .expect("bash runs");
    let deadline = Instant::now() + LINE_TIMEOUT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            return Outcome::Failed(format!("timed out after {LINE_TIMEOUT:?}"));
        }
        thread::sleep(Duration::from_millis(5));
    }
    let stderr = fs::read_to_string(&errors).unwrap_or_default();
    let recorded = fs::read(&log).unwrap_or_default();
    if recorded.is_empty() && stderr.contains("syntax error") {
        return Outcome::Rejected;
    }
    match parse_log(&recorded) {
        Ok(commands) => Outcome::Ran(sorted(commands)),
        Err(why) => Outcome::Failed(why),
    }
}

fn parse_log(bytes: &[u8]) -> Result<Commands, String> {
    let mut fields = bytes
        .split(|b| *b == 0)
        .map(|f| String::from_utf8_lossy(f).into_owned());
    let mut commands = Vec::new();
    while let Some(count) = fields.next().filter(|f| !f.is_empty()) {
        let n: usize = count.parse().map_err(|_| format!("bad count {count:?}"))?;
        let argv: Vec<String> = fields.by_ref().take(n).collect();
        if argv.len() != n {
            return Err("truncated log".to_owned());
        }
        commands.push(argv);
    }
    Ok(commands)
}

fn sorted(mut commands: Commands) -> Commands {
    commands.sort();
    commands
}

fn write_divergence(report: &mut String, line: &str, lexer: &Commands, bash: &Outcome) {
    let quoted = serde_json::to_string(line).unwrap();
    let _ = writeln!(report, "line:  {quoted}");
    let _ = writeln!(report, "lexer: {lexer:?}");
    let _ = match bash {
        Outcome::Ran(commands) => writeln!(report, "bash:  {commands:?}"),
        Outcome::Rejected => writeln!(report, "bash:  syntax error"),
        Outcome::Failed(why) => writeln!(report, "bash:  {why}"),
    };
    let _ = writeln!(
        report,
        "fixture:\n- id: lexer-bash-TODO\n  action: {{ shell: {quoted} }}\n  expect: {{ verdict: ask }}\n"
    );
}
