//! From PowerShell statements to the POSIX line that does the same
//! (`powershell.rs`), statement by statement and pipeline element by element.
//!
//! Words become POSIX words with the same text: literal text single-quoted
//! (unquoted when it has no character a POSIX shell treats specially, so a
//! host or a glob reads as it does in a POSIX line), a leading unquoted `~` kept
//! as the home folder, `$HOME`, `$env:USERPROFILE` and `$env:HOME` as `$HOME`,
//! `$PWD` as `$PWD`, `$env:NAME` as `${NAME}`, and any other variable as a
//! POSIX variable `ps_<name>`, which a `$name = 'text'` earlier on the line
//! sets (`ps_name='text'`) and which is otherwise not known.

mod cmdlet;

use super::cmdlets::{self, Cmdlet, Does};
use super::lex::{Part, PsWord, Tok};
use crate::action::AtomicAction;
use crate::paths;
use crate::shell::{ClassifyError, ShellContext, Sink};
use cmdlet::cmdlet_line;

/// A string as one single-quoted POSIX word.
pub(super) fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Text a POSIX shell reads as written, unquoted.
fn plain(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('~')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:@%+=,-*?".contains(c))
}

/// `word` as a POSIX word with the same text.
pub(super) fn posix(word: &PsWord) -> String {
    let mut out = String::new();
    for (i, part) in word.parts.iter().enumerate() {
        match part {
            Part::Lit(text) if i == 0 && word.tilde && text.starts_with('~') => {
                let rest = &text[1..];
                if rest.is_empty() || rest.starts_with(['/', '\\']) {
                    out.push_str("~/");
                    let rest = rest.get(1..).unwrap_or("");
                    if !rest.is_empty() {
                        out.push_str(&literal(rest));
                    }
                } else {
                    out.push_str(&quote(&text.replace('\\', "/")));
                }
            }
            Part::Lit(text) => out.push_str(&literal(text)),
            Part::Env(name) if matches!(name.as_str(), "USERPROFILE" | "HOME") => {
                out.push_str("\"$HOME\"");
            }
            Part::Env(name) if is_name(name) => {
                out.push_str("\"${");
                out.push_str(name);
                out.push_str("}\"");
            }
            Part::Var(name) => out.push_str(&variable(name)),
            Part::Env(_) | Part::Sub(_) => out.push_str("\"${ps_unknown}\""),
        }
    }
    if out.is_empty() { "''".to_owned() } else { out }
}

/// Literal text as a POSIX word. `\` is no escape in PowerShell but Windows'
/// path separator, written as `/`, the form paths are matched in
/// (`C:\Users\me\.ssh` is `C:/Users/me/.ssh`).
fn literal(text: &str) -> String {
    let text = text.replace('\\', "/");
    if plain(&text) { text } else { quote(&text) }
}

fn is_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A PowerShell variable as POSIX text.
fn variable(name: &str) -> String {
    match name {
        "home" => "\"$HOME\"".to_owned(),
        "pwd" => "\"$PWD\"".to_owned(),
        "true" => "True".to_owned(),
        "false" => "False".to_owned(),
        "null" => "''".to_owned(),
        n if is_name(n) => format!("\"${{ps_{n}}}\""),
        _ => "\"${ps_unknown}\"".to_owned(),
    }
}

/// What `-Command`, `-EncodedCommand` or nothing a PowerShell command line runs.
pub(super) enum Cli {
    Command(String),
    Encoded(String),
    Nothing,
}

/// PowerShell's own options that take a value (`-ExecutionPolicy Bypass`).
const CLI_VALUES: &[&str] = &[
    "executionpolicy",
    "ep",
    "windowstyle",
    "inputformat",
    "outputformat",
    "version",
    "configurationname",
    "workingdirectory",
    "wd",
    "psconsolefile",
    "settingsfile",
    "custompipename",
];

/// The line `powershell`/`pwsh` runs from its arguments.
pub(super) fn cli_command(args: &[String]) -> Cli {
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let Some(option) = arg.strip_prefix(['-', '/']) else {
            // the first operand starts the command, the rest are its words
            return Cli::Command(args[i..].join(" "));
        };
        let lower = option.to_ascii_lowercase();
        let (name, glued) = lower
            .split_once(':')
            .map_or((lower.as_str(), None), |(n, v)| (n, Some(v)));
        if crate::obfuscation::is_encoded_command(name) {
            return glued
                .map(str::to_owned)
                .or_else(|| args.get(i + 1).cloned())
                .map_or(Cli::Nothing, Cli::Encoded);
        }
        if name == "c" || (name.len() >= 2 && "command".starts_with(name)) {
            return match args.get(i + 1..) {
                Some(rest) if !rest.is_empty() && rest[0] != "-" => Cli::Command(rest.join(" ")),
                _ => Cli::Nothing,
            };
        }
        if name == "f" || (name.len() >= 2 && "file".starts_with(name)) {
            return Cli::Nothing;
        }
        if CLI_VALUES
            .iter()
            .any(|v| *v == name || (name.len() >= 2 && v.starts_with(name)))
            && glued.is_none()
        {
            i += 1;
        }
        i += 1;
    }
    Cli::Nothing
}

/// Whether every evaluator in `tokens` reads only its piped input (`iwr x | iex`).
pub(super) fn evaluates_piped_input_only(tokens: &[Tok]) -> bool {
    let mut seen = false;
    for (i, tok) in tokens.iter().enumerate() {
        let Tok::Word(w) = tok else { continue };
        let Some(lit) = w.literal() else { continue };
        let lower = lit.to_ascii_lowercase();
        if !super::EVALUATORS.contains(&lower.as_str()) {
            continue;
        }
        let after_pipe = i > 0 && tokens[i - 1] == Tok::Pipe;
        let alone = !matches!(tokens.get(i + 1), Some(Tok::Word(_)));
        if !(after_pipe && alone && matches!(lower.as_str(), "iex" | "invoke-expression")) {
            return false;
        }
        seen = true;
    }
    seen
}

/// The POSIX line for `tokens`; what it cannot read is noted in `sink`.
pub(super) fn translate(
    tokens: &[Tok],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<String, ClassifyError> {
    let mut out = String::new();
    let mut start = 0;
    for (i, tok) in tokens
        .iter()
        .enumerate()
        .chain([(tokens.len(), &Tok::End(";"))])
    {
        let Tok::End(sep) = tok else { continue };
        let statement = &tokens[start..i.min(tokens.len())];
        start = i + 1;
        if statement.is_empty() {
            continue;
        }
        if let Some(line) = translate_statement(statement, ctx, sink, depth)? {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&line);
            out.push_str(if *sep == ";" { ";" } else { sep });
        }
    }
    Ok(out.trim_end_matches([';', '&', '|']).to_owned())
}

fn translate_statement(
    statement: &[Tok],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<Option<String>, ClassifyError> {
    if statement.iter().any(|t| matches!(t, Tok::Complex(_))) {
        unread(statement, ctx, sink)?;
        return Ok(None);
    }
    // `$x = …`, `$env:X = …`
    if let [Tok::Word(target), Tok::Assign, rest @ ..] = statement {
        let name = match target.parts.as_slice() {
            [Part::Var(n)] if is_name(n) => format!("ps_{n}"),
            [Part::Env(n)] if is_name(n) => format!("export {n}"),
            _ => {
                unread(statement, ctx, sink)?;
                return Ok(None);
            }
        };
        let value = match rest {
            [Tok::Word(w)] => posix(w),
            _ => match pipeline(rest, ctx, sink, depth)? {
                Some(line) => format!("\"$({line})\""),
                None => return Ok(None),
            },
        };
        return Ok(Some(format!("{name}={value}")));
    }
    if statement.iter().any(|t| matches!(t, Tok::Assign)) {
        unread(statement, ctx, sink)?;
        return Ok(None);
    }
    pipeline(statement, ctx, sink, depth)
}

fn pipeline(
    tokens: &[Tok],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<Option<String>, ClassifyError> {
    let mut stages = Vec::new();
    for element in tokens.split(|t| *t == Tok::Pipe) {
        match element_line(element, ctx, sink, depth)? {
            Some(line) => stages.push(line),
            None => return Ok(None),
        }
    }
    Ok(Some(stages.join(" | ")))
}

/// Note `tokens` as not read, and still read the literal paths and the
/// `$env:` variables they name.
fn unread(tokens: &[Tok], ctx: &ShellContext<'_>, sink: &mut Sink) -> Result<(), ClassifyError> {
    let mut shown = Vec::new();
    for tok in tokens {
        let Tok::Word(w) = tok else { continue };
        shown.push(w.display());
        for part in &w.parts {
            if let Part::Env(name) = part {
                sink.push(AtomicAction::EnvRead { name: name.clone() })?;
            }
        }
        if let Some(lit) = w.literal().map(|l| l.replace('\\', "/"))
            && paths::looks_like_path(&lit)
        {
            let word = if w.tilde {
                lit.replacen('~', ctx.home, 1)
            } else {
                lit
            };
            sink.read(ctx, &word)?;
        }
    }
    sink.skip(ClassifyError::PowerShell(shown.join(" ")));
    Ok(())
}

/// One pipeline element as a POSIX command; `None` when it is not read.
fn element_line(
    element: &[Tok],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<Option<String>, ClassifyError> {
    let mut words: Vec<&PsWord> = Vec::new();
    let mut redirects = Vec::new();
    let mut iter = element.iter().peekable();
    let called = matches!(iter.peek(), Some(Tok::Call));
    if called {
        iter.next();
    }
    while let Some(tok) = iter.next() {
        match tok {
            Tok::Word(w) => words.push(w),
            Tok::Redirect("dup") => {}
            Tok::Redirect(op) => {
                let Some(Tok::Word(target)) = iter.next() else {
                    unread(element, ctx, sink)?;
                    return Ok(None);
                };
                redirects.push(redirect(op, target));
            }
            _ => {
                unread(element, ctx, sink)?;
                return Ok(None);
            }
        }
    }
    let Some((first, args)) = words.split_first() else {
        return Ok(Some(format!(": {}", redirects.join(" "))));
    };
    let Some(program) = first.literal() else {
        // `& $tool args`, `$cmd`: the program is computed
        super::opaque(sink)?;
        unread(element, ctx, sink)?;
        return Ok(None);
    };
    let mut line = if program == "." && !called {
        args.first()
            .map_or_else(String::new, |p| format!(". {}", posix(p)))
    } else if let Some(cmdlet) = cmdlets::find(&program).filter(|c| !external(c, &program, args)) {
        match cmdlet_line(cmdlet, &program, args, ctx, sink, depth)? {
            Some(line) => line,
            None => return Ok(None),
        }
    } else {
        std::iter::once(program_word(&program))
            .chain(args.iter().map(|w| posix(w)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    for r in redirects {
        line.push(' ');
        line.push_str(&r);
    }
    Ok(Some(line))
}

/// `curl -sS URL` in PowerShell 7 is `curl.exe`: options of its own mean the program.
fn external(cmdlet: &Cmdlet, program: &str, args: &[&PsWord]) -> bool {
    cmdlet.does == Does::Fetch
        && matches!(program.to_ascii_lowercase().as_str(), "curl" | "wget")
        && args.iter().filter_map(|w| w.literal()).any(|a| {
            a.starts_with("--") || (a.len() == 2 && a.starts_with('-')) || a.starts_with("-s")
        })
}

/// An external program's name as POSIX rules name it: a bare name in lower
/// case without `.exe`; a path as written.
fn program_word(program: &str) -> String {
    if program.contains(['/', '\\']) {
        return literal(program);
    }
    let lower = program.to_ascii_lowercase();
    literal(lower.strip_suffix(".exe").unwrap_or(&lower))
}

fn redirect(op: &str, target: &PsWord) -> String {
    let to = match target.parts.as_slice() {
        [Part::Var(n)] if n == "null" => "/dev/null".to_owned(),
        _ => posix(target),
    };
    format!("{} {to}", if op == ">>" { ">>" } else { ">" })
}
