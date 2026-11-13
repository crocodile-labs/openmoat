//! The lines `cmd`, PowerShell and the programs that launch others run as a
//! command line OpenMoat does not otherwise parse.
//!
//! Each segment (after `&`, `|`, `;`, a parenthesis or a brace) names one
//! program, after the options of whoever runs it: the shell's own
//! (`runner/options.rs`: PowerShell's table, where an option that takes a value
//! skips it and an unknown one makes the line opaque; `cmd`'s `/c`, also
//! glued, `/cwsl`, and Git Bash's `//c`), or a launching program's
//! (`start`, `Start-Process` and its `-FilePath` and `-ArgumentList`,
//! `explorer`, `wt`, `runas`, `conhost`, `Invoke-Item`). So `cmd /c docker
//! run ubuntu` runs `docker`. A bare `bash` or one in the Windows system
//! folders is WSL's: Windows' search finds `System32\bash.exe` first.
//! `cmd` reads only `"` as a quote; a `'` or backquote around a program
//! (`for /f %i in ('wsl ls')`) is dropped.
//!
//! What is built when the line runs cannot be read, so the line is marked
//! opaque: a program word with a `cmd` escape (`^`), a variable (`%x%`,
//! `!x!`), a joined string (`'ws'+'l'`), a PowerShell escape; after a call
//! operator (`&`, `.`) a `$` or a parenthesis; a `$( … )` inside a
//! PowerShell double-quoted string; `iex`, `Invoke-Expression`,
//! `Invoke-Command`, `Get-Command`, `[scriptblock]`; `-EncodedCommand`; a UNC
//! word built the same ways; and every `wt` line. And as a backstop, a line
//! in which `wsl`, `wslg`, `wslconfig` or `bash` stands as a whole word
//! anywhere, quoted or not, is opaque whatever the parse found: parsing these
//! shells exactly keeps losing, so the rule fails toward review.

mod line;
mod options;
mod simple;

use options::{Kind, Opt};

/// Words that keep the program's place open: `call wsl`, `. wsl`.
const PREFIXES: &[&str] = &["call", "."];

/// PowerShell commands that run a string or a looked-up command as code.
const EVALUATORS: &[&str] = &[
    "iex",
    "invoke-expression",
    "icm",
    "invoke-command",
    "gcm",
    "get-command",
];

/// Commands that make a link to a file, whose target may be a launcher.
const LINKERS: &[&str] = &["mklink", "new-item", "ni"];

/// What a runner's line hands on.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Found {
    /// The WSL launchers it runs.
    pub(super) launchers: Vec<String>,
    /// A word names the WSL share.
    pub(super) share: bool,
    /// What it runs cannot all be read.
    pub(super) opaque: bool,
}

/// One token of a line.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    /// `&`: `cmd`'s separator and PowerShell's call operator.
    Call,
    /// `(`, which after a call operator computes the program.
    Open,
    /// `|`, `;`, `)`, braces, a line break.
    Sep,
}

/// Read the line `program` runs from `args`; nothing for another program.
pub(super) fn scan(program: &str, args: &[String]) -> Found {
    let name = super::path::program(program);
    let mut found = Found::default();
    let Some(kind) = Kind::of(&name) else {
        return found;
    };
    let line = args.join(" ");
    found.opaque = name == "wt" || names_launcher(&line);
    let (tokens, subexpression) = tokens(&line, kind.single_quotes());
    found.opaque |= subexpression || line::opaque(&line, kind);
    let mut state = State::new(kind, !kind.single_quotes());
    for token in tokens {
        match token {
            Tok::Word(word) => state.word(&word, &mut found),
            Tok::Call => state.segment(true),
            Tok::Open => {
                // `& (…)`, `saps (…)`: the program is computed
                found.opaque |= state.called || (state.launching() && state.next == Next::Program);
                state.segment(false);
            }
            Tok::Sep => state.segment(false),
        }
    }
    found
}

/// Whether one of [`super::BACKSTOP`]'s names stands as a whole word anywhere
/// in `line`, as Win32 reads a path component (`WSL.EXE.`, `wsl.exe::$DATA`).
fn names_launcher(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || ".~$:_-".contains(c)))
        .map(super::path::program)
        .any(|name| {
            super::BACKSTOP.contains(&name.as_str()) || super::is_short_name(&name, "wslcon")
        })
}

/// What the next word of a segment is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// The segment's program, unless it is an option.
    Program,
    /// An option's value.
    Value,
    /// A launched program's arguments (`-ArgumentList`), until an option.
    Arguments,
    /// The program's own arguments: nothing more to read.
    Done,
}

struct State {
    /// Whose options the next words are.
    kind: Kind,
    /// The line is `cmd`'s, where `'` and a backquote do not quote.
    cmd_line: bool,
    next: Next,
    /// The program's place follows a call operator (`&`, `.`).
    called: bool,
    /// The segment's program makes links: a launcher path is a launcher.
    links: bool,
}

impl State {
    fn new(kind: Kind, cmd_line: bool) -> Self {
        Self {
            kind,
            cmd_line,
            next: Next::Program,
            called: false,
            links: false,
        }
    }

    /// Whether the words are a launching program's, whose program word is
    /// what it starts.
    fn launching(&self) -> bool {
        matches!(self.kind, Kind::Start | Kind::StartProcess | Kind::Launcher)
    }

    /// A new segment starts, after a separator or a call operator.
    fn segment(&mut self, called: bool) {
        *self = Self {
            called,
            ..Self::new(Kind::Plain, self.cmd_line)
        };
    }

    fn word(&mut self, word: &str, found: &mut Found) {
        found.share |= super::names_share(word);
        found.opaque |= built_unc(word) || wildcard_launcher_path(word);
        if self.links {
            found.launchers.extend(super::launcher_path(word));
        }
        match self.next {
            Next::Value => {
                self.next = Next::Program;
                return;
            }
            Next::Done => return,
            Next::Program | Next::Arguments => {}
        }
        match self.kind.option(word) {
            Some(Opt::Flag) => self.next = Next::Program,
            Some(Opt::Value) => self.next = Next::Value,
            Some(Opt::Arguments) => self.next = Next::Arguments,
            Some(Opt::Opaque) => found.opaque = true,
            Some(Opt::Glued(rest)) => self.program(&rest, found),
            None if self.next == Next::Arguments => {}
            None => self.program(word, found),
        }
    }

    fn program(&mut self, word: &str, found: &mut Found) {
        let word = if self.cmd_line {
            word.trim_matches(['\'', '`'])
        } else {
            word
        };
        let program = super::path::program(word);
        if PREFIXES.contains(&word) || PREFIXES.contains(&program.as_str()) {
            self.called |= word == ".";
            return;
        }
        if let Some(launcher) = super::launcher(word) {
            found.launchers.push(launcher);
        } else if program == "bash" && super::path::read(word).parts.len() == 1 {
            found.launchers.push(program.clone());
        }
        // after a call operator or as what a launching program starts, a
        // variable's value is the program; so is a wildcard's match (a script
        // the line writes is `line.rs`'s)
        let computed = (self.called || self.launching()) && word.contains('$');
        let wildcard = word != "?" && word.contains(['*', '?']);
        found.opaque |= computed
            || wildcard
            || built_at_run_time(word)
            || EVALUATORS.contains(&program.as_str())
            || word.to_ascii_lowercase().contains("[scriptblock]");
        *self = Self::new(Kind::Plain, self.cmd_line);
        self.next = Next::Done;
        if let Some(kind) = Kind::of(&program) {
            found.opaque |= program == "wt";
            *self = Self::new(kind, self.cmd_line);
        } else if LINKERS.contains(&program.as_str()) {
            self.links = true;
        }
    }
}

/// A wildcard in a path under `Windows` or the Store WSL's folder
/// (`C:\Windows\System32\ws?.exe`): what it matches is a launcher the
/// literal names of the read deny miss.
fn wildcard_launcher_path(word: &str) -> bool {
    let lower = word.replace('\\', "/").to_ascii_lowercase();
    (lower.contains("windows/") || lower.contains("program files/wsl"))
        && lower.contains(['*', '?'])
}

/// A program word whose text is made when the line runs: a `cmd` escape or
/// variable, a joined string, a PowerShell escape. (A `$x` there runs only
/// after a call operator: `State::called`.)
fn built_at_run_time(word: &str) -> bool {
    word.contains(['^', '%', '!', '+', '`'])
}

/// A UNC word whose text is made when the line runs (`\\ws%x%l$\x`): the
/// share it names cannot be read.
fn built_unc(word: &str) -> bool {
    let unc = word.starts_with("\\\\") || word.starts_with("//");
    unc && (word.contains(['^', '%', '!', '+', '`']) || word.contains("$("))
}

/// The tokens of a line, and whether a PowerShell double-quoted string in it
/// holds a `$( … )`, which runs code. Quotes group words and are dropped;
/// `'` is a quote only where `single_quotes` (PowerShell, not `cmd`).
fn tokens(line: &str, single_quotes: bool) -> (Vec<Tok>, bool) {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut subexpression = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(q) => {
                subexpression |=
                    single_quotes && q == '"' && c == '$' && chars.peek() == Some(&'(');
                word.push(c);
            }
            None => match c {
                '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\'' if single_quotes => {
                    quote = Some(c);
                    in_word = true;
                }
                '&' | '(' | '|' | ';' | ')' | '{' | '}' | '\n' => {
                    flush(&mut word, &mut in_word, &mut out);
                    out.push(match c {
                        '&' => Tok::Call,
                        '(' => Tok::Open,
                        _ => Tok::Sep,
                    });
                }
                c if c.is_whitespace() => flush(&mut word, &mut in_word, &mut out),
                c => {
                    word.push(c);
                    in_word = true;
                }
            },
        }
    }
    flush(&mut word, &mut in_word, &mut out);
    (out, subexpression)
}

/// End the word being read, if it holds text.
fn flush(word: &mut String, in_word: &mut bool, out: &mut Vec<Tok>) {
    if *in_word && !word.is_empty() {
        out.push(Tok::Word(std::mem::take(word)));
    }
    word.clear();
    *in_word = false;
}
