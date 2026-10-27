//! Environment reads that use none of the bases `environ.rs` looks for:
//! Python reaching `os.environ` through `getattr(os, 'environ')`, `vars(os)` or
//! `os.__dict__` (`__import__("os").__dict__` too), or running `env` or `printenv` as a child (`os.popen('env')`,
//! `subprocess.run(['printenv', 'X'])`); PowerShell's
//! `[Environment]::GetEnvironmentVariable('X')` and `GetEnvironmentVariables()`,
//! its `Env:` drive (`Get-ChildItem Env:`, `gci env:X`) and `$env:X` in any
//! letter case, since PowerShell ignores case.

use super::{Access, IMPORTS_OS, argument, is_ident, literal, member};

/// Python calls that run a command line or an argument list.
const CHILD_CALLS: &[&str] = &[
    "popen",
    "system",
    "run",
    "call",
    "check_output",
    "check_call",
    "Popen",
    "getoutput",
    "getstatusoutput",
];

/// PowerShell commands (and their aliases) that list or read a drive's items.
const DRIVE_READERS: &[&str] = &[
    "get-childitem",
    "gci",
    "ls",
    "dir",
    "get-item",
    "gi",
    "get-content",
    "gc",
    "cat",
    "type",
    "get-itemproperty",
    "gp",
];

/// Add the variables these forms name in `code` to `names`; the expression of
/// the first one that reads the environment whole, if any.
pub(super) fn reads(code: &str, names: &mut Vec<String>) -> Option<&'static str> {
    let mut found = Found { names, whole: None };
    python_object(code, &mut found);
    python_children(code, &mut found);
    powershell(code, &mut found);
    found.whole
}

struct Found<'a> {
    names: &'a mut Vec<String>,
    whole: Option<&'static str>,
}

impl Found<'_> {
    fn name(&mut self, name: &str) {
        if !self.names.iter().any(|n| n == name) {
            self.names.push(name.to_owned());
        }
    }

    fn whole(&mut self, expression: &'static str) {
        self.whole = self.whole.or(Some(expression));
    }

    /// What `access` reads; anything but a named variable counts as all of them.
    fn access(&mut self, access: Access, expression: &'static str) {
        match access {
            Access::Name(name) => self.name(&name),
            Access::Whole | Access::Other => self.whole(expression),
        }
    }
}

/// Every position of `word` in `text` not preceded by an identifier character.
fn calls<'t>(text: &'t str, word: &'t str) -> impl Iterator<Item = usize> + 't {
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |&at| text[..at].chars().next_back().is_none_or(|c| !is_ident(c)))
}

/// `getattr(<module>, 'environ')`, `vars(os)` and `os.__dict__`: the module's
/// attributes, the environment among them.
fn python_object(code: &str, found: &mut Found<'_>) {
    for at in calls(code, "getattr(") {
        let args = &code[at + "getattr(".len()..];
        let Some((_, second)) = args.split_once(',') else {
            continue;
        };
        if let Some((name, rest)) = literal(second)
            && name == "environ"
        {
            let after = rest.trim_start().strip_prefix(')').unwrap_or(rest);
            found.access(member("environ", after), "getattr(os,'environ')");
        }
    }
    for at in calls(code, "vars(") {
        let arg = code[at + "vars(".len()..].trim_start();
        let module = arg
            .strip_prefix("os")
            .is_some_and(|rest| rest.trim_start().starts_with(')') || rest.starts_with('.'))
            || arg.starts_with("__import__(");
        if module {
            found.whole("vars(os)");
        }
    }
    let imported = IMPORTS_OS
        .iter()
        .any(|import| code.contains(&format!("{import}.__dict__")));
    if imported || calls(code, "os.__dict__").next().is_some() {
        found.whole("os.__dict__");
    }
}

/// A quoted string at the start of `text`, of any characters, and the text
/// after it.
fn string(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    let quote = text.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let body = &text[1..];
    let end = body.find(quote)?;
    Some((&body[..end], &body[end + 1..]))
}

/// The command lines a call's first argument holds: a string is split at the
/// shell's separators, a list (`['printenv', 'X']`) is one argument vector in
/// which an element that is not a string is `None`.
fn command_lines(first: &str) -> Vec<Vec<Option<String>>> {
    let first = first.trim_start();
    if let Some(list) = first.strip_prefix(['[', '(']) {
        let mut words = Vec::new();
        let mut rest = list;
        loop {
            let trimmed = rest.trim_start();
            if trimmed.starts_with([']', ')']) || trimmed.is_empty() {
                break;
            }
            if let Some((word, after)) = string(trimmed) {
                words.push(Some(word.to_owned()));
                rest = after;
            } else {
                words.push(None);
                rest = trimmed.trim_start_matches(|c: char| !matches!(c, ',' | ']' | ')'));
            }
            match rest.trim_start().strip_prefix(',') {
                Some(after) => rest = after,
                None => break,
            }
        }
        return vec![words];
    }
    let Some((line, _)) = string(first) else {
        return Vec::new();
    };
    line.split(['|', ';', '&', '\n'])
        .map(|segment| {
            segment
                .split_whitespace()
                .map(|w| Some(w.to_owned()))
                .collect()
        })
        .collect()
}

/// `env` or `printenv` run as a child, which prints every variable or the ones
/// it names.
fn python_children(code: &str, found: &mut Found<'_>) {
    for call in CHILD_CALLS {
        let open = format!("{call}(");
        for (at, _) in code.match_indices(&open) {
            let before = code[..at].chars().next_back();
            if before.is_some_and(is_ident) {
                continue;
            }
            for argv in command_lines(&code[at + open.len()..]) {
                child(&argv, found);
            }
        }
    }
}

fn child(argv: &[Option<String>], found: &mut Found<'_>) {
    let Some(Some(program)) = argv.first() else {
        return;
    };
    let program = program.rsplit('/').next().unwrap_or(program);
    let operands: Vec<&Option<String>> = argv
        .iter()
        .skip(1)
        .filter(|a| !matches!(a.as_deref(), Some("-0" | "--null")))
        .collect();
    match program {
        "env" | "set" | "export" if operands.is_empty() => found.whole("env"),
        "printenv" if operands.is_empty() => found.whole("printenv"),
        "printenv" => {
            for arg in operands {
                match arg.as_deref() {
                    Some(name) if !name.is_empty() && name.chars().all(is_ident) => {
                        found.name(name);
                    }
                    _ => found.whole("printenv"),
                }
            }
        }
        _ => {}
    }
}

/// PowerShell's environment reads, matched in any letter case.
fn powershell(code: &str, found: &mut Found<'_>) {
    // ASCII lowercasing keeps every byte offset, so `lower` indexes `code`.
    let lower = code.to_ascii_lowercase();
    for (at, _) in lower.match_indices("]::getenvironmentvariable") {
        if !lower[..at].ends_with("environment") {
            continue;
        }
        let after = &code[at + "]::getenvironmentvariable".len()..];
        if after.starts_with(['s', 'S']) {
            found.whole("[Environment]::GetEnvironmentVariables()");
        } else if let Some(args) = after.trim_start().strip_prefix('(') {
            found.access(
                argument(args, true),
                "[Environment]::GetEnvironmentVariable()",
            );
        }
    }
    for (at, _) in lower.match_indices("env:") {
        let before = &lower[..at];
        let after = &code[at + "env:".len()..];
        if before.ends_with('$') || before.ends_with("${") {
            let name: String = after.chars().take_while(|c| is_ident(*c)).collect();
            if !name.is_empty() {
                found.name(&name);
            }
        } else if drive_reader(before) {
            let path = after.trim_start_matches(['\\', '/']);
            let name: String = path.chars().take_while(|c| is_ident(*c)).collect();
            let wildcard = path[name.len()..].starts_with('*');
            if name.is_empty() || wildcard {
                found.whole("Env:");
            } else {
                found.name(&name);
            }
        }
    }
}

/// Whether the `Env:` drive path that follows `before` (lowercased) is the
/// operand of a command that reads it (`Get-ChildItem Env:`, `gc -Path 'env:X'`).
fn drive_reader(before: &str) -> bool {
    if before.ends_with(|c: char| is_ident(c) || c == '-' || c == '$' || c == '{') {
        return false;
    }
    let before = before.trim_end_matches(['\'', '"']).trim_end();
    let before = ["-literalpath", "-path"]
        .iter()
        .find_map(|p| before.strip_suffix(p))
        .map_or(before, str::trim_end);
    let word = before
        .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '-')
        .len();
    DRIVE_READERS.contains(&&before[word..])
}
