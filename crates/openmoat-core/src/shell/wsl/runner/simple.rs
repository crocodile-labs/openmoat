//! The allow-list a runner line must pass to be read at all (ADR-083).
//!
//! Chasing the constructs that compute a program (`$t::Start(…)`,
//! `([type]'…')::Start`, `$ExecutionContext.InvokeCommand…`,
//! `(New-Object -ComObject …).Run(…)`) one by one does not end, so the
//! rule is inverted: a line is read only when every part of it is simple,
//! and anything else makes it opaque, which the `opaque-code` rule holds for
//! review.
//!
//! - PowerShell: bare words, options (`-Name`, `-Name:value`), paths,
//!   single-quoted strings, double-quoted strings without `$` or a backquote,
//!   and the separators `;`, `|`, `&&`, `||`, a line break and redirects.
//!   Anything else is not simple: `$`, parentheses, brackets, braces, `@`, a
//!   backquote, `::`, a lone `&` or `.` (the call operators), the operators
//!   `-join`, `-replace`, `-split` (and their `c`/`i` forms), `-f` after a
//!   quoted string, `New-Object`, `Add-Type`, `iex`, `Invoke-Expression`.
//! - `cmd`: no `^`, `%` or `!` anywhere (escapes and variables), no
//!   parenthesis outside double quotes (blocks), no `for` and no `call`.

/// PowerShell words that build or run code from text.
const POWERSHELL_FORBIDDEN: &[&str] = &[
    "-join",
    "-replace",
    "-creplace",
    "-ireplace",
    "-split",
    "-csplit",
    "-isplit",
    "new-object",
    "add-type",
    "iex",
    "invoke-expression",
];

/// Whether `line`, read as PowerShell, is simple.
pub(super) fn powershell(line: &str) -> bool {
    let mut words: Vec<Word> = Vec::new();
    let mut word = Word::default();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') if c == '\'' => quote = None,
            Some('\'') => word.text.push(c),
            Some(_) if c == '"' => quote = None,
            Some(_) if c == '$' || c == '`' => return false,
            Some(_) => word.text.push(c),
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    word.quoted = true;
                }
                '$' | '(' | ')' | '[' | ']' | '{' | '}' | '`' | '@' => return false,
                ':' if chars.peek() == Some(&':') => return false,
                '&' if chars.peek() != Some(&'&') => return false,
                '&' => {
                    chars.next();
                    end(&mut words, &mut word, true);
                }
                '|' | ';' | '\n' => end(&mut words, &mut word, true),
                c if c.is_whitespace() => end(&mut words, &mut word, false),
                c => word.text.push(c),
            },
        }
    }
    if quote.is_some() {
        return false;
    }
    end(&mut words, &mut word, false);
    let mut after_string = false;
    for word in &words {
        let lower = word.text.to_ascii_lowercase();
        let bare = !word.quoted;
        let forbidden = bare && POWERSHELL_FORBIDDEN.contains(&lower.as_str());
        // `.` first in a segment is the call operator (`. ./x.ps1`), not a path
        let call = bare && word.first && lower == ".";
        // `'{0}' -f $x` formats a string; `-f` after anything else is an option
        let format = bare && lower == "-f" && after_string;
        if forbidden || call || format {
            return false;
        }
        after_string = word.quoted;
    }
    true
}

/// A word of a PowerShell line.
#[derive(Default)]
struct Word {
    text: String,
    /// It was written in quotes.
    quoted: bool,
    /// It is the first word of its segment.
    first: bool,
}

/// End the word being read, if any. A separator is kept as an empty, unquoted word, which marks the next word
/// as the first of its segment.
fn end(words: &mut Vec<Word>, word: &mut Word, separator: bool) {
    if !word.text.is_empty() || word.quoted {
        let mut done = std::mem::take(word);
        done.first = words.last().is_none_or(|w| w.text.is_empty() && !w.quoted);
        words.push(done);
    }
    if separator {
        words.push(Word::default());
    }
}

/// Whether `line`, read as `cmd`, is simple.
pub(super) fn cmd(line: &str) -> bool {
    let mut in_quote = false;
    for c in line.chars() {
        match c {
            '"' => in_quote = !in_quote,
            '^' | '%' | '!' => return false,
            '(' | ')' if !in_quote => return false,
            _ => {}
        }
    }
    !line
        .split(|c: char| c.is_whitespace() || "&|<>\"".contains(c))
        .any(|word| word.eq_ignore_ascii_case("for") || word.eq_ignore_ascii_case("call"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_powershell_lines() {
        for line in [
            "-NoProfile -Command Get-ChildItem *.log",
            r".\build.ps1 -Configuration:Release",
            "git status; git log -1 | Select-Object -First 1 && echo done",
            "Write-Output 'a $b (c) [d]' \"plain\" > out.txt",
            "Get-ChildItem Env:HOME",
            "docker build -f Dockerfile .",
        ] {
            assert!(powershell(line), "{line}");
        }
    }

    #[test]
    fn powershell_beyond_simple_commands() {
        for line in [
            "$t=[Diagnostics.Process]; $t::Start((-join('w','sl')),'-e id')",
            "([type]'Diagnostics.Process')::Start((-join('w','sl')),'-e id')",
            "$ExecutionContext.InvokeCommand.InvokeScript(-join('w','sl',' -e id'))",
            "(New-Object -ComObject WScript.Shell).Run((-join('w','sl')))",
            "[math]::Round(1.5)",
            "echo \"$env:PATH\"",
            "& wsl",
            ". ./x.ps1",
            "gci | ? { $_ }",
            "'w','sl' -join ''",
            "'{0}sl' -f 'w'",
            "New-Object Net.WebClient",
            "echo `$x",
            "echo @args",
            "echo 'unterminated",
        ] {
            assert!(!powershell(line), "{line}");
        }
    }

    #[test]
    fn simple_cmd_lines() {
        for line in [
            "/c docker run ubuntu",
            "/c build.cmd",
            "/c gradlew.bat build",
            "/c \"echo done> out.txt\"",
            "/c echo \"(not a block)\"",
        ] {
            assert!(cmd(line), "{line}");
        }
        for line in [
            "/c echo %PATH% > out.txt",
            "/c w^sl",
            "/v:on /c echo !x!",
            "/c (echo a) & echo b",
            "/c for /f %i in ('x') do echo %i",
            "/c call x.bat",
        ] {
            assert!(!cmd(line), "{line}");
        }
    }
}
