//! The signals of a POSIX shell line.
//!
//! One pass over the line keeps the quoting state (none, `'…'`, `"…"`,
//! `$'…'`) and notes where a command's first word starts; the signals that
//! need neither are read from the text.

use super::Assessment;

/// Escapes of printable ASCII (`\x63` for `c`) that make a line obfuscated.
/// Only those count: a script writes colours (`\033[31m`) and non-ASCII
/// characters (`\xe2\x9c\x93`) as escapes every day, never plain letters.
const MANY_ESCAPES: usize = 3;

/// What the scan of the quoting found.
#[derive(Default)]
struct Scan {
    /// `c''at`, `c"a"t`, `'c'"a"'t'`: a word split by quotes around one or
    /// two letters, or by an empty pair between letters.
    splits: u32,
    /// A backslash before a letter outside quotes, which bash drops: the
    /// strongest of `\c\a\t` (escaped letters in a row, 3), `r\m` (one inside
    /// a word, 2) and any other (1).
    backslash_letters: u32,
    /// Command words built by an expansion: 1 for `$x args` and `$(…) args`,
    /// 3 for one that cuts or looks up a value (`${s:2:3}`, `${!r}`).
    computed_programs: u32,
    /// `{cat,file}` as a command: brace expansion makes the command's words.
    brace_commands: u32,
    /// `eval` as a command.
    evals: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
    AnsiC,
}

pub(super) fn score(line: &str, out: &mut Assessment) {
    let scan = scan(line);
    out.add("ansi-escapes", escapes(line));
    out.add(
        "quote-splitting",
        match scan.splits {
            0 => 0,
            1 => 2,
            _ => 3,
        },
    );
    out.add("backslash-escapes", scan.backslash_letters);
    out.add("computed-command", scan.computed_programs);
    out.add("brace-command", 3 * scan.brace_commands.min(1));
    out.add("eval", scan.evals.min(1));
    expansions(line, out);
    out.add("ifs", ifs(line));
    out.add("char-concatenation", concatenation(line));
    out.add("decoder", u32::from(decodes(line)));
    out.add(
        "rev",
        u32::from(line.contains("| rev") || line.contains("|rev")),
    );
    out.add("tr-rotation", 3 * u32::from(rotates(line)));
    out.add("arithmetic", arithmetic(line));
    out.add("escape-density", u32::from(dense(line)));
}

fn scan(line: &str) -> Scan {
    let chars: Vec<char> = line.chars().collect();
    let mut s = Scan::default();
    let mut quote = Quote::None;
    // the start of the quoted text being read, and of the word it is in
    let mut opened = 0usize;
    let mut word_start = 0usize;
    let mut command_start = true;
    let mut i = 0usize;
    let is_letter = |c: Option<&char>| c.is_some_and(char::is_ascii_alphanumeric);
    while let Some(&c) = chars.get(i) {
        match quote {
            Quote::Single | Quote::AnsiC if c == '\'' => {
                close(&chars, opened, i, word_start, &mut s);
                quote = Quote::None;
            }
            Quote::AnsiC | Quote::Double if c == '\\' => i += 1,
            Quote::Double if c == '"' => {
                close(&chars, opened, i, word_start, &mut s);
                quote = Quote::None;
            }
            Quote::Single | Quote::Double | Quote::AnsiC => {}
            Quote::None => {
                let at_word =
                    i == 0 || chars[i - 1].is_whitespace() || "|;&(".contains(chars[i - 1]);
                if at_word {
                    word_start = i;
                }
                if command_start && !c.is_whitespace() {
                    command_start = false;
                    first_word(&chars, i, &mut s, &mut command_start);
                }
                match c {
                    '\'' | '"' => {
                        // an empty pair between letters: `c''at`
                        if chars.get(i + 1) == Some(&c)
                            && i > 0
                            && is_letter(chars.get(i - 1))
                            && is_letter(chars.get(i + 2))
                        {
                            s.splits += 1;
                            i += 2;
                            continue;
                        }
                        quote = if c == '"' {
                            Quote::Double
                        } else {
                            Quote::Single
                        };
                        opened = i;
                    }
                    '$' if chars.get(i + 1) == Some(&'\'') => {
                        quote = Quote::AnsiC;
                        opened = i + 1;
                        i += 1;
                    }
                    '\\' => {
                        if chars.get(i + 1).is_some_and(char::is_ascii_alphabetic) {
                            let weight = if chars.get(i + 2) == Some(&'\\') {
                                3
                            } else if i > 0 && chars[i - 1].is_ascii_alphabetic() {
                                2
                            } else {
                                1
                            };
                            s.backslash_letters = s.backslash_letters.max(weight);
                        }
                        i += 1;
                    }
                    ';' | '|' | '&' | '(' | '\n' => command_start = true,
                    _ => {}
                }
            }
        }
        i += 1;
    }
    s
}

/// A quoted fragment of one or two letters joined to text on both sides
/// (`'c'"a"'t'`, `c"a"t`): the word was cut to hide it.
fn close(chars: &[char], opened: usize, closed: usize, word_start: usize, s: &mut Scan) {
    let inner = &chars[opened + 1..closed];
    let joined_before = opened > word_start;
    let joined_after = chars
        .get(closed + 1)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '\'' || *c == '"');
    if (1..=2).contains(&inner.len())
        && inner.iter().all(char::is_ascii_alphabetic)
        && joined_before
        && joined_after
    {
        s.splits += 1;
    }
}

/// The first word of a command at `at`: an assignment leaves the command's
/// place open; an expansion, a brace list or `eval` there is a signal.
fn first_word(chars: &[char], at: usize, s: &mut Scan, command_start: &mut bool) {
    let rest: String = chars[at..]
        .iter()
        .take_while(|c| !c.is_whitespace() && !";|&".contains(**c))
        .collect();
    let name_end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if name_end > 0 && rest[name_end..].starts_with('=') {
        // `X=1 cmd`: the command is the next word
        *command_start = true;
        return;
    }
    let unquoted = rest.trim_start_matches('"');
    if unquoted.starts_with('$') && !unquoted.starts_with("$'") || rest.starts_with('`') {
        let transformed = rest.match_indices("${").any(|(at, _)| {
            let body = &rest[at + 2..];
            let name_end = body
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(body.len());
            let op = &body[name_end..];
            body.starts_with('!')
                || (op.starts_with(':') && !op[1..].starts_with(['-', '=', '+', '?']))
                || op.starts_with(['/', '^', ','])
        });
        s.computed_programs = s.computed_programs.max(if transformed { 3 } else { 1 });
    }
    if rest.starts_with('{') && rest.contains(',') {
        s.brace_commands += 1;
    }
    if rest == "eval" {
        s.evals += 1;
    }
}

/// `\x63`, `\143`, `\u0063` escapes, not counting colour escapes.
fn escapes(line: &str) -> u32 {
    let bytes = line.as_bytes();
    let mut n = 0usize;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let rest = &bytes[i + 1..];
        let (digits, radix, skip) = match rest.first() {
            Some(b'x') => (hex_run(&rest[1..], 2), 16, 1),
            Some(b'u') => (hex_run(&rest[1..], 4), 16, 1),
            Some(b'0'..=b'7') => {
                let len = rest
                    .iter()
                    .take(3)
                    .take_while(|b| (b'0'..=b'7').contains(b))
                    .count();
                (&rest[..len], 8, 0)
            }
            _ => (&rest[..0], 16, 0),
        };
        let value = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| u32::from_str_radix(d, radix).ok());
        if digits.len() >= 2 && value.is_some_and(|v| (0x20..0x7f).contains(&v)) {
            n += 1;
        }
        i += 1 + skip + digits.len().max(1 - skip);
    }
    if n >= MANY_ESCAPES { 3 } else { 0 }
}

/// The hexadecimal digits at the start of `bytes`, at most `max`.
fn hex_run(bytes: &[u8], max: usize) -> &[u8] {
    let len = bytes
        .iter()
        .take(max)
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    &bytes[..len]
}

/// `${!x}`, `${x:2:3}`, `${x^^}`, `${x//a/b}`: expansions that compute a
/// name or cut and change a value.
fn expansions(line: &str, out: &mut Assessment) {
    let mut slices = 0u32;
    for (at, _) in line.match_indices("${") {
        let body = &line[at + 2..];
        let Some(end) = body.find('}') else { continue };
        let body = &body[..end];
        if let Some(name) = body.strip_prefix('!') {
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                out.add("indirect-expansion", 3);
            }
            continue;
        }
        let name_end = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        let op = &body[name_end..];
        if let Some(rest) = op.strip_prefix(':') {
            let rest = rest.trim_start();
            let numeric = rest.starts_with(|c: char| c.is_ascii_digit())
                || rest.starts_with('(')
                || (rest.starts_with('-') && op[1..].starts_with(' '));
            if numeric {
                slices += 1;
            }
        } else if op.starts_with(['^', ',']) {
            out.add("case-change", 1);
        } else if op.starts_with('/') {
            out.add("pattern-substitution", 1);
        }
    }
    out.add("substring", slices.min(2));
}

/// `IFS=,` before a command that splits with it, and `$IFS` in a word; not
/// `IFS= read`, the common way to read lines whole.
fn ifs(line: &str) -> u32 {
    let reads = |after: &str| {
        let value_end = after.find(char::is_whitespace).unwrap_or(after.len());
        after[value_end..].trim_start().starts_with("read") && !after[..value_end].contains(';')
    };
    let set = line.match_indices("IFS=").any(|(at, _)| {
        let before = line[..at].chars().last();
        before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_')) && !reads(&line[at + 4..])
    });
    let used = line.contains("$IFS") || line.contains("${IFS}");
    2 * u32::from(set || used)
}

/// Three one- or two-letter assignments (`a=c;b=a;c=t`), or three
/// variables joined in one word (`$a$b$c`): a word built a letter at a time.
fn concatenation(line: &str) -> u32 {
    let short_assignments = line
        .split([';', '\n', ' ', '&'])
        .filter(|part| {
            part.split_once('=').is_some_and(|(name, value)| {
                !name.is_empty()
                    && name.len() <= 3
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && (1..=2).contains(&value.trim_matches(['\'', '"']).len())
            })
        })
        .count();
    let joined = line
        .split(|c: char| c.is_whitespace() || "|;&".contains(c))
        .any(|word| {
            let parts: Vec<&str> = word.split('$').collect();
            parts.len() >= 4
                && parts[1..].iter().all(|p| {
                    let p = p.trim_start_matches('{').trim_end_matches(['}', '"']);
                    !p.is_empty()
                        && p.len() <= 3
                        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        });
    2 * u32::from(short_assignments >= 3 || joined)
}

/// A decoder whose output is the next command's input or a substitution.
fn decodes(line: &str) -> bool {
    [
        "base64 -d",
        "base64 --decode",
        "base64 -D",
        "xxd -r",
        "openssl enc -d",
        "openssl base64 -d",
    ]
    .iter()
    .any(|d| line.contains(d))
}

/// `tr` with a rotated alphabet (`tr a-z n-za-m`, ROT13 and its kin).
fn rotates(line: &str) -> bool {
    line.contains("tr ")
        && line.as_bytes().windows(5).any(|w| {
            w[0].is_ascii_alphabetic()
                && w[1] == b'-'
                && matches!(w[2], b'z' | b'Z')
                && matches!(w[3], b'a' | b'A')
                && w[4] == b'-'
                && !matches!(w[0], b'a' | b'A')
        })
}

/// `$((16#63))`, a number in another base, and `\\$(printf …)`, a character
/// made from its code; `$[…]`, the old arithmetic.
fn arithmetic(line: &str) -> u32 {
    let base = line.match_indices("$((").any(|(at, _)| {
        line[at..]
            .find("))")
            .is_some_and(|end| line[at..at + end].contains('#'))
    });
    let built = line.contains("\\$(printf") || line.contains("\\\\$(printf");
    2 * u32::from(base || built) + u32::from(line.contains("$["))
}

/// A line of at least 40 characters, a third of them quoting, escaping or expanding.
fn dense(line: &str) -> bool {
    let special = line.chars().filter(|c| "\\'\"`$".contains(*c)).count();
    line.len() >= 40 && special * 3 > line.chars().count()
}
