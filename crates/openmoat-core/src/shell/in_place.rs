//! Commands that rewrite the files they name: `perl -i` and `ruby -i` edit their
//! file operands in place (and write a backup when given a suffix), and `patch`
//! writes the file it patches and its `-o` and `-r` files and reads its `-i`
//! patch file. Each becomes an `fs.write` (or `fs.read`), so the write rules
//! apply. Interpreter code itself is not read here, except to recognise a
//! `perl -pi -e` program that is only substitutions ([`substitution`]).

use super::{ClassifyError, ShellContext, Sink};

/// `perl -i` with `-p` or `-n` and one `-e`/`-E` program that is only `s`
/// substitutions without the `e` flag ([`substitutions_only`]): the argv index
/// of the program. Such a command rewrites the files it names and opens
/// nothing else, so the files are its writes ([`interpreter`]) and the program
/// is data, not code to scan or a path. Any other option (`-M`, `-l`, `-a`, …),
/// a second program, a program file or no `-i` is not recognised, and the
/// command is decided as any other inline program.
pub(super) fn substitution(argv: &[String], program: &str) -> Option<usize> {
    if program != "perl" {
        return None;
    }
    let mut in_place = false;
    let mut reads_lines = false;
    let mut code: Option<usize> = None;
    let mut words = argv.iter().enumerate().skip(1);
    while let Some((_, arg)) = words.next() {
        let Some(cluster) = arg
            .strip_prefix('-')
            .filter(|c| !c.is_empty() && !c.starts_with('-'))
        else {
            break;
        };
        let bytes = cluster.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            match bytes[at] {
                b'p' | b'n' => {
                    reads_lines = true;
                    at += 1;
                }
                // the rest of the word is the backup suffix
                b'i' => {
                    in_place = true;
                    break;
                }
                // `-0` and its octal digits set the record separator
                b'0' => {
                    at += 1;
                    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                        at += 1;
                    }
                }
                b'e' | b'E' => {
                    let rest = &cluster[at + 1..];
                    // attached code (`-es/a/b/`) is not a separate word to point at
                    let index = if rest.is_empty() {
                        words.next()?.0
                    } else {
                        return None;
                    };
                    if code.replace(index).is_some() {
                        return None;
                    }
                    break;
                }
                _ => return None,
            }
        }
    }
    code.filter(|&at| in_place && reads_lines && substitutions_only(&argv[at]))
}

/// Whether `program` is only `s` substitutions, separated by `;` and
/// whitespace: each with a delimiter or a bracket pair, and flags without
/// `e`, which runs the replacement as code. Perl interpolates variables into
/// the pattern and the replacement, and `@{[ … ]}` or `${\ …}` there runs
/// code, so a `$` may only name a capture (`$1`, `${1}`, `$&`) or, in the
/// pattern, be an anchor, and no `@` or backtick may appear; `(?{ … })` in
/// the pattern runs code too. A backslash escapes the next character.
fn substitutions_only(program: &str) -> bool {
    let separators = |c: char| c.is_whitespace() || c == ';';
    let mut rest = program.trim_start_matches(separators);
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix('s').and_then(substitution_body) else {
            return false;
        };
        rest = after.trim_start_matches(separators);
    }
    true
}

/// What follows one substitution's `/pattern/replacement/flags` (after the `s`).
fn substitution_body(text: &str) -> Option<&str> {
    let (open, rest) = delimiter(text)?;
    let (pattern, rest) = part(rest, open, closing(open))?;
    // with a bracket pair, the replacement has its own, maybe after whitespace
    let (open, rest) = if closing(open) == open {
        (open, rest)
    } else {
        delimiter(rest.trim_start())?
    };
    let (replacement, rest) = part(rest, open, closing(open))?;
    let flags_end = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let flags = &rest[..flags_end];
    let safe = flags.chars().all(|c| "gimsxopr".contains(c))
        && !pattern.contains("(?{")
        && !pattern.contains("(??{")
        && interpolates_only_captures(pattern, true)
        && interpolates_only_captures(replacement, false);
    safe.then_some(&rest[flags_end..])
}

/// The delimiter `text` starts with: any character but a letter, a digit,
/// whitespace or a backslash.
fn delimiter(text: &str) -> Option<(char, &str)> {
    let c = text.chars().next()?;
    (!c.is_alphanumeric() && !c.is_whitespace() && c != '\\').then(|| (c, &text[c.len_utf8()..]))
}

/// The text up to the unescaped `close` (nested pairs skipped when `open` and
/// `close` differ), and what follows it.
fn part(text: &str, open: char, close: char) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c == close && depth == 0 {
            return Some((&text[..at], &text[at + c.len_utf8()..]));
        } else if c == close {
            depth -= 1;
        } else if c == open && open != close {
            depth += 1;
        }
    }
    None
}

fn closing(open: char) -> char {
    match open {
        '{' => '}',
        '(' => ')',
        '[' => ']',
        '<' => '>',
        c => c,
    }
}

/// Whether `text` interpolates nothing but captures: every unescaped `$` is
/// followed by a digit, `&` or `{digits}`, or, in a pattern, is an anchor
/// (followed by `)`, `|` or nothing); no unescaped `@` or backtick.
fn interpolates_only_captures(text: &str, pattern: bool) -> bool {
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '`' | '@' => return false,
            '$' => {
                let rest = &text[at + 1..];
                let capture = rest.starts_with('&')
                    || rest.starts_with(|d: char| d.is_ascii_digit())
                    || rest
                        .strip_prefix('{')
                        .and_then(|r| r.split_once('}'))
                        .is_some_and(|(n, _)| {
                            !n.is_empty() && n.chars().all(|d| d.is_ascii_digit())
                        });
                let anchor = pattern && (rest.is_empty() || rest.starts_with([')', '|']));
                if !capture && !anchor {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Options of `perl` and `ruby` whose value is the rest of the word or else the
/// next word; every other letter that takes a value takes only the rest.
fn takes_next(program: &str, c: char) -> bool {
    match program {
        "perl" => matches!(c, 'e' | 'E'),
        _ => matches!(c, 'e' | 'I' | 'r' | 'C' | 'E'),
    }
}

/// Letters that take the rest of the word as their value.
fn takes_rest(program: &str, c: char) -> bool {
    match program {
        "perl" => "ilx0CdDFIMmV".contains(c),
        _ => "ix0WFKT".contains(c),
    }
}

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match program {
        "perl" | "ruby" => interpreter(argv, program, ctx, sink),
        "patch" => patch(argv, ctx, sink),
        _ => Ok(()),
    }
}

fn interpreter(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let mut suffix: Option<&str> = None;
    let mut code = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            break;
        };
        i += 1;
        if cluster.starts_with('-') {
            continue;
        }
        for (pos, c) in cluster.char_indices() {
            let rest = &cluster[pos + c.len_utf8()..];
            if c == 'i' {
                suffix = Some(rest);
                break;
            }
            if takes_next(program, c) {
                code |= matches!(c, 'e' | 'E') && !(program == "ruby" && c == 'E');
                i += usize::from(rest.is_empty());
                break;
            }
            if takes_rest(program, c) {
                break;
            }
        }
    }
    let Some(suffix) = suffix else {
        return Ok(());
    };
    // without `-e`, the first operand is the script
    let files = argv
        .get(i..)
        .unwrap_or_default()
        .iter()
        .skip(usize::from(!code));
    for file in files {
        sink.write(ctx, file)?;
        if suffix.contains('*') {
            sink.write(ctx, &suffix.replace('*', file))?;
        } else if !suffix.is_empty() {
            sink.write(ctx, &format!("{file}{suffix}"))?;
        }
    }
    Ok(())
}

/// `patch` options whose value is the rest of the word or the next word.
const PATCH_VALUED: &str = "BDdFgioprVYz";
const PATCH_LONG_VALUED: &[&str] = &[
    "input",
    "output",
    "reject-file",
    "directory",
    "strip",
    "prefix",
    "suffix",
    "basename-prefix",
    "ifdef",
    "fuzz",
    "version-control",
    "quoting-style",
    "get",
];

/// `patch [OPTION]… [ORIGFILE [PATCHFILE]]`.
fn patch(argv: &[String], ctx: &ShellContext<'_>, sink: &mut Sink) -> Result<(), ClassifyError> {
    let mut operands = Vec::new();
    let mut options = true;
    let mut words = argv[1..].iter();
    while let Some(arg) = words.next() {
        if !options || arg == "-" || !arg.starts_with('-') {
            operands.push(arg.as_str());
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        let (name, value) = if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None if PATCH_LONG_VALUED.contains(&long) => (long, words.next().cloned()),
                None => (long, None),
            }
        } else {
            let cluster = &arg[1..];
            match cluster
                .char_indices()
                .find(|(_, c)| PATCH_VALUED.contains(*c))
            {
                Some((pos, c)) => {
                    let rest = &cluster[pos + c.len_utf8()..];
                    let value = if rest.is_empty() {
                        words.next().cloned()
                    } else {
                        Some(rest.to_owned())
                    };
                    (&cluster[pos..pos + c.len_utf8()], value)
                }
                None => continue,
            }
        };
        let Some(value) = value.filter(|v| !v.is_empty() && v != "-") else {
            continue;
        };
        match name {
            "i" | "input" => sink.read(ctx, &value)?,
            "o" | "output" | "r" | "reject-file" => sink.write(ctx, &value)?,
            _ => {}
        }
    }
    let mut operands = operands.into_iter().filter(|o| *o != "-");
    if let Some(target) = operands.next() {
        sink.write(ctx, target)?;
    }
    if let Some(patch_file) = operands.next() {
        sink.read(ctx, patch_file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{substitution, substitutions_only};

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn in_place_substitution_programs() {
        for words in [
            &["perl", "-pi", "-e", "s/foo/bar/g", "src/lib.rs"][..],
            &["perl", "-0pi", "-e", "s~\\A.*?x~y~s", "a.cpp"],
            &["perl", "-pi.bak", "-e", "s/a/b/", "README.md"],
            &["perl", "-i", "-pe", "s{a}{b}gs", "README.md"],
            &["perl", "-ni", "-e", "s|a|b|; s/c/d/", "README.md"],
            &["perl", "-0777", "-pi", "-e", "s/a\\nb/c/", "README.md"],
            &["perl", "-pi", "-e", "s/(a)(b)/$2$1${1}$&/", "f"],
        ] {
            let a = argv(words);
            assert!(substitution(&a, "perl").is_some(), "{words:?}");
        }
    }

    #[test]
    fn programs_that_are_more_than_substitutions() {
        for words in [
            // no `-i`, or no `-p`/`-n`
            &["perl", "-pe", "s/a/b/", "f"][..],
            &["perl", "-i", "-e", "s/a/b/", "f"],
            // the `e` flag runs the replacement
            &["perl", "-pi", "-e", "s/x/`id`/e", "f"],
            &["perl", "-pi", "-e", "s/x/system(\"id\")/ee", "f"],
            // code beside the substitution, a module, a second program
            &["perl", "-pi", "-e", "s/x/y/; system(\"id\")", "f"],
            &["perl", "-pi", "-e", "use POSIX; s/a/b/", "f"],
            &["perl", "-MFile::Copy", "-pi", "-e", "s/a/b/", "f"],
            &["perl", "-pi", "-e", "s/a/b/", "-e", "s/c/d/", "f"],
            &["perl", "-pi", "-l", "-e", "s/a/b/", "f"],
            &["perl", "-pi", "-es/a/b/", "f"],
            // code and variables interpolated into the replacement or the pattern
            &["perl", "-pi", "-e", "s/a/@{[ system(\"id\") ]}/", "f"],
            &["perl", "-pi", "-e", "s/a/${\\ system(\"id\")}/", "f"],
            &["perl", "-pi", "-e", "s/a/$ENV{GITHUB_TOKEN}/", "f"],
            &["perl", "-pi", "-e", "s/(?{ system(\"id\") })/x/", "f"],
            &["perl", "-pi", "-e", "s/$x/y/", "f"],
            &["perl", "-pi", "-e", "s/@a/y/", "f"],
            // not a substitution at all
            &["perl", "-pi", "-e", "tr/a-z/A-Z/", "f"],
            &["perl", "-pi", "-e", "", "f"],
            &["perl", "-pi", "-e", "s/a/b", "f"],
        ] {
            let a = argv(words);
            assert!(substitution(&a, "perl").is_none(), "{words:?}");
        }
    }

    #[test]
    fn anchors_and_escapes() {
        assert!(substitutions_only("s/^a$/b/; s/(x|y)$/z/"));
        assert!(substitutions_only("s/\\$HOME/home/"));
        assert!(substitutions_only("s/a\\/b/c/"));
        assert!(substitutions_only("s{a{1}}{b}"));
        assert!(!substitutions_only("s/a/\\\\$x/"));
    }
}
