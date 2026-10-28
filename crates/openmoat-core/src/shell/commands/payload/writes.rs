//! Inline code that writes files: `open("x.py", "w")`, `write_text`,
//! `shutil.copy`, `fs.writeFileSync`, `File.write`, Perl's `open F, ">x"`,
//! `file_put_contents`, `Deno.writeTextFile`, Lua's `io.open(…, "w")`. The scan
//! cannot tell which of the names in the code the write goes to, so when the
//! code writes at all, every file name it shows as literal text is written as
//! well as read: conservative, never looser. The existing rules then decide
//! those writes (`shell-rc`, `kernel-self`, `runs-later`, `project-fs`), and
//! the guard records them as the session's writes (ADR-039). Code that only
//! reads keeps its reads.

use crate::paths;

/// Calls that write a file whatever arguments they get.
const WRITERS: &[&str] = &[
    // Python
    "write_text",
    "write_bytes",
    ".touch(",
    "shutil.copy",
    "shutil.move",
    "os.rename",
    "os.replace",
    "os.symlink",
    "os.link",
    "os.mkfifo",
    // Node, Deno, Bun
    "writeFileSync",
    "writeFile(",
    "appendFileSync",
    "appendFile(",
    "createWriteStream",
    "copyFileSync",
    "copyFile(",
    "renameSync",
    "symlinkSync",
    "Deno.writeTextFile",
    "Deno.writeFile",
    "Deno.copyFile",
    "Deno.rename",
    "Bun.write",
    // Ruby
    "File.write",
    "IO.write",
    "File.rename",
    "FileUtils.",
    // PHP
    "file_put_contents",
    // PowerShell
    "Set-Content",
    "Add-Content",
    "Out-File",
];

/// Calls whose mode argument says whether they write (`open(p, "w")`).
const OPENERS: &[&str] = &["open(", "fopen("];

/// The literal file names `code` may write, or `None` when it writes nothing.
pub(super) fn written(code: &str) -> Option<Vec<String>> {
    let literals = literals(code);
    let writes = WRITERS.iter().any(|w| code.contains(w))
        || OPENERS.iter().any(|call| {
            code.match_indices(call)
                .any(|(at, _)| opens_for_writing(arguments(&code[at + call.len()..])))
        })
        || perl_writes(code, &literals);
    writes.then(|| {
        literals
            .iter()
            .map(|l| l.trim_start_matches(['+', '>', '<', ' ']))
            .filter(|l| names_a_file(l))
            .map(str::to_owned)
            .collect()
    })
}

/// The text up to the parenthesis that closes the call `rest` starts inside.
fn arguments(rest: &str) -> &str {
    let mut depth = 0usize;
    for (at, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return &rest[..at],
            ')' => depth -= 1,
            _ => {}
        }
    }
    rest
}

/// Whether the arguments of an `open` call hold a mode that writes: `"w"`,
/// `'a'`, `"x"`, `"wb"`, `"r+"`, `mode="w"`.
fn opens_for_writing(arguments: &str) -> bool {
    literals(arguments).iter().skip(1).any(|l| is_write_mode(l))
        || arguments
            .split_once("mode=")
            .is_some_and(|(_, rest)| literals(rest).first().is_some_and(|l| is_write_mode(l)))
}

fn is_write_mode(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 4
        && text.chars().all(|c| "rwaxbtU+".contains(c))
        && text.contains(['w', 'a', 'x', '+'])
}

/// Perl's `open F, ">x"`, `open(my $f, '>>', 'x')`, `'+<'`.
fn perl_writes(code: &str, literals: &[String]) -> bool {
    code.contains("open")
        && literals
            .iter()
            .any(|l| l.starts_with('>') || l.starts_with("+<") || l.starts_with("+>"))
}

/// A literal that names a file: a path, or a plain file name with an
/// extension (`x.py`, `out.txt`); not a mode, a URL or text with spaces.
fn names_a_file(text: &str) -> bool {
    if text.is_empty() || text.contains("://") || text.contains(char::is_whitespace) {
        return false;
    }
    if text.contains(['$', '{', '}', '%', '*', '?', '`']) {
        return false;
    }
    paths::looks_like_path(text)
        || text.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && (1..=5).contains(&ext.len())
                && ext.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// The bodies of the string literals of `code`, with backslash escapes and
/// Python's triple quotes read.
fn literals(code: &str) -> Vec<String> {
    let bytes = code.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            i += 1;
            continue;
        }
        let triple = bytes.get(i..i + 3) == Some(&[quote; 3][..]);
        let open = if triple { 3 } else { 1 };
        let mut j = i + open;
        let mut end = bytes.len();
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == quote && (!triple || bytes.get(j..j + 3) == Some(&[quote; 3][..])) {
                end = j;
                break;
            }
            j += 1;
        }
        if let Some(body) = code.get(i + open..end) {
            found.push(body.to_owned());
        }
        i = end + open;
    }
    found
}
