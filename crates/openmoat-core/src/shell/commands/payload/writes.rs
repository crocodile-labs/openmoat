//! Inline code that writes files: `open("x.py", "w")`, `write_text`,
//! `shutil.copy`, `fs.writeFileSync`, `File.write`, Perl's `open F, ">x"`,
//! `file_put_contents`, `Deno.writeTextFile`, Lua's `io.open(…, "w")`. The scan
//! cannot tell which of the names in the code the write goes to, so when the
//! code writes at all, every file name it shows as literal text is written as
//! well as read: conservative, never looser. The existing rules then decide
//! those writes (`shell-rc`, `kernel-self`, `runs-later`, `project-fs`), and
//! the guard records them as the session's writes (ADR-039). Code that only
//! reads keeps its reads.

use std::collections::BTreeMap;

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
    "binwrite",
    "FileUtils.",
    // PHP
    "file_put_contents",
    // PowerShell
    "Set-Content",
    "Add-Content",
    "Out-File",
];

/// Calls whose mode argument says whether they write (`open(p, "w")`,
/// `os.open(p, os.O_WRONLY)`, `fs.openSync(p, "a")`, `File.new(p, "w")`).
const OPENERS: &[&str] = &["open(", "fopen(", "openSync(", "File.new("];

/// `open` flags that write (`os.O_WRONLY`, `fs.constants.O_APPEND`).
const WRITE_FLAGS: &[&str] = &["O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"];

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

/// The literals `code` shows where it writes them, once per place: the
/// arguments of a write call (`writeFileSync("x.js", …)`, `FileUtils.cp(…)`),
/// its receiver (`Path("x.py").write_text(…)`), the file of an `open` in a
/// write mode and Perl's `">x"`. Those places name what is written, not code
/// that runs (`executes/inline.rs`).
pub(super) fn targets(code: &str) -> Vec<String> {
    // keyed by where the place starts: `fopen(` is also `open(`, and
    // `Deno.writeFile(` also `writeFile(`; one place counts once
    let mut places: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let offset = |part: &str| part.as_ptr() as usize - code.as_ptr() as usize;
    let mut receiver = |at: usize| {
        let before = code[..at].trim_end_matches('.');
        if let Some(inside) = before.strip_suffix(')').and_then(opened) {
            places.insert(offset(inside), literals(inside));
        }
    };
    let mut calls: Vec<(usize, &str)> = Vec::new();
    for writer in WRITERS {
        for (at, _) in code.match_indices(writer) {
            receiver(at);
            let after = code[at + writer.len()..]
                .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
            let after = if writer.ends_with('(') {
                Some(after)
            } else {
                after.strip_prefix('(')
            };
            calls.extend(after.map(|rest| (offset(rest), arguments(rest))));
        }
    }
    for call in OPENERS {
        for (at, _) in code.match_indices(call) {
            let rest = &code[at + call.len()..];
            let arguments = arguments(rest);
            if !opens_for_writing(arguments) {
                continue;
            }
            // `Path("x.py").open("w")`: the file is the receiver
            receiver(at);
            if arguments.trim_start().starts_with(['"', '\'', '`']) {
                calls.push((
                    offset(rest),
                    &arguments[..arguments.find(',').unwrap_or(arguments.len())],
                ));
            }
        }
    }
    for (at, arguments) in calls {
        places.insert(at, literals(arguments));
    }
    let mut found: Vec<String> = places.into_values().flatten().collect();
    let literals = literals(code);
    if perl_writes(code, &literals) {
        // `">x"`, `"+<x"`, and the name after a bare `">"` / `">>"` / `"+<"`
        let mut after_mode = false;
        for literal in literals {
            let name = literal.trim_start_matches(['+', '>', '<', ' ']);
            let writes = literal.starts_with(['>', '+']);
            if after_mode || (writes && !name.is_empty()) {
                found.push(name.to_owned());
            }
            after_mode = writes && name.is_empty();
        }
    }
    found.retain(|name| !name.is_empty());
    found
}

/// The text inside the parenthesis that `before`'s closing one (just cut off)
/// matches: `Path("x.py"` → `"x.py"`.
fn opened(before: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (at, c) in before.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' if depth == 0 => return Some(&before[at + 1..]),
            '(' => depth -= 1,
            _ => {}
        }
    }
    None
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
/// `'a'`, `"x"`, `"wb"`, `"r+"`, `mode="w"`, a write flag. Any literal
/// counts, whatever its place (`open(p, "w")` has no literal file name); a
/// file that is itself named `w` is read as a mode: conservative.
fn opens_for_writing(arguments: &str) -> bool {
    literals(arguments).iter().any(|l| is_write_mode(l))
        || WRITE_FLAGS.iter().any(|flag| arguments.contains(flag))
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
