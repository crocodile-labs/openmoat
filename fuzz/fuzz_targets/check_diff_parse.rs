//! `openmoat policy check-diff` and the pull request action read a unified
//! diff the pull request's author wrote. The parser must reject what it cannot
//! read in full without panicking: every path it reports comes from the input,
//! and a diff cut off inside a hunk is an error, never a clean change.

#![no_main]

// As openclaw_json5 does for json5.rs: `moat` is a binary crate, and the
// parser is one file that uses only `std`.
#[path = "../../crates/openmoat-cli/src/commands/policy/diff/parse.rs"]
mod parse;

use libfuzzer_sys::fuzz_target;

/// The lines a `@@ -a,b +c,d @@` header says its hunk holds; `None` for a
/// line that is not one.
fn hunk_lines(line: &str) -> Option<usize> {
    let mut parts = line.strip_prefix("@@ ")?.split(' ');
    let count = |part: Option<&str>, sign: char| -> Option<usize> {
        let range = part?.strip_prefix(sign)?;
        match range.split_once(',') {
            Some((start, count)) => {
                start.parse::<usize>().ok()?;
                count.parse().ok()
            }
            None => range.parse::<usize>().ok().map(|_| 1),
        }
    };
    let old = count(parts.next(), '-')?;
    let new = count(parts.next(), '+')?;
    (parts.next()? == "@@").then_some(old + new)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(files) = parse::parse(text) else {
        return;
    };
    // A quoted name is decoded (`\t`, octal escapes), so only an unquoted one
    // must appear as it is.
    for file in &files {
        for path in file.paths() {
            assert!(text.contains(path) || text.contains('"'), "{path:?}");
        }
        for (_, line) in &file.added {
            assert!(text.contains(line.as_str()), "{line:?}");
        }
    }
    // Cut the diff right after each hunk header that promises lines: what is
    // left must not read as a complete diff, with or without the line's end.
    let lines: Vec<&str> = text.split('\n').collect();
    let mut in_file = false;
    let mut offset = 0;
    for line in &lines {
        let end = offset + line.len();
        let bare = line.strip_suffix('\r').unwrap_or(line);
        in_file |= bare.starts_with("diff --git ") || bare.starts_with("--- ");
        if in_file && hunk_lines(bare).is_some_and(|n| n > 0) {
            let cut = &text[..end];
            assert!(parse::parse(cut).is_err(), "{cut:?}");
            if end < text.len() {
                let cut = &text[..=end];
                assert!(parse::parse(cut).is_err(), "{cut:?}");
            }
        }
        offset = end + 1;
    }
});
