//! Brace groups in IR globs, expanded before they become Seatbelt filters.

/// Most patterns one brace group may expand to; past it the pattern is
/// translated as written.
const MAX_ALTERNATIVES: usize = 64;

/// `pattern` with its brace groups expanded (`src/{a,b}.rs` → `src/a.rs`,
/// `src/b.rs`), as the
/// engine's glob reads them; nested groups too. A pattern without braces, with
/// an unclosed group, or with more than [`MAX_ALTERNATIVES`] results is
/// returned as it is.
pub(super) fn alternatives(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    if expand(pattern, &mut out) {
        out
    } else {
        vec![pattern.to_owned()]
    }
}

/// Append every expansion of `pattern` to `out`; `false` when it cannot be
/// expanded within the bound.
fn expand(pattern: &str, out: &mut Vec<String>) -> bool {
    let Some((open, close, options)) = first_group(pattern) else {
        out.push(pattern.to_owned());
        return true;
    };
    let (head, tail) = (&pattern[..open], &pattern[close + 1..]);
    options.iter().all(|option| {
        expand(&format!("{head}{option}{tail}"), out) && out.len() <= MAX_ALTERNATIVES
    })
}

/// The first top-level brace group: its byte range and its comma-separated
/// options (nested groups left in them). `None` without a closed group.
fn first_group(pattern: &str) -> Option<(usize, usize, Vec<&str>)> {
    let (mut depth, mut open, mut start) = (0usize, None, 0);
    let mut options = Vec::new();
    let mut chars = pattern.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '{' => {
                if depth == 0 {
                    open = Some(i);
                    start = i + 1;
                }
                depth += 1;
            }
            ',' if depth == 1 => {
                options.push(&pattern[start..i]);
                start = i + 1;
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    options.push(&pattern[start..i]);
                    return Some((open?, i, options));
                }
            }
            _ => {}
        }
    }
    None
}
