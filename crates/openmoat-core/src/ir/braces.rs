//! Brace groups in file globs, expanded before they reach an OS backend.
//!
//! The engine's globs read `{a,b}` as alternatives. Seatbelt has no such syntax,
//! Claude Code's and Codex's settings and bubblewrap's mounts need each path on
//! its own, so [`super::lower()`] writes every alternative of a file pattern as a
//! pattern of its own (`~/.codex/{auth.json,.credentials.json}` becomes two).

/// Most patterns one brace group may expand to; past it the pattern is
/// translated as written.
const MAX_ALTERNATIVES: usize = 64;

/// `pattern` with its brace groups expanded (`src/{a,b}.rs` → `src/a.rs`,
/// `src/b.rs`), as the engine's glob reads them; nested groups too. A pattern
/// without braces, with an unclosed group, or with more than
/// `MAX_ALTERNATIVES` (64) results is returned as it is.
#[must_use]
pub fn alternatives(pattern: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::alternatives;

    fn owned(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn each_alternative_becomes_a_pattern() {
        assert_eq!(
            alternatives("/h/{.ssh/**,.aws/**}"),
            owned(&["/h/.ssh/**", "/h/.aws/**"])
        );
        assert_eq!(
            alternatives("/a/{b,{c,d}e}/f"),
            owned(&["/a/b/f", "/a/ce/f", "/a/de/f"])
        );
        assert_eq!(
            alternatives("!/p/{x,y}/**"),
            owned(&["!/p/x/**", "!/p/y/**"])
        );
        assert_eq!(alternatives("/a/{b"), owned(&["/a/{b"]), "unclosed");
        assert_eq!(
            alternatives(r"/a/\{b,c}"),
            owned(&[r"/a/\{b,c}"]),
            "escaped"
        );
        let wide = "/{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}";
        assert_eq!(alternatives(wide), owned(&[wide]), "past the bound");
    }
}
