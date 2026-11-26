//! The literal text every match of a glob ends with, or for `dir/**` holds,
//! read from the glob's own text: what lets [`super::LazyGlob`] refuse a
//! candidate without building the regex.
//!
//! Most path patterns of the default policy begin with `**/` (`**/.env`,
//! `**/.git/hooks/**`), so their literal start is empty and the prefix check
//! passes every path; and most shell programs are written
//! `{gh,*/gh}`. Without this check, the first decision of a process built a
//! regex for each of them; with it, only for those a candidate could match.

/// Characters after which the rest of a glob is not plain literal text, or
/// that open or close a class or an alternation.
const META: [char; 7] = ['*', '?', '[', ']', '{', '}', '\\'];

/// What every match of a glob must show at its end, or anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tail {
    /// Nothing known: every candidate goes to the regex.
    Any,
    /// Every match ends with one of these (ASCII) texts.
    EndsWith(Vec<String>),
    /// Every match holds one of these (ASCII) texts: a `dir/**` glob, whose
    /// matches are a match of `dir`, a `/` and anything.
    Contains(Vec<String>),
}

impl Tail {
    /// The tail of `glob`, as globset parses it with any options.
    pub(super) fn of(glob: &str) -> Self {
        match glob.strip_suffix("/**") {
            Some(dir) if !dir.is_empty() => endings(dir).map_or(Self::Any, Self::Contains),
            _ => endings(glob).map_or(Self::Any, Self::EndsWith),
        }
    }

    /// False only where the regex could not match either. A candidate with a
    /// non-ASCII character, which the glob's own non-ASCII text or case
    /// folding may match in ways an ASCII comparison does not see, or with a
    /// `\`, which globset reads as a separator on Windows, is left to the regex.
    pub(super) fn may_match(&self, candidate: &str, case_insensitive: bool) -> bool {
        if !candidate.is_ascii() || candidate.contains('\\') {
            return true;
        }
        let eq = |a: &[u8], b: &[u8]| {
            if case_insensitive {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        };
        let text = candidate.as_bytes();
        match self {
            Self::Any => true,
            Self::EndsWith(ends) => ends.iter().any(|end| {
                let end = end.as_bytes();
                text.len() >= end.len() && eq(&text[text.len() - end.len()..], end)
            }),
            Self::Contains(parts) => parts.iter().any(|part| {
                let part = part.as_bytes();
                text.windows(part.len()).any(|w| eq(w, part))
            }),
        }
    }
}

/// The texts one of which every match of `glob` ends with; `None` when one
/// of them would be empty, or the glob's end is not read here.
///
/// A glob ending in plain text ends every match with that text: the text after
/// its last [`META`] character. A glob ending in an alternation `{a,b}` ends
/// every match with one alternative's, each read the same way. Only the ASCII
/// end of each counts, and a leading `/` is dropped, since a `**` before it
/// takes the `/` too (`**/x` matches `x`).
fn endings(glob: &str) -> Option<Vec<String>> {
    let Some(body) = glob.strip_suffix('}') else {
        return ending(glob).map(|e| vec![e]);
    };
    if glob.contains(['[', '\\']) {
        return None;
    }
    let open = body.rfind('{')?;
    let alternatives = &body[open + 1..];
    if alternatives.contains('}') {
        return None;
    }
    alternatives.split(',').map(ending).collect()
}

/// The ASCII literal text `glob` ends with, without a leading `/`; `None`
/// when that is empty.
fn ending(glob: &str) -> Option<String> {
    let literal = glob.rfind(META).map_or(glob, |at| &glob[at + 1..]);
    let ascii = literal
        .rfind(|c: char| !c.is_ascii())
        .map_or(literal, |at| {
            let width = literal[at..].chars().next().map_or(1, char::len_utf8);
            &literal[at + width..]
        });
    let end = ascii.trim_start_matches('/');
    (!end.is_empty()).then(|| end.to_owned())
}

#[cfg(test)]
mod tests;
