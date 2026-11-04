//! `ask` to `review` in a policy's text: the rule list and the verdict were
//! renamed in 0.14.0 (ADR-053), and `moat policy upgrade` renames them.
//!
//! The rewrite is on the text, line by line, so comments, order and every other
//! line stay as the person wrote them: a top-level `ask:` key, and `ask` as a
//! value of `defaults` (one verdict, a flow mapping, or a block mapping below
//! it). It is kept only if the result reads as exactly the same policy and no
//! old name is left; otherwise the text stays as it is and `policy lint` keeps
//! saying which name to change by hand.

use openmoat_core::{OLD_REVIEW, OldNames, Policy};

const NEW: &str = "review";

/// `text` with the old names renamed, and whether anything was.
pub fn old_names(text: &str) -> (String, bool) {
    let Ok(before) = Policy::parse(text) else {
        return (text.to_owned(), false);
    };
    if !before.old_names.any() {
        return (text.to_owned(), false);
    }
    let renamed = rewrite(text);
    match Policy::parse(&renamed) {
        Ok(after) if !after.old_names.any() && same(before, &after) => (renamed, true),
        _ => (text.to_owned(), false),
    }
}

fn same(mut before: Policy, after: &Policy) -> bool {
    before.old_names = OldNames::default();
    before == *after
}

fn rewrite(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let mut in_defaults = false;
    for line in text.split_inclusive('\n') {
        let top_level = !line.starts_with([' ', '\t', '#', '\r', '\n']);
        if top_level {
            in_defaults = line.starts_with("defaults:");
        }
        if top_level && let Some(rest) = key_rest(line, OLD_REVIEW) {
            out.push_str(NEW);
            out.push(':');
            out.push_str(rest);
        } else if top_level && in_defaults {
            out.push_str(&values(line, "defaults:".len()));
        } else if in_defaults && !top_level {
            let at = line.find(':').map_or(line.len(), |i| i + 1);
            out.push_str(&values(line, at));
        } else {
            out.push_str(line);
        }
    }
    out
}

/// What follows `key:` when `line` is that key at the start of a line.
fn key_rest<'l>(line: &'l str, key: &str) -> Option<&'l str> {
    let rest = line.strip_prefix(key)?.strip_prefix(':')?;
    (rest.is_empty() || rest.starts_with([' ', '\t', '\r', '\n'])).then_some(rest)
}

/// `line` with each verdict `ask` after byte `from` renamed: a bare, quoted or
/// flow-mapping value, never a key or text inside a comment.
fn values(line: &str, from: usize) -> String {
    let (head, tail) = line.split_at(from.min(line.len()));
    let (body, comment) = match tail.find(" #") {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    let mut out = String::from(head);
    let mut rest = body;
    while let Some(i) = find_value(rest) {
        let (start, len) = i;
        out.push_str(&rest[..start]);
        out.push_str(NEW);
        rest = &rest[start + len..];
    }
    out.push_str(rest);
    out.push_str(comment);
    out
}

/// Byte offset and length of the next `ask` in `text` that is a whole value:
/// after `:` (or at the start, for `defaults: ask`) and before `,`, `}`, the
/// end or a closing quote.
fn find_value(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text[from..].find(OLD_REVIEW) {
        let at = from + found;
        let end = at + OLD_REVIEW.len();
        let quoted =
            at > 0 && matches!(bytes[at - 1], b'"' | b'\'') && bytes.get(end) == bytes.get(at - 1);
        let (start, stop) = if quoted { (at - 1, end + 1) } else { (at, end) };
        let before = text[..start].trim_end();
        let after = text[stop..].trim_start();
        let opens = before.is_empty() || before.ends_with(':');
        let closes = after.is_empty() || after.starts_with([',', '}']);
        if opens && closes {
            return Some((start, stop - start));
        }
        from = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::old_names;

    #[test]
    fn the_list_and_every_form_of_default_are_renamed_and_the_rest_kept() {
        let text = "version: 1\n# ask: stays a comment\ndefaults: { '*': ask, net: deny } # ask\n\
                    ask:   # the questions\n  - id: ask-me\n    reason: ask first\n    \
                    shell: ['ask *']\n";
        let (renamed, changed) = old_names(text);
        assert!(changed);
        assert_eq!(
            renamed,
            "version: 1\n# ask: stays a comment\ndefaults: { '*': review, net: deny } # ask\n\
             review:   # the questions\n  - id: ask-me\n    reason: ask first\n    \
             shell: ['ask *']\n"
        );
        for (before, after) in [
            ("defaults: ask\n", "defaults: review\n"),
            ("defaults: \"ask\"\n", "defaults: review\n"),
            (
                "defaults:\n  net: deny\n  '*': ask\n",
                "defaults:\n  net: deny\n  '*': review\n",
            ),
            (
                "defaults:\r\n  \"*\": 'ask'\r\n",
                "defaults:\r\n  \"*\": review\r\n",
            ),
        ] {
            let (renamed, changed) = old_names(&format!("version: 1\n{before}"));
            assert!(changed, "{before}");
            assert_eq!(renamed, format!("version: 1\n{after}"));
        }
    }

    #[test]
    fn a_policy_without_old_names_or_that_does_not_parse_is_left_alone() {
        for text in [
            "version: 1\ndefaults: review\nreview: []\n",
            "version: 1\nask: [\n",
            "version: 1\nask: []\nreview: []\n",
        ] {
            assert_eq!(old_names(text), (text.to_owned(), false), "{text}");
        }
    }
}
