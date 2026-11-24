//! Whether one pattern matches everything another does, reading `{a,b}`
//! alternatives as the union they are, and what a broader `{…}` list gained.
//!
//! [`openmoat_core::lint::covers`] compares a glob word only with an equal one,
//! so `{moat,openmoat} {allow,trust}*` does not cover itself with `team` added
//! to the list. Expanding both lists into their alternatives first shows it does:
//! every alternative of the old pattern is covered by one of the new.
//! Conservative: anything that does not expand cleanly (a nested or unbalanced
//! brace, an escape, a class, a list with spaces or quotes, too many
//! alternatives) is compared as written, so the answer errs towards "no".

use openmoat_core::Kind;

/// More alternatives than this and the pattern is compared as written.
const MAX_EXPANSIONS: usize = 512;

/// True when every call `target` matches is also matched by `by`.
pub(super) fn covers(kind: Kind, by: &str, target: &str) -> bool {
    if openmoat_core::lint::covers(kind, by, target) {
        return true;
    }
    let (Some(by), Some(target)) = (expansions(by), expansions(target)) else {
        return false;
    };
    target
        .iter()
        .all(|t| by.iter().any(|b| openmoat_core::lint::covers(kind, b, t)))
}

/// The alternatives `new` lists in its `{…}` groups that `old` does not, when
/// the two are the same pattern but for longer lists: `team` for
/// `x {allow,trust}*` → `x {allow,team,trust}*`. `None` for any other change.
pub(super) fn gained(old: &str, new: &str) -> Option<Vec<String>> {
    let (old, new) = (split(old)?, split(new)?);
    if old.len() != new.len() {
        return None;
    }
    let mut gained = Vec::new();
    for (was, now) in old.iter().zip(&new) {
        match (was, now) {
            (Piece::Text(a), Piece::Text(b)) if a == b => {}
            (Piece::Alternatives(a), Piece::Alternatives(b)) if a.iter().all(|x| b.contains(x)) => {
                gained.extend(b.iter().filter(|x| !a.contains(x)).cloned());
            }
            _ => return None,
        }
    }
    gained.dedup();
    (!gained.is_empty()).then_some(gained)
}

/// A stretch of a pattern: text as written, or one `{a,b}` list.
#[derive(Debug, PartialEq, Eq)]
enum Piece {
    Text(String),
    Alternatives(Vec<String>),
}

/// `pattern` cut into text and `{…}` lists. `${name}` is a variable, kept as
/// text. `None` when a list is nested, unbalanced, empty or holds a space, a
/// quote, an escape or a class, or the pattern has an escape or a class.
fn split(pattern: &str) -> Option<Vec<Piece>> {
    if pattern.contains(['\\', '[', ']']) {
        return None;
    }
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '$' if chars.as_str().starts_with('{') => {
                let rest = chars.as_str();
                let end = rest.find('}')?;
                text.push('$');
                text.push_str(&rest[..=end]);
                chars = rest[end + 1..].chars();
            }
            '{' => {
                let rest = chars.as_str();
                let end = rest.find('}')?;
                let body = &rest[..end];
                if body.is_empty() || body.contains(['{', ' ', '\t', '\'', '"']) {
                    return None;
                }
                if !text.is_empty() {
                    pieces.push(Piece::Text(std::mem::take(&mut text)));
                }
                pieces.push(Piece::Alternatives(
                    body.split(',').map(str::to_owned).collect(),
                ));
                chars = rest[end + 1..].chars();
            }
            '}' => return None,
            other => text.push(other),
        }
    }
    if !text.is_empty() {
        pieces.push(Piece::Text(text));
    }
    Some(pieces)
}

/// Every pattern `pattern`'s `{…}` lists stand for, or `None` (see [`split`]).
fn expansions(pattern: &str) -> Option<Vec<String>> {
    let mut all = vec![String::new()];
    for piece in split(pattern)? {
        match piece {
            Piece::Text(text) => all.iter_mut().for_each(|p| p.push_str(&text)),
            Piece::Alternatives(alternatives) => {
                if all.len() * alternatives.len() > MAX_EXPANSIONS {
                    return None;
                }
                all = all
                    .iter()
                    .flat_map(|p| alternatives.iter().map(move |a| format!("{p}{a}")))
                    .collect();
            }
        }
    }
    Some(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "script * {moat,openmoat} {allow,snapshot,trust}*";
    const NEW: &str = "script * {moat,openmoat} {allow,snapshot,team,trust}*";

    #[test]
    fn a_longer_list_covers_the_shorter_and_not_the_reverse() {
        assert!(!openmoat_core::lint::covers(Kind::Shell, NEW, OLD));
        assert!(covers(Kind::Shell, NEW, OLD));
        assert!(!covers(Kind::Shell, OLD, NEW), "`team` was not matched");
        assert_eq!(gained(OLD, NEW), Some(vec!["team".to_owned()]));
        assert_eq!(gained(NEW, OLD), None, "a shorter list gained nothing");
        // A quoted pattern word and a file pattern read the same way.
        assert!(covers(
            Kind::Shell,
            "expect * '*moat {edit,team,trust}*'",
            "expect * '*moat {edit,trust}*'"
        ));
        assert!(covers(
            Kind::FsWrite,
            "~/.moat/{policy,team}/**",
            "~/.moat/{policy}/**"
        ));
    }

    #[test]
    fn anything_else_is_not_a_superset() {
        // Another command around the same list.
        assert!(!covers(
            Kind::Shell,
            "tmux * {moat,openmoat} {allow,team}*",
            "script * {moat,openmoat} {allow}*"
        ));
        assert_eq!(
            gained(
                "script * {moat,openmoat} {allow}*",
                "tmux * {moat,openmoat} {allow,team}*"
            ),
            None
        );
        // A list that lost an entry while gaining one.
        assert!(!covers(Kind::Shell, "x {a,c}*", "x {a,b}*"));
        assert_eq!(gained("x {a,b}*", "x {a,c}*"), None);
        // Variables are text, nested or escaped lists are not expanded.
        assert_eq!(
            expansions("${project}/{a,b}"),
            Some(vec!["${project}/a".to_owned(), "${project}/b".to_owned()])
        );
        assert_eq!(expansions("x {a,{b,c}}"), None);
        assert_eq!(expansions(r"x \{a,b}"), None);
        assert_eq!(expansions("x {a b,c}"), None);
        assert_eq!(expansions("x a}"), None);
    }
}
