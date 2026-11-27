//! The proof that a pattern's needles hold: every match of the pattern in an
//! ASCII text holds one of them in some letter case, so a text that holds none
//! is left as it is without building the regex (`redact/gate.rs`).
//!
//! The proof reads the pattern as the regex crate parses it (`regex-syntax`'s
//! HIR, with the same defaults) and finds texts every match must hold
//! ([`required`]); each of those must hold one of the rule's needles.

use regex_syntax::hir::{Class, Hir, HirKind};

use super::super::{Rule, rules};

/// The lowercase ASCII character every character `class` matches folds to,
/// when there is one: a letter in any case (`(?i)k` is `[Kk\u{212A}]`) or one
/// character. In an ASCII text, a match of the class is that character in
/// some letter case.
fn one_letter(class: &Class) -> Option<char> {
    let mut found = None;
    let mut fold = |c: char| -> Option<()> {
        let folded = match c {
            c if c.is_ascii() => c.to_ascii_lowercase(),
            // The non-ASCII members of a case-folded `s` and `k`: absent from
            // an ASCII text, so a match there is the ASCII letter.
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            _ => return None,
        };
        match found {
            None => found = Some(folded),
            Some(seen) if seen == folded => {}
            Some(_) => return None,
        }
        Some(())
    };
    match class {
        Class::Unicode(set) => {
            for range in set.ranges() {
                if u32::from(range.end()) - u32::from(range.start()) > 4 {
                    return None;
                }
                for c in range.start()..=range.end() {
                    fold(c)?;
                }
            }
        }
        Class::Bytes(set) => {
            for range in set.ranges() {
                if range.end() - range.start() > 4 {
                    return None;
                }
                for b in range.start()..=range.end() {
                    fold(char::from(b))?;
                }
            }
        }
    }
    found
}

/// The exact text `hir` matches, lowercased, when it matches one text only
/// (up to the letter case of an ASCII text): a literal, a one-letter class, or
/// a group or a concatenation of those.
fn exact(hir: &Hir) -> Option<String> {
    match hir.kind() {
        HirKind::Literal(literal) => {
            let text = std::str::from_utf8(&literal.0).ok()?;
            text.is_ascii().then(|| text.to_ascii_lowercase())
        }
        HirKind::Class(class) => one_letter(class).map(String::from),
        HirKind::Capture(capture) => exact(&capture.sub),
        HirKind::Concat(subs) => subs.iter().map(exact).collect(),
        _ => None,
    }
}

/// Texts one of which every match of `hir` in an ASCII text holds, ignoring
/// letter case (all lowercase); `None` when none is known. Of several such
/// sets the one whose shortest text is longest.
pub(super) fn required(hir: &Hir) -> Option<Vec<String>> {
    if let Some(text) = exact(hir).filter(|t| !t.is_empty()) {
        return Some(vec![text]);
    }
    match hir.kind() {
        HirKind::Capture(capture) => required(&capture.sub),
        HirKind::Repetition(rep) if rep.min >= 1 => required(&rep.sub),
        // Each branch's set: a match is a match of one of them.
        HirKind::Alternation(subs) => {
            let mut all = Vec::new();
            for sub in subs {
                all.extend(required(sub)?);
            }
            all.sort();
            all.dedup();
            Some(all)
        }
        // A match holds the match of every part: each run of exact parts is
        // one text, and each other part's own set holds too.
        HirKind::Concat(subs) => {
            let mut candidates: Vec<Vec<String>> = Vec::new();
            let mut run = String::new();
            for sub in subs {
                if let Some(text) = exact(sub) {
                    run.push_str(&text);
                    continue;
                }
                if !run.is_empty() {
                    candidates.push(vec![std::mem::take(&mut run)]);
                }
                candidates.extend(required(sub));
            }
            if !run.is_empty() {
                candidates.push(vec![run]);
            }
            // The first of the most selective, so the answer reads left to right.
            let shortest = |set: &Vec<String>| set.iter().map(String::len).min().unwrap_or(0);
            let mut best: Option<Vec<String>> = None;
            for set in candidates {
                if best.as_ref().is_none_or(|b| shortest(&set) > shortest(b)) {
                    best = Some(set);
                }
            }
            best
        }
        _ => None,
    }
}

/// What the proof finds for `rule`'s pattern.
fn derived(rule: &Rule) -> Option<Vec<String>> {
    let hir = regex_syntax::parse(rule.pattern).expect("the pattern parses");
    required(&hir)
}

#[test]
fn every_needle_holds() {
    let mut wrong = Vec::new();
    for rule in rules() {
        for needle in rule.needs {
            if needle.is_empty()
                || !needle
                    .bytes()
                    .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
            {
                wrong.push(format!(
                    "{}: needle {needle:?} is not lowercase ASCII",
                    rule.pattern
                ));
            }
        }
        if rule.needs.is_empty() {
            continue;
        }
        let Some(found) = derived(&rule) else {
            wrong.push(format!(
                "{}: no text every match holds; leave its needles empty",
                rule.pattern
            ));
            continue;
        };
        for text in &found {
            if !rule.needs.iter().any(|n| text.contains(n)) {
                wrong.push(format!(
                    "{}: a match may hold {text:?}, which holds none of {:?} (derived {found:?})",
                    rule.pattern, rule.needs
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_proof_reads_patterns_as_expected() {
    let of = |p: &str| required(&regex_syntax::parse(p).unwrap());
    assert_eq!(of(r"(?i)\bbearer\s+x"), Some(vec!["bearer".to_owned()]));
    assert_eq!(of(r"AKIA[0-9A-Z]{16}"), Some(vec!["akia".to_owned()]));
    assert_eq!(
        of(r"(?i)(?:api[_-]?key|token)"),
        Some(vec!["api".to_owned(), "token".to_owned()])
    );
    assert_eq!(of(r"(?:a|b*)"), None);
    assert_eq!(of(r"x?"), None);
    assert_eq!(of(r"[a-z]+"), None);
    assert_eq!(of(r"(?i)ks"), Some(vec!["ks".to_owned()]));
}
