//! `unparseable` (POLICY.md §4 step 5): never `allow`; a part the classifier
//! cannot model takes the catch-all, a line not read in full needs review.

use super::*;

/// Padding a line until the classifier stops cannot turn a deny into the
/// default policy's `defer`: past the atom limit or the length limit the call
/// needs review (`MAX_ATOMS`, `MAX_COMMAND_BYTES`).
#[test]
fn a_deny_hidden_past_a_classifier_limit_needs_review() {
    let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let operands = (0..crate::shell::MAX_ATOMS + 10)
        .map(|i| format!("f{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    for line in [
        format!("cat {operands}; cat ~/.ssh/id_rsa"),
        format!(
            "cat ~/.ssh/id_rsa # {}",
            "x".repeat(crate::lexer::MAX_COMMAND_BYTES)
        ),
    ] {
        let d = evaluate(&p, &ctx(), &shell(&line)).unwrap();
        assert!(
            matches!(d.verdict, Verdict::Review | Verdict::Deny),
            "{:?} {:?}",
            d.verdict,
            d.rules
        );
    }
}

/// The same for the glob budget all globs of one call share (`MAX_MATCHES`):
/// a glob that names more than can be listed may name a secret past the
/// bound, so the call needs review instead of the catch-all's `defer`.
#[test]
fn a_deny_hidden_past_the_glob_expansion_limit_needs_review() {
    use crate::expand::MAX_MATCHES;
    use crate::realpath::MapPathResolver;
    let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let mut files: Vec<String> = (0..=MAX_MATCHES).map(|n| format!("/p/a{n}")).collect();
    // listed last, so only past the bound
    files.push("/p/z/.env".to_owned());
    let fs = MapPathResolver {
        files,
        ..MapPathResolver::default()
    };
    for line in ["cat */.env", "cat *", "true; cat */.env"] {
        let d = compiled.decide_with(&shell(line), &NoResolver, &fs);
        assert!(
            matches!(d.verdict, Verdict::Review | Verdict::Deny),
            "{line}: {:?} {:?}",
            d.verdict,
            d.rules
        );
    }
}

/// `inner` inside `levels` nested `$( … )`.
fn nested(levels: usize, inner: &str) -> String {
    format!("{}{inner}{}", "echo $(".repeat(levels), ")".repeat(levels))
}

/// Nesting up to `MAX_DEPTH` levels of `$( … )` is classified as written: the
/// innermost command keeps its verdict. One level more and the classifier
/// stops, so the call needs review, never `allow` or the catch-all's `defer`.
#[test]
fn nesting_at_the_depth_limit_is_classified_and_past_it_needs_review() {
    let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let decide = |line: &str| evaluate(&p, &ctx(), &shell(line)).unwrap();
    let at = usize::from(crate::shell::MAX_DEPTH);
    let d = decide(&nested(at, "cat src/main.rs"));
    assert_eq!(d.verdict, Verdict::Allow, "{:?}", d.rules);
    let d = decide(&nested(at, "cat ~/.ssh/id_rsa"));
    assert_eq!(d.verdict, Verdict::Deny, "{:?}", d.rules);
    for inner in ["cat src/main.rs", "cat ~/.ssh/id_rsa"] {
        let d = decide(&nested(at + 1, inner));
        assert!(
            matches!(d.verdict, Verdict::Review | Verdict::Deny),
            "{inner}: {:?} {:?}",
            d.verdict,
            d.rules
        );
    }
    let d = decide(&nested(at + 1, "cat src/main.rs"));
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Review, vec!["unparseable".to_owned()])
    );
}

/// A word whose braces make `MAX_BRACE_WORDS` words is checked as every one of
/// them; one that would make more is kept as written and the call needs review.
#[test]
fn braces_at_the_word_limit_are_classified_and_past_it_need_review() {
    let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let decide = |line: &str| evaluate(&p, &ctx(), &shell(line)).unwrap();
    let at = crate::lexer::MAX_BRACE_WORDS;
    let d = decide(&format!("cat src/f{{1..{at}}}.rs"));
    assert_eq!(d.verdict, Verdict::Allow, "{:?}", d.rules);
    // the last of the words the braces make is a secret: it is still checked
    let d = decide(&format!("cat {{src/f{{1..{}}}.rs,.env}}", at - 1));
    assert_eq!(d.verdict, Verdict::Deny, "{:?}", d.rules);
    let past = at + 1;
    let d = decide(&format!("cat src/f{{1..{past}}}.rs"));
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Review, vec!["unparseable".to_owned()])
    );
    let d = decide(&format!("cat src/f{{1..{past}}}.rs; cat .e{{nv,x}}"));
    assert!(
        matches!(d.verdict, Verdict::Review | Verdict::Deny),
        "{:?} {:?}",
        d.verdict,
        d.rules
    );
}

#[test]
fn unparseable_is_never_allowed() {
    let p = policy("version: 1\ndefaults: allow\n");
    // A line the lexer cannot read needs review whatever the catch-all says: a deny in
    // the part that was not read must not become a defer.
    let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
    assert_eq!(d.verdict, Verdict::Review);
    assert_eq!(d.rules, ["unparseable"]);
    let d = evaluate(
        &p,
        &ctx(),
        &Action::Net {
            url: "https://".into(),
        },
    )
    .unwrap();
    assert_eq!(d.verdict, Verdict::Defer);
    let powershell = Action::ForeignShell {
        shell: "PowerShell".into(),
        command: "Get-ChildItem".into(),
    };
    let d = evaluate(&p, &ctx(), &powershell).unwrap();
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Defer, vec!["unparseable".to_owned()])
    );
    // Under a `review` catch-all it needs review, as before ADR-025.
    let p = policy("version: 1\ndefaults: review\n");
    let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
    assert_eq!(d.verdict, Verdict::Review);
}
