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
