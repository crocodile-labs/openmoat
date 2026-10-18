//! `unparseable` (POLICY.md §4 step 5): never `allow`; a part the classifier
//! cannot model takes the catch-all, a line not read in full asks.

use super::*;

/// Padding a line until the classifier stops cannot turn a deny into the
/// default policy's `defer`: past the atom limit or the length limit the call
/// asks (`MAX_ATOMS`, `MAX_COMMAND_BYTES`).
#[test]
fn a_deny_hidden_past_a_classifier_limit_asks() {
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
            matches!(d.verdict, Verdict::Ask | Verdict::Deny),
            "{:?} {:?}",
            d.verdict,
            d.rules
        );
    }
}

#[test]
fn unparseable_is_never_allowed() {
    let p = policy("version: 1\ndefaults: allow\n");
    // A line the lexer cannot read asks whatever the catch-all says: a deny in
    // the part that was not read must not become a defer.
    let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
    assert_eq!(d.verdict, Verdict::Ask);
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
    // Under an `ask` catch-all it asks, as before ADR-025.
    let p = policy("version: 1\ndefaults: ask\n");
    let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
    assert_eq!(d.verdict, Verdict::Ask);
}
