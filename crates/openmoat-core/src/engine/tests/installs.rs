//! Package installs (ADR-030): an ordinary install decides as its command
//! alone; only a near miss adds an atom of its own.

use super::*;

fn decided(p: &Policy, command: &str) -> (Verdict, Vec<String>) {
    let d = evaluate(p, &ctx(), &shell(command)).unwrap();
    (d.verdict, d.rules)
}

const NEAR_MISS_ASK: &str =
    "ask:\n  - id: package-near-miss\n    shell: ['@package-near-miss *']\n";

#[test]
fn an_allowed_install_stays_allowed_whatever_the_catch_all() {
    for catch_all in ["ask", "deny"] {
        let p = policy(&format!(
            "version: 1\ndefaults: {{ '*': {catch_all} }}\n{NEAR_MISS_ASK}\
             allow:\n  - id: left-pad\n    shell: ['npm i left-pad', 'pip install requests']\n"
        ));
        let allowed = (Verdict::Allow, vec!["left-pad".to_owned()]);
        assert_eq!(decided(&p, "npm i left-pad"), allowed, "{catch_all}");
        assert_eq!(decided(&p, "pip install requests"), allowed, "{catch_all}");
        // what no rule names still gets the catch-all
        assert_ne!(decided(&p, "npm i other").0, Verdict::Allow, "{catch_all}");
    }
}

#[test]
fn a_near_miss_asks_until_a_rule_allows_its_own_atom() {
    let with = |shell: &str| {
        policy(&format!(
            "version: 1\ndefaults: {{ '*': deny }}\n{NEAR_MISS_ASK}\
             allow:\n  - id: lodahs\n    shell: [{shell}]\n"
        ))
    };
    assert_eq!(
        decided(&with("'npm i lodahs'"), "npm i lodahs"),
        (Verdict::Ask, vec!["package-near-miss".to_owned()])
    );
    let both = with("'npm i lodahs', '@package-near-miss npm lodahs lodash'");
    assert_eq!(decided(&both, "npm i lodahs").0, Verdict::Allow);
}
