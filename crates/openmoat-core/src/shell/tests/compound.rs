//! Compound commands: reserved words, `for` loops and shell variables.

use super::{has_read, parsed};
use crate::action::AtomicAction;

fn shells(atoms: &[AtomicAction]) -> Vec<String> {
    atoms
        .iter()
        .filter_map(|a| match a {
            AtomicAction::Shell { argv } => Some(argv.join(" ")),
            _ => None,
        })
        .collect()
}

fn reads_env(atoms: &[AtomicAction], name: &str) -> bool {
    atoms.contains(&AtomicAction::EnvRead {
        name: name.to_owned(),
    })
}

#[test]
fn the_command_after_a_reserved_word_is_classified() {
    let a = parsed("for f in a b; do cat ~/.ssh/id_rsa; done");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"), "{a:?}");
    let a = parsed("if cat .env; then echo ok; else rm x; fi");
    assert!(has_read(&a, "/p/.env"), "{a:?}");
    let s = shells(&a);
    assert!(s.contains(&"cat .env".to_owned()), "{s:?}");
    assert!(s.contains(&"rm x".to_owned()), "{s:?}");
    assert!(
        !s.iter().any(|x| x.starts_with("if ") || x == "fi"),
        "{s:?}"
    );
    let s = shells(&parsed("while true; do ! git log -1; done"));
    assert!(s.contains(&"git log -1".to_owned()), "{s:?}");
}

#[test]
fn a_quoted_reserved_word_is_a_program() {
    let s = shells(&parsed("'do' x"));
    assert_eq!(s, ["do x"]);
}

#[test]
fn a_for_loop_sets_its_variable() {
    let a = parsed("for PATH in /x; do ls; done");
    assert!(a.contains(&AtomicAction::EnvSet {
        name: "PATH".to_owned()
    }));
    let a = parsed("for s in $GITHUB_TOKEN b; do git log -1 $s; done");
    assert!(reads_env(&a, "GITHUB_TOKEN"), "{a:?}");
    assert!(!reads_env(&a, "s"), "{a:?}");
}

#[test]
fn only_a_lowercase_variable_set_on_its_own_is_local() {
    assert!(!reads_env(&parsed("x=1; echo $x"), "x"));
    assert!(reads_env(&parsed("X=1; echo $X"), "X"));
    // a prefix assignment sets the variable for that one command only
    assert!(reads_env(&parsed("x=1 true; echo $x"), "x"));
    // read before it is set
    assert!(reads_env(&parsed("echo $x; x=1"), "x"));
    // a child shell does not see it
    assert!(reads_env(&parsed("x=1; sh -c 'echo $x'"), "x"));
}
