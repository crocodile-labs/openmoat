//! Compound commands: reserved words, `for` loops and shell variables.

use super::{ParseOutcome, classify, ctx, has_read, parsed};
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
    // known values are substituted: each command is classified with each value
    let a = parsed("for s in a1 b2; do git log -1 $s; done");
    assert!(!reads_env(&a, "s"), "{a:?}");
    let s = shells(&a);
    assert!(
        s.contains(&"git log -1 a1".to_owned()) && s.contains(&"git log -1 b2".to_owned()),
        "{s:?}"
    );
    // a value that is not known keeps the read
    let a = parsed("for s in $GITHUB_TOKEN b; do git log -1 $s; done");
    assert!(reads_env(&a, "GITHUB_TOKEN"), "{a:?}");
    assert!(reads_env(&a, "s"), "{a:?}");
}

#[test]
fn a_known_variable_is_substituted_where_it_names_a_path() {
    let a = parsed("d=~/.ssh; cat $d/id_rsa");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"), "{a:?}");
    let a = parsed("d=~/.ssh; echo x > ${d}/authorized_keys");
    assert!(
        a.contains(&AtomicAction::FsWrite {
            path: "/Users/me/.ssh/authorized_keys".to_owned()
        }),
        "{a:?}"
    );
    // a later assignment replaces the earlier value; values chain
    assert!(has_read(
        &parsed("d=x; d=~/.ssh; cat $d/id_rsa"),
        "/Users/me/.ssh/id_rsa"
    ));
    assert!(has_read(
        &parsed("d=~/.ssh; e=$d; cat $e/id_rsa"),
        "/Users/me/.ssh/id_rsa"
    ));
    // an uppercase name is substituted as well, and keeps its read
    let a = parsed("X=~/.ssh; cat $X/id_rsa");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"), "{a:?}");
    assert!(reads_env(&a, "X"), "{a:?}");
    assert!(has_read(
        &parsed("export D=~/.ssh; cat $D/id_rsa"),
        "/Users/me/.ssh/id_rsa"
    ));
    // with an option the builtin may set an array, a number or a reference
    assert!(matches!(
        classify("declare -n D=x; cat $D/id_rsa", &ctx()),
        ParseOutcome::Unparseable { .. }
    ));
    // inside single quotes nothing is expanded: the file is literally `$d/id_rsa`
    assert!(has_read(
        &parsed("d=~/.ssh; cat '$d/id_rsa'"),
        "/p/$d/id_rsa"
    ));
}

#[test]
fn a_path_through_a_variable_that_is_not_known_is_unparseable() {
    for cmd in [
        "cat $X/id_rsa",
        "d=$(pwd); cat $d/id_rsa",
        "d=~/.ssh; cat ${d:-x}/id_rsa",
        "d='~/.ssh'; cat $d/id_rsa",
        "for f in src/*.rs; do wc -l $f; done",
    ] {
        assert!(
            matches!(classify(cmd, &ctx()), ParseOutcome::Unparseable { .. }),
            "{cmd}"
        );
    }
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
