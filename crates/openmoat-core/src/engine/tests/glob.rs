//! Glob operands: checked as the files the shell expands them to (`crate::expand`).

use super::*;
use crate::expand::MAX_MATCHES;
use crate::realpath::MapPathResolver;

/// An unquoted glob operand is checked as every file it matches as well as
/// literally; a quoted or escaped one only literally; one that names too much
/// needs review without hiding a deny (docs/POLICY.md §3.2).
#[test]
fn glob_operands_are_checked_as_the_files_they_match() {
    let p = policy(
        "version: 1\ndefaults: review\ndeny:\n  - id: secret\n    \
         fs.read: ['**/.env', '~/.ssh/**']\n    fs.write: ['**/.env']\n\
         allow:\n  - id: proj\n    fs.read: ['${project}/**']\n    \
         fs.write: ['${project}/**']\n  - id: cat\n    shell: ['cat *', 'echo *', 'timeout *']\n",
    );
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let mut fs = MapPathResolver {
        links: [("/p/s".to_owned(), "/h/.ssh".to_owned())].into(),
        files: ["/p/.env", "/p/src/a.rs", "/h/.ssh/id_rsa"]
            .map(str::to_owned)
            .into(),
    };
    let decide = |fs: &MapPathResolver, cmd: &str| {
        let d = compiled.decide_with(&shell(cmd), &NoResolver, fs);
        (d.verdict, d.rules)
    };
    let secret = (Verdict::Deny, vec!["secret".to_owned()]);
    for cmd in [
        "cat .en?",
        "cat .e*",
        "cat .[e]nv",
        "cat < .en?",
        "echo x > .e*",
        "timeout 5 cat .en?",
        "cat ~/.ss?/id_rsa",
        "cat s/*",
        "cat src/../.e*",
    ] {
        assert_eq!(decide(&fs, cmd), secret, "{cmd}");
    }
    let allowed = (Verdict::Allow, vec!["cat".to_owned(), "proj".to_owned()]);
    for cmd in ["cat src/*.rs", "cat *", "cat '.en?'", "cat .en\\?"] {
        assert_eq!(decide(&fs, cmd), allowed, "{cmd}");
    }

    fs.files
        .extend((0..MAX_MATCHES).map(|n| format!("/p/f{n}")));
    let (verdict, rules) = decide(&fs, "cat *");
    assert_eq!(verdict, Verdict::Review);
    assert!(rules.contains(&"unparseable".to_owned()), "{rules:?}");
    assert_eq!(
        decide(&fs, "cat * .env"),
        secret,
        "a deny beside an overflow stays"
    );
}
