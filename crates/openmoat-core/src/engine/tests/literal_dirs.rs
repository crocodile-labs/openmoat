//! A home, project, moved or resolved directory spliced into a rule pattern
//! is literal text (`paths::glob_literal`): its glob characters match only
//! themselves, in deny, allow, review and defer lists alike.

use super::*;
use crate::kind::Kind;

const RULES: &str = "version: 1\ndefaults: review\n\
     deny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n  - id: state\n    fs.write: ['~/.claude/**']\n\
     allow:\n  - id: proj\n    fs.write: ['${project}/**', '!${project}/.git/**']\n\
     defer:\n  - id: notes\n    fs.read: ['~/notes/*']\n";

fn decide(ctx: &EvalContext, action: &Action) -> Verdict {
    CompiledPolicy::compile(&policy(RULES), ctx)
        .unwrap()
        .decide(action)
        .verdict
}

fn read(path: &str) -> Action {
    Action::FsRead { path: path.into() }
}

fn write(path: &str) -> Action {
    Action::FsWrite { path: path.into() }
}

/// Each glob character, and a space, in the home, the project, their
/// resolved spellings and a moved directory names that directory only.
#[test]
fn glob_characters_in_spliced_directories_match_only_themselves() {
    for c in ['*', '?', '[', ']', '{', '}', ',', ' '] {
        let ctx = EvalContext {
            home: format!("/Users/a{c}b"),
            project: Some(format!("/w/p{c}q")),
            real_home: Some(format!("/vol/a{c}b")),
            real_project: Some(format!("/vol/p{c}q")),
            moved_dirs: vec![("~/.claude".into(), format!("/srv/m{c}n"))],
            cwd: format!("/w/p{c}q"),
            case_insensitive_paths: false,
        };
        for home in [format!("/Users/a{c}b"), format!("/vol/a{c}b")] {
            let key = format!("{home}/.ssh/id_rsa");
            assert_eq!(decide(&ctx, &read(&key)), Verdict::Deny, "{key}");
            let notes = format!("{home}/notes/n.md");
            assert_eq!(decide(&ctx, &read(&notes)), Verdict::Defer, "{notes}");
        }
        for project in [format!("/w/p{c}q"), format!("/vol/p{c}q")] {
            let own = format!("{project}/src/main.rs");
            assert_eq!(decide(&ctx, &write(&own)), Verdict::Allow, "{own}");
            let git = format!("{project}/.git/config");
            assert_eq!(decide(&ctx, &write(&git)), Verdict::Review, "{git}");
        }
        let moved = format!("/srv/m{c}n/settings.json");
        assert_eq!(decide(&ctx, &write(&moved)), Verdict::Deny, "{moved}");
        // look-alikes a wildcard, a class or an alternation would take in
        for other in ["X", "", "XY", "bX", "{", "["] {
            if other == c.to_string() {
                continue;
            }
            for home in ["/Users", "/vol"] {
                let key = format!("{home}/a{other}b/.ssh/id_rsa");
                assert_ne!(decide(&ctx, &read(&key)), Verdict::Deny, "{c:?}: {key}");
                let notes = format!("{home}/a{other}b/notes/n.md");
                assert_eq!(
                    decide(&ctx, &read(&notes)),
                    Verdict::Review,
                    "{c:?}: {notes}"
                );
            }
            for project in ["/w", "/vol"] {
                let near = format!("{project}/p{other}q/src/main.rs");
                assert_eq!(
                    decide(&ctx, &write(&near)),
                    Verdict::Review,
                    "{c:?}: {near}"
                );
            }
            let near = format!("/srv/m{other}n/settings.json");
            assert_eq!(
                decide(&ctx, &write(&near)),
                Verdict::Review,
                "{c:?}: {near}"
            );
        }
    }
}

/// A `\` in a directory is a separator, as in every path the engine checks:
/// `/Users/a\b` is checked as `/Users/a/b`, the home's own paths match, and
/// neither `/Users/ab` nor a `\b` read as an escaped `b` does.
#[test]
fn a_backslash_in_a_spliced_directory_is_a_separator() {
    let ctx = EvalContext {
        home: r"/Users/a\b".into(),
        project: Some(r"/w/p\q".into()),
        cwd: r"/w/p\q".into(),
        ..ctx()
    };
    for key in [
        r"/Users/a\b/.ssh/id_rsa",
        "/Users/a/b/.ssh/id_rsa",
        "~/.ssh/id_rsa",
    ] {
        assert_eq!(decide(&ctx, &read(key)), Verdict::Deny, "{key}");
    }
    assert_eq!(
        decide(&ctx, &read("/Users/ab/.ssh/id_rsa")),
        Verdict::Review
    );
    assert_eq!(decide(&ctx, &write(r"/w/p\q/src/x")), Verdict::Allow);
    assert_eq!(decide(&ctx, &write("${project}/src/x")), Verdict::Allow);
    assert_eq!(decide(&ctx, &write("/w/pq/src/x")), Verdict::Review);
}

/// For a home and project without glob characters, every pattern of the
/// default policy is spelled exactly as plain text substitution spells it.
#[test]
fn ordinary_directories_spell_the_default_policy_unchanged() {
    let p = Policy::parse(crate::DEFAULT_POLICY).expect("default policy must lint");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: Some("/Users/me/src/app".into()),
        real_home: Some("/System/Volumes/Data/Users/me".into()),
        real_project: Some("/System/Volumes/Data/Users/me/src/app".into()),
        moved_dirs: vec![("~/.claude".into(), "/srv/claude-config".into())],
        cwd: "/Users/me/src/app".into(),
        case_insensitive_paths: false,
    };
    let plain = |raw: &str| -> Vec<String> {
        let (negated, body) = crate::pattern::split_negation(raw);
        let bang = if negated { "!" } else { "" };
        let mut bodies = vec![body.to_owned()];
        for (default, dir) in &ctx.moved_dirs {
            if let Some(rest) = body.strip_prefix(default.as_str())
                && (rest.is_empty() || rest.starts_with('/'))
            {
                bodies.push(format!("{dir}{rest}"));
            }
        }
        let mut out = Vec::new();
        for home in [&ctx.home, ctx.real_home.as_ref().unwrap()] {
            for project in [
                ctx.project.as_ref().unwrap(),
                ctx.real_project.as_ref().unwrap(),
            ] {
                for body in &bodies {
                    let homed = match body.strip_prefix('~') {
                        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
                            format!("{home}{rest}")
                        }
                        _ => body.clone(),
                    };
                    out.push(format!("{bang}{}", homed.replace("${project}", project)));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    };
    let mut checked = 0;
    for group in p
        .deny
        .iter()
        .chain(&p.allow)
        .chain(&p.review)
        .chain(&p.defer)
    {
        for kind in [Kind::FsRead, Kind::FsWrite] {
            for raw in group.patterns(kind) {
                // `~name` (another user) is kept as written by both
                if crate::paths::other_user_home(raw.trim_start_matches('!'), &ctx.home) {
                    continue;
                }
                assert_eq!(ctx.spellings(raw), plain(raw), "{}: {raw}", group.id);
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "only {checked} patterns checked");
}
