use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;

fn generated(yaml: &str) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ctx = EvalContext {
        home: "/home/me".into(),
        project: Some("/home/me/proj".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/me/proj".into(),
        case_insensitive_paths: false,
    };
    let grants = Grants {
        proxy_port: Some(18080),
        tmpdir: Some("/tmp".into()),
        program: Some("/home/me/.local/bin/agent".into()),
        writes: vec!["/home/me/.agent".into()],
        terminals: vec!["/dev/pts/3".into()],
    };
    let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
    generate(&ir, &grants).expect("generates")
}

fn allowance<'a>(out: &'a Generated, kind: Kind, rule: &str) -> Option<&'a [String]> {
    let found = out.report.allowances.iter();
    let mut found = found.filter(|a| a.kind == kind && a.rule == rule);
    found.next().map(|a| a.patterns.as_slice())
}

#[test]
fn the_default_policy_grants_the_project_roots_and_session_paths_only() {
    let out = generated(DEFAULT_POLICY);
    let rules = &out.rules;
    for read in [
        "/home/me/proj",
        "/usr",
        "/home/me/.cargo",
        "/dev/null",
        "/home/me/.local/bin/agent",
    ] {
        assert!(
            rules.read.contains(&read.to_owned()),
            "{read}: {:?}",
            rules.read
        );
    }
    for write in ["/home/me/proj", "/tmp", "/home/me/.agent", "/dev/null"] {
        assert!(
            rules.write.contains(&write.to_owned()),
            "{write}: {:?}",
            rules.write
        );
    }
    for never in ["/", "/home/me", "/home/me/.ssh", "/dev/pts"] {
        assert!(!rules.read.contains(&never.to_owned()), "{never}");
        assert!(!rules.write.contains(&never.to_owned()), "{never}");
    }
    // Only the run's own terminal and the controlling one, `/dev/tty`.
    let terminals = |list: &[String]| {
        let found = list
            .iter()
            .filter(|p| p.starts_with("/dev/pts") || p.starts_with("/dev/tty"));
        found.cloned().collect::<Vec<_>>()
    };
    assert_eq!(terminals(&rules.read), ["/dev/tty", "/dev/pts/3"]);
    assert_eq!(terminals(&rules.write), ["/dev/tty", "/dev/pts/3"]);
    assert!(allowance(&out, Kind::FsWrite, "landlock.terminal").is_some());
    assert!(
        !rules.write.contains(&"/usr".to_owned()),
        "read roots stay read-only"
    );
    assert_eq!(rules.connect_port, Some(18080));
}

#[test]
fn denies_inside_grants_are_listed_as_allowances() {
    let out = generated(DEFAULT_POLICY);
    let read = allowance(&out, Kind::FsRead, "landlock.inside-grants").unwrap_or_default();
    for open in ["**/.env", "/home/me/.cargo/credentials.toml"] {
        assert!(read.contains(&open.to_owned()), "{open}: {read:?}");
    }
    assert!(
        !read.contains(&"/home/me/.ssh/**".to_owned()),
        "outside every grant: enforced"
    );
    let write = allowance(&out, Kind::FsWrite, "landlock.inside-grants").unwrap_or_default();
    for open in ["/home/me/proj/.git/**", "**/.claude/settings.json"] {
        assert!(write.contains(&open.to_owned()), "{open}: {write:?}");
    }
    assert!(
        !write.contains(&"/home/me/.zshrc".to_owned()),
        "outside every grant: enforced"
    );
    assert!(allowance(&out, Kind::Net, "landlock.tcp-port").is_some());
    assert!(
        allowance(&out, Kind::Net, "landlock.sockets").is_none(),
        "the seccomp filter closes UDP and Unix sockets"
    );
    assert!(out.report.losses.iter().any(|l| l.rule == "registries"));
}

#[test]
fn a_grant_inside_a_denied_path_is_not_made_and_globs_stay_denied() {
    let out = generated(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.ssh/**']\n\
         allow:\n  - id: g\n    fs.read: ['/srv/*.log']\n\
         sandbox:\n  read_roots: ['~/.ssh/pub', '/usr']\n",
    );
    assert!(!out.rules.read.contains(&"/home/me/.ssh/pub".to_owned()));
    assert!(out.rules.read.contains(&"/usr".to_owned()));
    let losses: Vec<String> = out.report.losses.iter().map(ToString::to_string).collect();
    assert!(
        losses.iter().any(|l| l.contains("/home/me/.ssh/pub")),
        "{losses:?}"
    );
    assert!(
        losses.iter().any(|l| l.contains("/srv/*.log")),
        "{losses:?}"
    );
}

#[test]
fn an_allow_default_grants_the_root() {
    let out = generated("version: 1\ndefaults:\n  fs.read: allow\n");
    assert!(out.rules.read.contains(&"/".to_owned()));
    assert!(!out.rules.write.contains(&"/".to_owned()));
}
