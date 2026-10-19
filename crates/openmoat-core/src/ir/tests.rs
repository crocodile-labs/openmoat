use super::*;
use crate::action::AtomicAction;
use crate::engine::EvalContext;
use crate::policy::Policy;

fn ctx() -> EvalContext {
    EvalContext {
        home: "/h".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    }
}

fn lowered(yaml: &str) -> Enforcement {
    lower(&Policy::parse(yaml).expect("test policy must lint"), &ctx()).expect("must lower")
}

fn ids(rules: &[Rule]) -> Vec<&str> {
    rules.iter().map(|r| r.id.as_str()).collect()
}

fn read(path: &str) -> AtomicAction {
    AtomicAction::FsRead { path: path.into() }
}

#[test]
fn default_policy_lowers_paths_and_hosts() {
    let ir = lower(
        &Policy::parse(crate::DEFAULT_POLICY).unwrap(),
        &EvalContext {
            home: "/Users/me".into(),
            ..ctx()
        },
    )
    .unwrap();
    assert_eq!(ir.fs.read.default, Effect::Deny);
    // `kernel-self` also denies reads of OpenMoat's state beside the policy.
    assert_eq!(ids(&ir.fs.read.deny), ["secrets-paths", "kernel-self"]);
    assert!(
        ir.fs.read.deny[1]
            .patterns
            .contains(&"/Users/me/.moat/policy.lock".to_owned())
    );
    assert_eq!(ids(&ir.fs.read.allow), ["project-fs", "agent-temp"]);
    let secrets = &ir.fs.read.deny[0].patterns;
    assert!(secrets.contains(&"/Users/me/.ssh/**".to_owned()));
    assert!(
        secrets.contains(&"!**/.env.example".to_owned()),
        "exclusions kept"
    );
    assert_eq!(
        ir.fs.write.allow[0].patterns[..4],
        ["/p/**", "!/p/.git/**", "!/p/**/.git/**", "!/p/.moat/**"]
    );
    assert!(
        (ir.fs.write.allow[0].patterns.iter()).any(|p| p == "!/p/**/.github/workflows/**"),
        "what `runs-later` asks for is left out"
    );
    assert_eq!(
        ids(&ir.fs.write.deny),
        ["secrets-paths", "destructive", "kernel-self", "shell-rc"]
    );
    // the home directory and the root themselves, not their subtrees, and raw disks
    assert_eq!(
        ir.fs.write.deny[1].patterns[..3],
        ["/Users/me", "/", "/dev/disk*"]
    );
    assert_eq!(ir.egress.net.default, Effect::Deny);
    assert_eq!(
        ids(&ir.egress.net.deny),
        ["cloud-metadata", CLOUD_METADATA_RULE]
    );
    assert_eq!(ids(&ir.egress.net.allow), ["registries"]);
    assert_eq!(
        ir.egress.fetch.default,
        Effect::Deny,
        "fetch: ask lowers to deny"
    );
    assert!(ir.secrets.is_empty() && ir.limits.is_empty());
    let kinds: Vec<&str> = ir.decide_only.iter().map(|d| d.kind.as_str()).collect();
    assert_eq!(kinds, ["shell", "env.read", "env.set", "mcp"]);
}

#[test]
fn every_deferred_kind_is_reported_as_a_loss() {
    let ir = lowered(crate::DEFAULT_POLICY);
    let losses: Vec<String> = ir.losses.iter().map(ToString::to_string).collect();
    let agent = "the hook leaves it to the agent";
    for expected in [
        format!("fs.read `default`: no rule matches: {agent}, OS layers deny"),
        format!("fs.write `default`: no rule matches: {agent}, OS layers deny"),
        format!("fetch `default.fetch`: no rule matches: {agent}, OS layers deny"),
        format!("net `local-net`: {agent}; OS layers deny unless an allow rule matches"),
        format!("fetch `local-net`: {agent}; OS layers deny unless an allow rule matches"),
        "fs.read `home-sweep`: the hook asks; OS layers deny unless an allow rule matches".into(),
        "fs.write `git-internals`: the hook asks; OS layers deny unless an allow rule matches"
            .into(),
        "fs.write `persistence`: the hook asks; OS layers deny unless an allow rule matches".into(),
        "fs.write `runs-later`: the hook asks; OS layers deny unless an allow rule matches".into(),
    ] {
        assert!(losses.contains(&expected), "{losses:#?}");
    }
    assert_eq!(losses.len(), 9, "{losses:#?}");
}

#[test]
fn ask_under_an_allow_default_becomes_a_deny_rule() {
    let ir = lowered(
        "version: 1\ndefaults: allow\nallow:\n  - id: a\n    fs.read: ['/x/**']\n\
         ask:\n  - id: q\n    fs.read: ['/x/secret']\n",
    );
    assert_eq!(ir.fs.read.default, Effect::Allow);
    assert_eq!(ids(&ir.fs.read.deny), ["q"]);
    let check = ir.checker().unwrap();
    assert_eq!(check.check(&read("/x/secret")), Some(Effect::Deny));
    assert_eq!(check.check(&read("/x/other")), Some(Effect::Allow));
    assert_eq!(ir.losses[0].rule, "q");
}

#[test]
fn net_rules_govern_fetch_with_their_own_exclusions() {
    let ir = lowered(
        "version: 1\ndefaults: deny\nallow:\n  - id: a\n    fetch: ['*.org', '!b.org']\n    net: ['b.org']\n",
    );
    assert_eq!(ir.egress.fetch.allow.len(), 2);
    let check = ir.checker().unwrap();
    let fetch = |host: &str| AtomicAction::Fetch { host: host.into() };
    assert_eq!(check.check(&fetch("B.org")), Some(Effect::Allow));
    assert_eq!(check.check(&fetch("a.org")), Some(Effect::Allow));
    let net = AtomicAction::Net {
        host: "a.org".into(),
    };
    assert_eq!(check.check(&net), Some(Effect::Deny));
}

#[test]
fn cloud_metadata_is_denied_even_when_allowed() {
    let ir = lowered("version: 1\ndefaults: allow\n");
    let check = ir.checker().unwrap();
    for host in ["169.254.169.254", "metadata.google.internal"] {
        for atom in [
            AtomicAction::Net { host: host.into() },
            AtomicAction::Fetch { host: host.into() },
        ] {
            assert_eq!(check.check(&atom), Some(Effect::Deny), "{atom:?}");
        }
    }
}

#[test]
fn builtin_metadata_hosts_match_the_default_policy() {
    let policy = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let group = policy.deny.iter().find(|g| g.id == "cloud-metadata");
    assert_eq!(
        group.map(|g| g.net.as_slice()),
        Some(&CLOUD_METADATA.map(String::from)[..])
    );
}

#[test]
fn project_rules_need_a_project_and_cover_every_spelling() {
    let yaml =
        "version: 1\nallow:\n  - id: p\n    fs.read: ['${project}/**', '!${project}/.git/**']\n";
    let policy = Policy::parse(yaml).unwrap();
    let none = lower(
        &policy,
        &EvalContext {
            project: None,
            ..ctx()
        },
    )
    .unwrap();
    assert!(none.fs.read.allow.is_empty());
    let linked = lower(
        &policy,
        &EvalContext {
            real_project: Some("/private/p".into()),
            ..ctx()
        },
    )
    .unwrap();
    assert_eq!(
        linked.fs.read.allow[0].patterns,
        [
            "/p/**",
            "/private/p/**",
            "!/p/.git/**",
            "!/private/p/.git/**"
        ]
    );
}

#[test]
fn decide_only_lists_rules_and_executables() {
    let ir = lowered(
        "version: 1\ndeny:\n  - id: s\n    shell: ['sudo *']\n    fs.read: ['/k']\n\
         executables:\n  git: ['/usr/bin/git']\n",
    );
    assert_eq!(
        ir.decide_only,
        [
            DecideOnly {
                kind: "shell".into(),
                rules: vec!["s".into()]
            },
            DecideOnly {
                kind: "executables".into(),
                rules: vec!["git".into()]
            },
        ]
    );
    assert_eq!(ir.checker().unwrap().check(&read("/k")), Some(Effect::Deny));
    let shell = AtomicAction::Shell {
        argv: vec!["sudo".into()],
    };
    assert_eq!(ir.checker().unwrap().check(&shell), None);
}

#[test]
fn lowering_is_deterministic_and_serialises_kinds_by_name() {
    let a = lowered(crate::DEFAULT_POLICY);
    assert_eq!(a, lowered(crate::DEFAULT_POLICY));
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains(r#""list":"fs.read""#), "{json}");
    assert!(json.contains(r#""default":"deny""#), "{json}");
    assert!(json.contains(r#""secrets":[]"#), "{json}");
}

#[test]
fn read_roots_are_an_allowance_that_deny_rules_still_beat() {
    let ir = lower(
        &Policy::parse(crate::DEFAULT_POLICY).unwrap(),
        &EvalContext {
            home: "/Users/me".into(),
            ..ctx()
        },
    )
    .unwrap();
    assert_eq!(ir.allowances.len(), 1);
    let roots = &ir.allowances[0];
    assert_eq!(
        (roots.kind, roots.rule.as_str()),
        (Kind::FsRead, READ_ROOTS_RULE)
    );
    for expected in ["/usr", "/usr/**", "/Users/me/.cargo", "/Users/me/.cargo/**"] {
        assert!(roots.patterns.contains(&expected.to_owned()), "{expected}");
    }
    assert!(
        !ids(&ir.fs.read.allow).contains(&READ_ROOTS_RULE),
        "the IR's own read verdicts stay the hook's"
    );
    let check = ir.checker().unwrap();
    let os = |path: &str| check.check_os(&read(path));
    let cargo = read("/Users/me/.cargo/registry/x");
    assert_eq!(check.check(&cargo), Some(Effect::Deny));
    assert_eq!(check.check_os(&cargo), Some(Effect::Allow));
    assert_eq!(os("/usr/bin/git"), Some(Effect::Allow));
    assert_eq!(os("/Users/me/.cargo/credentials.toml"), Some(Effect::Deny));
    assert_eq!(os("/Users/me/.cargo/registry/.env"), Some(Effect::Deny));
    assert_eq!(os("/Users/me/Documents/x"), Some(Effect::Deny));
    assert_eq!(os("/p/src/main.rs"), Some(Effect::Allow), "the project");
    let write = AtomicAction::FsWrite {
        path: "/usr/local/bin/x".into(),
    };
    assert_eq!(
        check.check_os(&write),
        Some(Effect::Deny),
        "writes stay out"
    );
}

#[test]
fn a_policy_without_read_roots_has_no_allowance() {
    assert!(lowered("version: 1\nsandbox: {}\n").allowances.is_empty());
    assert!(lowered("version: 1\n").allowances.is_empty());
}

/// #167: the policy's `secrets:` list lowers into `ir.secrets` field-for-field,
/// so OS backends (Claude Code's broker, `moat proxy`) read one source of truth.
#[test]
fn policy_secrets_lower_into_ir_secrets() {
    let ir = lowered(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com', 'registry.npmjs.org']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
         - id: npm\n    host: registry.npmjs.org\n    header: Authorization\n    source: { file: ~/.config/moat/npm }\n    plain_http: true\n",
    );
    assert_eq!(ir.secrets.len(), 2);
    assert_eq!(ir.secrets[0].id, "gh");
    assert_eq!(ir.secrets[0].host, "api.github.com");
    assert_eq!(ir.secrets[0].header, "Authorization");
    assert!(matches!(
        &ir.secrets[0].source,
        crate::SecretSource::Env(name) if name == "GITHUB_TOKEN"
    ));
    assert!(!ir.secrets[0].plain_http);
    assert_eq!(ir.secrets[1].id, "npm");
    assert!(matches!(
        &ir.secrets[1].source,
        crate::SecretSource::File(path) if path == "~/.config/moat/npm"
    ));
    assert!(ir.secrets[1].plain_http);
    assert!(
        lowered("version: 1\n").secrets.is_empty(),
        "no `secrets:` key means no entries"
    );
}
