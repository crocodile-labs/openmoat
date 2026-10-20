use super::*;

#[test]
fn parses_minimal() {
    let p = Policy::parse("version: 1\ndeny:\n  - id: a\n    shell: ['sudo *']\n").unwrap();
    assert_eq!(p.defaults, Defaults::All(Verdict::Ask));
    assert_eq!(p.rule_count(), (1, 0, 0));
}

#[test]
fn rejects_duplicate_and_empty() {
    let dup = "version: 1\ndeny:\n  - id: a\n    shell: ['x']\nallow:\n  - id: a\n    net: ['h']\n";
    assert!(matches!(
        Policy::parse(dup),
        Err(PolicyError::DuplicateId(_))
    ));
    let empty = "version: 1\ndeny:\n  - id: a\n";
    assert!(matches!(
        Policy::parse(empty),
        Err(PolicyError::EmptyRule(_))
    ));
    let ver = "version: 2\n";
    assert!(matches!(
        Policy::parse(ver),
        Err(PolicyError::Version { .. })
    ));
}

#[test]
fn per_kind_defaults() {
    let p = Policy::parse("version: 1\ndefaults: { net: deny, '*': ask }\n").unwrap();
    assert_eq!(
        p.defaults.for_kind(Kind::Net),
        (Verdict::Deny, "default.net".to_owned())
    );
    assert_eq!(
        p.defaults.for_kind(Kind::Shell),
        (Verdict::Ask, "default".to_owned())
    );
}

#[test]
fn fetch_defaults_fall_back_to_net_then_star() {
    let own = Policy::parse("version: 1\ndefaults: { net: deny, fetch: ask }\n").unwrap();
    assert_eq!(
        own.defaults.for_kind(Kind::Fetch),
        (Verdict::Ask, "default.fetch".to_owned())
    );
    assert_eq!(
        own.defaults.for_kind(Kind::Net),
        (Verdict::Deny, "default.net".to_owned())
    );
    let net = Policy::parse("version: 1\ndefaults: { net: deny, '*': allow }\n").unwrap();
    assert_eq!(
        net.defaults.for_kind(Kind::Fetch),
        (Verdict::Deny, "default.net".to_owned())
    );
    let star = Policy::parse("version: 1\ndefaults: { '*': allow }\n").unwrap();
    assert_eq!(
        star.defaults.for_kind(Kind::Fetch),
        (Verdict::Allow, "default".to_owned())
    );
}

#[test]
fn executables_must_be_absolute_on_every_platform() {
    let ok =
        "version: 1\nexecutables:\n  git: ['/usr/bin/git', 'C:/Program Files/Git/bin/git.exe']\n";
    assert!(Policy::parse(ok).is_ok());
    let rel = "version: 1\nexecutables:\n  git: ['bin/git']\n";
    assert!(matches!(Policy::parse(rel), Err(PolicyError::Rule { .. })));
}

#[test]
fn read_roots_must_be_plain_paths_below_a_root() {
    let ok = "version: 1\nsandbox:\n  read_roots: ['/usr', '~/.cargo', 'C:/tools']\n";
    assert!(Policy::parse(ok).is_ok());
    for bad in [
        "usr",
        "~",
        "~/",
        "/",
        "C:/",
        "/usr/**",
        "~/../x",
        "${project}/x",
        "!/usr",
    ] {
        let yaml = format!("version: 1\nsandbox:\n  read_roots: ['{bad}']\n");
        assert!(
            matches!(Policy::parse(&yaml), Err(PolicyError::Rule { rule, .. }) if rule == "sandbox.read_roots"),
            "{bad} must be rejected"
        );
    }
    assert!(Policy::parse("version: 1\nsandbox: { bogus: 1 }\n").is_err());
    assert!(Policy::parse("version: 1\nsandbox: { proxy_port: 18081 }\n").is_ok());
    assert!(Policy::parse("version: 1\nsandbox: { proxy_port: 0 }\n").is_err());
    let ech = Policy::parse("version: 1\nsandbox: { proxy_allow_ech: true }\n").unwrap();
    assert!(ech.sandbox.is_some_and(|s| s.proxy_allow_ech));
    let default = Policy::parse("version: 1\nsandbox: { proxy_port: 18081 }\n").unwrap();
    assert!(default.sandbox.is_some_and(|s| !s.proxy_allow_ech));
}

#[test]
fn package_release_age_defaults_to_seven_days_and_zero_turns_it_off() {
    let age = |yaml: &str| Policy::parse(yaml).unwrap().package_min_release_age_days();
    assert_eq!(age("version: 1\n"), 7);
    assert_eq!(age("version: 1\nsandbox: { proxy_port: 18081 }\n"), 7);
    assert_eq!(
        age("version: 1\nsandbox: { package_min_release_age_days: 0 }\n"),
        0
    );
    assert_eq!(
        age("version: 1\nsandbox: { package_min_release_age_days: 14 }\n"),
        14
    );
    assert_eq!(
        Policy::parse(crate::DEFAULT_POLICY)
            .unwrap()
            .package_min_release_age_days(),
        7
    );
    assert!(Policy::parse("version: 1\nsandbox: { package_min_release_age_days: -1 }\n").is_err());
}

#[test]
fn signed_repository_policies_are_trusted_only_when_asked_for() {
    assert!(
        !Policy::parse("version: 1\n")
            .unwrap()
            .require_signed_repo_policy
    );
    let on = Policy::parse("version: 1\nrequire_signed_repo_policy: true\n").unwrap();
    assert!(on.require_signed_repo_policy);
    assert!(Policy::parse("version: 1\nrequire_signed_repo_policy: 1\n").is_err());
}

#[test]
fn mcp_first_sight_is_held_unless_the_policy_trusts_it() {
    assert!(
        !Policy::parse("version: 1\n")
            .unwrap()
            .trust_mcp_first_sight()
    );
    let off = Policy::parse("version: 1\nmcp: {}\n").unwrap();
    assert!(!off.trust_mcp_first_sight());
    let on = Policy::parse("version: 1\nmcp: { trust_first_sight: true }\n").unwrap();
    assert!(on.trust_mcp_first_sight());
    assert!(Policy::parse("version: 1\nmcp: { bogus: true }\n").is_err());
}

#[test]
fn hook_only_is_for_deny_groups_that_name_files() {
    let group = |list: &str, body: &str| {
        Policy::parse(&format!(
            "version: 1\n{list}:\n  - id: b\n    hook_only: true\n{body}"
        ))
    };
    let ok = group(
        "deny",
        "    fs.read: ['~/.m2/settings.xml']\n    shell: ['x']\n",
    )
    .unwrap();
    assert!(ok.deny[0].hook_only);
    assert!(!Policy::parse(crate::DEFAULT_POLICY).unwrap().deny[0].hook_only);
    let problem = |list: &str, body: &str| match group(list, body) {
        Err(PolicyError::Rule { rule, problem }) if rule == "b" => problem,
        other => panic!("{list}: {other:?}"),
    };
    for list in ["allow", "ask", "defer"] {
        let message = problem(list, "    fs.read: ['/x']\n");
        assert!(message.contains("`deny` groups only"), "{message}");
    }
    let net = problem("deny", "    fs.read: ['/x']\n    net: ['evil.example']\n");
    assert!(net.contains("`net` or `fetch`"), "{net}");
    let fetch = problem(
        "deny",
        "    fs.write: ['/x']\n    fetch: ['evil.example']\n",
    );
    assert!(fetch.contains("`net` or `fetch`"), "{fetch}");
    let files = problem("deny", "    shell: ['x']\n");
    assert!(files.contains("needs `fs.read` or `fs.write`"), "{files}");
    // Written out only when set, so other policies serialise as before.
    let yaml = serde_json::to_string(&Policy::parse(crate::DEFAULT_POLICY).unwrap()).unwrap();
    assert_eq!(yaml.matches("hook_only").count(), 1, "{yaml}");
}

#[test]
fn rejects_unknown_keys() {
    assert!(Policy::parse("version: 1\nbogus: 1\n").is_err());
}
