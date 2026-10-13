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
}

#[test]
fn rejects_unknown_keys() {
    assert!(Policy::parse("version: 1\nbogus: 1\n").is_err());
}
