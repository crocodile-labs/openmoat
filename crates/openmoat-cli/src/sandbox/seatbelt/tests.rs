use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;
use crate::sandbox::assert_golden;

fn generated(yaml: &str, proxy_port: Option<u16>) -> Generated {
    let grants = Grants {
        proxy_port,
        tmpdir: Some("/private/var/folders/xy/T".into()),
        program: Some("/Users/me/.local/share/agent/1.0/agent".into()),
        writes: vec!["/Users/me/.agent".into()],
    };
    generated_with(yaml, &grants)
}

fn generated_with(yaml: &str, grants: &Grants) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: Some("/Users/me/proj".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/Users/me/proj".into(),
        case_insensitive_paths: true,
    };
    generate(
        &openmoat_core::ir::lower(&policy, &ctx).expect("lowers"),
        grants,
    )
}

/// The profile and report for the default policy, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_profile() {
    let out = generated(DEFAULT_POLICY, Some(18080));
    let losses = out
        .report
        .losses
        .iter()
        .map(|l| format!("; stricter: {l}\n"));
    let wider = out
        .report
        .allowances
        .iter()
        .map(|a| format!("; wider: {a}\n"));
    let text = out.profile + &losses.chain(wider).collect::<String>();
    assert_golden("seatbelt-default.sb", &text);
}

#[test]
fn deny_rules_come_after_every_allow_and_keep_their_exceptions() {
    let profile = generated(DEFAULT_POLICY, Some(18080)).profile;
    let first_deny = profile.find("(deny file-").expect("deny rules");
    let last_allow = profile.rfind("(allow file-").expect("allow rules");
    assert!(last_allow < first_deny, "{profile}");
    assert!(profile.contains("(subpath \"/Users/me/.ssh\")"));
    assert!(profile.contains("(literal \"/Users/me/.cargo/credentials.toml\")"));
    let not = profile.find("(require-not").expect("exceptions");
    let example = profile.find(r#"(regex "^(.*/)?\\.env\\.example$")"#);
    assert!(example.is_some_and(|at| at > not), "{profile}");
    assert!(
        profile.contains("(require-not (require-any\n      (subpath \"/Users/me/proj/.git\")"),
        "the project's .git stays unwritable"
    );
}

#[test]
fn the_keychain_is_never_reachable_and_the_proxy_is_the_only_exit() {
    let profile = generated(DEFAULT_POLICY, Some(18080)).profile;
    assert!(profile.contains("(deny mach-lookup\n  (global-name \"com.apple.SecurityServer\")"));
    let deny = profile.find("com.apple.SecurityServer").unwrap_or_default();
    assert_eq!(profile.rfind("com.apple.SecurityServer"), Some(deny));
    for absent in ["dnssd", "trustd", "(allow network*", "(remote ip \"*"] {
        assert!(!profile.contains(absent), "{absent}");
    }
    assert!(profile.ends_with("(allow network-outbound (remote ip \"localhost:18080\"))\n"));
    let closed = generated(DEFAULT_POLICY, None).profile;
    assert!(!closed.contains("network-outbound"), "{closed}");
}

#[test]
fn losses_and_allowances_are_listed() {
    let report = generated(DEFAULT_POLICY, None).report;
    let losses: Vec<String> = report.losses.iter().map(ToString::to_string).collect();
    assert_eq!(losses.len(), 1, "{losses:?}");
    assert!(losses[0].starts_with("net `registries`: "), "{losses:?}");
    let rules: Vec<String> = report
        .allowances
        .iter()
        .map(|a| format!("{} {}", a.kind, a.rule))
        .collect();
    for rule in [
        "fs.read seatbelt.metadata",
        "fs.read seatbelt.platform",
        "fs.write seatbelt.platform",
        "fs.read sandbox.read_roots",
        "fs.write seatbelt.tmpdir",
        "fs.read seatbelt.case",
        "fs.read seatbelt.program",
        "fs.write seatbelt.write",
    ] {
        assert!(rules.contains(&rule.to_owned()), "{rule}: {rules:?}");
    }
}

#[test]
fn run_grants_open_the_program_and_the_written_paths_but_deny_rules_win() {
    let profile = generated(DEFAULT_POLICY, None).profile;
    let program = r#"(allow file-read*
  (literal "/Users/me/.local/share/agent/1.0/agent"))"#;
    let write = profile
        .find("(subpath \"/Users/me/.agent\")")
        .expect("--write");
    assert!(profile.contains(program), "{profile}");
    assert!(write < profile.find("(deny file-").unwrap_or_default());
    let bare = generated_with(DEFAULT_POLICY, &Grants::default());
    for absent in ["seatbelt.program", "seatbelt.write", "seatbelt.tmpdir"] {
        assert!(!bare.profile.contains(absent), "{absent}");
    }
}

#[test]
fn an_allow_default_opens_the_whole_access() {
    let out = generated(
        "version: 1\ndefaults:\n  fs.write: allow\n  net: allow\n",
        None,
    );
    assert!(out.profile.contains("; default\n(allow file-write*)\n"));
    assert!(!out.profile.contains("; default\n(allow file-read*)"));
    assert!(
        out.report.losses.iter().any(|l| l.rule == "default.net"),
        "{:?}",
        out.report.losses
    );
}

#[test]
fn globs_become_anchored_regexes_with_the_engine_semantics() {
    for (glob, re) in [
        ("**/.env", r"^(.*/)?\.env$"),
        ("**/.moat/**", r"^(.*/)?\.moat(/.*)?$"),
        ("/h/**/x/*.txt", r"^/h/(.*/)?x/[^/]*\.txt$"),
        ("**", "^.*$"),
        ("/a/b?{c,d}", r"^/a/b[^/](c|d)$"),
        ("/dev/ttys[0-9]*", "^/dev/ttys[0-9][^/]*$"),
        ("/x/[!a]", "^/x/[^/a]$"),
        ("/x/[a", r"^/x/\[a$"),
        ("/x/a**b", "^/x/a[^/]*[^/]*b$"),
        (r"/x/\*", r"^/x/\*$"),
    ] {
        assert_eq!(regex(glob), re, "{glob}");
    }
    assert_eq!(filter("/h/.ssh/**"), "(subpath \"/h/.ssh\")");
    assert_eq!(filter("/h/.netrc"), "(literal \"/h/.netrc\")");
    assert_eq!(filter("/h/a\"b"), r#"(literal "/h/a\"b")"#);
    assert_eq!(filter("**/.env"), r#"(regex "^(.*/)?\\.env$")"#);
}

/// `**` inside braces is recursive in the engine, so each brace alternative
/// is translated on its own: `~/{.ssh/**,.aws/**}` covers both trees.
#[test]
fn braces_are_expanded_before_translating() {
    let owned = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        alternatives("/h/{.ssh/**,.aws/**}"),
        owned(&["/h/.ssh/**", "/h/.aws/**"])
    );
    assert_eq!(
        alternatives("/a/{b,{c,d}e}/f"),
        owned(&["/a/b/f", "/a/ce/f", "/a/de/f"])
    );
    assert_eq!(
        alternatives("!/p/{x,y}/**"),
        owned(&["!/p/x/**", "!/p/y/**"])
    );
    assert_eq!(
        alternatives("/a/{b"),
        owned(&["/a/{b"]),
        "unclosed: as written"
    );
    assert_eq!(
        alternatives(r"/a/\{b,c}"),
        owned(&[r"/a/\{b,c}"]),
        "escaped"
    );
    let wide = "/{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}";
    assert_eq!(
        alternatives(wide),
        owned(&[wide]),
        "past the bound: as written"
    );

    let mut profile = String::new();
    rule(
        &mut profile,
        "deny keys",
        "deny file-read-data",
        &["/h/{.ssh/**,.aws/**}".to_owned()],
    );
    assert!(profile.contains("(subpath \"/h/.ssh\")"), "{profile}");
    assert!(profile.contains("(subpath \"/h/.aws\")"), "{profile}");
}

/// A pattern under a symlinked directory is also written where the link
/// points, as Seatbelt compares the path the kernel opens.
#[cfg(target_os = "macos")]
#[test]
fn a_pattern_under_a_symlinked_directory_gets_its_real_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let real = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir(real.join("target")).unwrap();
    std::os::unix::fs::symlink(real.join("target"), real.join("link")).unwrap();
    let real = real.to_str().unwrap();
    assert_eq!(
        through_links(&format!("{real}/link/keys/**")),
        Some(format!("{real}/target/keys/**"))
    );
    assert_eq!(
        through_links(&format!("!{real}/link/*.pem")),
        Some(format!("!{real}/target/*.pem"))
    );
    assert_eq!(through_links(&format!("{real}/target/x")), None, "no link");
    assert_eq!(through_links("**/.env"), None, "not absolute");
}
