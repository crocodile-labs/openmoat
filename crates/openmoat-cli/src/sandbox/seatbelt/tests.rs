use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::filter::regex;
use super::*;
use crate::sandbox::assert_golden;

fn session(proxy_port: Option<u16>) -> Grants {
    Grants {
        proxy_port,
        tmpdir: Some("/private/var/folders/xy/T".into()),
        program: Some("/Users/me/.local/share/agent/1.0/agent".into()),
        writes: vec!["/Users/me/.agent".into()],
        terminals: vec!["/dev/ttys003".into()],
        trust: None,
    }
}

/// On a case-sensitive disk, where every filter is written as the policy
/// spells it.
fn generated(yaml: &str, proxy_port: Option<u16>) -> Generated {
    generated_on(yaml, &session(proxy_port), false)
}

fn generated_with(yaml: &str, grants: &Grants) -> Generated {
    generated_on(yaml, grants, false)
}

fn generated_on(yaml: &str, grants: &Grants, case_insensitive_paths: bool) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: Some("/Users/me/proj".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/Users/me/proj".into(),
        case_insensitive_paths,
    };
    generate(
        &openmoat_core::ir::lower(&policy, &ctx).expect("lowers"),
        grants,
    )
}

/// The profile and report for the default policy on macOS's usual
/// case-insensitive disk, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_profile() {
    let out = generated_on(DEFAULT_POLICY, &session(Some(18080)), true);
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

/// ADR-028: the hooks' decisions come over the proxy's port, so the profile
/// has one way out and no Unix socket at all, and the golden is unchanged.
#[test]
fn the_hook_relay_adds_no_rule() {
    let profile = generated(DEFAULT_POLICY, Some(18080)).profile;
    assert_eq!(profile.matches("network-outbound").count(), 1, "{profile}");
    for absent in [
        "unix-socket",
        "network-bind",
        "network-inbound",
        "path-literal",
    ] {
        assert!(!profile.contains(absent), "{absent}");
    }
}

#[test]
fn losses_and_allowances_are_listed() {
    let report = generated(DEFAULT_POLICY, None).report;
    let losses: Vec<String> = report.losses.iter().map(ToString::to_string).collect();
    assert_eq!(losses.len(), 2, "{losses:?}");
    assert!(
        losses[0].starts_with("fs.write `seatbelt.agent-config`: "),
        "{losses:?}"
    );
    assert!(losses[1].starts_with("net `registries`: "), "{losses:?}");
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
        "fs.read seatbelt.program",
        "fs.write seatbelt.write",
        "fs.write seatbelt.terminal",
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
        assert_eq!(regex(glob, Case::Exact), re, "{glob}");
    }
    assert_eq!(filter("/h/.ssh/**", Case::Exact), "(subpath \"/h/.ssh\")");
    assert_eq!(filter("/h/.netrc", Case::Exact), "(literal \"/h/.netrc\")");
    assert_eq!(filter("/h/a\"b", Case::Exact), r#"(literal "/h/a\"b")"#);
    assert_eq!(
        filter("**/.env", Case::Exact),
        r#"(regex "^(.*/)?\\.env$")"#
    );
}

/// Folded, every letter matches in either case, literal and subtree filters
/// included, and a character class gets its members in the other case too.
#[test]
fn folded_globs_match_letters_in_either_case() {
    for (glob, re) in [
        ("/h/.ssh/**", r"^/[hH]/\.[sS][sS][hH](/.*)?$"),
        ("/h/.netrc", r"^/[hH]/\.[nN][eE][tT][rR][cC]$"),
        ("**/.env*", r"^(.*/)?\.[eE][nN][vV][^/]*$"),
        ("/x/[a-c1]", "^/[xX]/[a-c1A-C1]$"),
        ("/x/[!a]", "^/[xX]/[^/aA]$"),
        ("/x/[0-9]", "^/[xX]/[0-9]$"),
    ] {
        assert_eq!(regex(glob, Case::Folded), re, "{glob}");
    }
    assert_eq!(
        filter("/h/.ssh/**", Case::Folded),
        r#"(regex "^/[hH]/\\.[sS][sS][hH](/.*)?$")"#
    );
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
        Case::Exact,
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

/// The terminal the run was started on and `/dev/tty` are open; no other
/// terminal of the person's is, and without one only `/dev/tty` is.
#[test]
fn only_the_runs_own_terminal_is_granted() {
    let profile = generated(DEFAULT_POLICY, None).profile;
    let granted = "; seatbelt.terminal\n(allow file-read* file-write-data\n  \
                   (literal \"/dev/ttys003\"))\n";
    assert!(profile.contains(granted), "{profile}");
    assert!(profile.contains("(literal \"/dev/tty\")"));
    assert!(!profile.contains("ttys[0-9]"), "{profile}");
    assert_eq!(profile.matches("/dev/ttys").count(), 1, "{profile}");
    let bare = generated_with(DEFAULT_POLICY, &Grants::default()).profile;
    assert!(!bare.contains("/dev/ttys"), "{bare}");
    assert!(bare.contains("(literal \"/dev/tty\")"));
}

/// An agent's own configuration in the project is left out of the project's
/// write grant and denied after every grant, so a `--write` or temp directory
/// grant cannot re-open it; CI files and commit-hook managers' files stay
/// writable (an install runs `husky`).
#[test]
fn agent_configuration_in_the_project_is_never_writable() {
    let out = generated(DEFAULT_POLICY, None);
    let profile = &out.profile;
    let deny = profile
        .find("; deny seatbelt.agent-config (fs.write)\n(deny file-write*")
        .expect("the agent configuration is denied");
    assert!(deny > profile.rfind("(allow file-").unwrap_or_default());
    let denied = &profile[deny..];
    for re in [
        r#"(regex "^/Users/me/proj/(.*/)?\\.claude/hooks(/.*)?$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.mcp\\.json$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.cursor/mcp\\.json$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.codex/config\\.toml$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.github/hooks(/.*)?$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.github/mcp\\.json$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.openclaw/extensions(/.*)?$")"#,
        r#"(regex "^/Users/me/proj/(.*/)?\\.pi/settings\\.json$")"#,
    ] {
        assert!(denied.contains(re), "{re}: {profile}");
    }
    for ci in [".husky", ".github/workflows", "lefthook"] {
        let escaped = ci.replace('.', "\\\\.");
        assert!(
            !profile.contains(&escaped),
            "{ci} stays writable: {profile}"
        );
    }
    let wider = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "seatbelt.runs-later");
    let wider = &wider.expect("CI files stay listed").patterns;
    assert!(wider.contains(&"**/.husky/**".to_owned()), "{wider:?}");
    assert!(!wider.contains(&"**/.mcp.json".to_owned()), "{wider:?}");
    let loss = out
        .report
        .losses
        .iter()
        .find(|l| l.rule == "seatbelt.agent-config");
    assert!(
        loss.is_some_and(|l| l.message.contains("outside `openmoat run`")),
        "{:?}",
        out.report.losses
    );
}

/// The project's `.claude`, `.codex`, `.cursor`, `.copilot` and `.gemini`
/// themselves cannot be written: not renamed away, removed, or replaced by a
/// directory moved into their place, while what is inside stays as the rules
/// say.
#[test]
fn another_agents_directory_cannot_be_moved_or_replaced() {
    let profile = generated(DEFAULT_POLICY, None).profile;
    let kernel = profile
        .find("; deny kernel-self (fs.write)\n(deny file-write*")
        .expect("kernel-self write denies");
    let denied = &profile[kernel..];
    for name in ["claude", "codex", "cursor", "copilot", "gemini"] {
        let node = format!("(regex \"^(.*/)?\\\\.{name}$\")");
        assert!(denied.contains(&node), "{node}: {profile}");
    }
}

/// Whether a `(regex …)` filter of the rule that `comment` starts matches
/// `path`, as Seatbelt reads the profile.
fn rule_matches(profile: &str, comment: &str, path: &str) -> bool {
    let start = profile.find(comment).expect("the rule is there");
    let body = &profile[start + comment.len()..];
    let body = &body[..body.find("\n; ").unwrap_or(body.len())];
    body.split("(regex \"").skip(1).any(|rest| {
        let quoted = &rest[..rest.find("\")").expect("a closed regex")];
        let re = regex::Regex::new(&quoted.replace("\\\\", "\\")).expect("a valid regex");
        re.is_match(path)
    })
}

/// The folders above an agent's configuration directly in the project cannot
/// be created, renamed or removed: moving `.github` away and back would carry
/// a hook written under another name past the deny. Files inside them that
/// are not agent configuration stay as the rules say, and so does a nested
/// `.github`, which packages bring into `node_modules`.
#[test]
fn the_folders_above_agent_configuration_cannot_be_moved() {
    let profile = generated(DEFAULT_POLICY, None).profile;
    let rule = "; deny seatbelt.agent-config (fs.write)\n";
    for folder in [
        ".github",
        ".pi",
        ".openclaw",
        ".claude",
        ".cursor",
        ".codex",
    ] {
        let path = format!("/Users/me/proj/{folder}");
        assert!(
            profile.contains(&format!("(literal \"{path}\")")),
            "{path}: {profile}"
        );
    }
    let open = [
        ".github/workflows/ci.yml",
        ".github/workflows",
        ".pi2",
        "src/a.rs",
        "node_modules/qs/.github",
    ];
    for open in open {
        let path = format!("/Users/me/proj/{open}");
        assert!(!rule_matches(&profile, rule, &path), "{path}: {profile}");
    }
}

/// On a case-insensitive disk a file or folder created in another case than
/// a deny names is still denied: `.MCP.JSON` is the `.mcp.json` the agent
/// loads, `.CLAUDE` its `.claude`. The exceptions of a deny stay as written.
#[test]
fn denies_match_either_case_on_a_case_insensitive_disk() {
    let profile = generated_on(DEFAULT_POLICY, &session(None), true).profile;
    let agent = "; deny seatbelt.agent-config (fs.write)\n";
    for path in [
        ".MCP.JSON",
        ".GitHub",
        ".Claude/Hooks/x.sh",
        "a/.PI/settings.json",
    ] {
        let path = format!("/Users/me/proj/{path}");
        assert!(rule_matches(&profile, agent, &path), "{path}: {profile}");
    }
    let kernel = "; deny kernel-self (fs.write)\n";
    for path in [
        "/Users/me/proj/.CLAUDE",
        "/Users/me/.Claude/Settings.JSON",
        "/Users/Me/.MOAT/x",
    ] {
        assert!(rule_matches(&profile, kernel, path), "{path}: {profile}");
    }
    assert!(
        !profile.contains("(subpath \"/Users/me/.ssh\")"),
        "a read deny is folded too: {profile}"
    );
    assert!(
        profile.contains("(require-not (require-any\n      (subpath \"/Users/me/proj/.git\")"),
        "an allow's exceptions stay as written"
    );
    let exact = generated(DEFAULT_POLICY, None).profile;
    assert!(
        !rule_matches(&exact, agent, "/Users/me/proj/.MCP.JSON"),
        "{exact}"
    );
}
