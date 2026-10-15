use openmoat_core::{DEFAULT_POLICY, Policy};
use toml_edit::DocumentMut;

use super::*;
use crate::sandbox::{assert_golden, lower_for_hosts};

pub(super) fn generated(yaml: &str) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    // The test home does not exist: name its one file, as on a real machine.
    generate_with(
        &ir,
        &["/Users/me".into()],
        crate::sandbox::proxy_port(&policy),
        |path| path == "/Users/me/.gitconfig",
    )
    .expect("generates")
}

fn mode<'a>(generated: &'a Generated, table: &[&str], key: &str) -> Option<&'a str> {
    let mut item = &generated.profile["filesystem"];
    for name in table {
        item = &item[name];
    }
    item.get(key)?.as_str()
}

/// The whole `config.toml` OpenMoat writes into an empty file, then the report.
fn render(generated: &Generated) -> String {
    let mut doc = DocumentMut::new();
    apply(&mut doc, generated).unwrap();
    let losses = generated
        .report
        .losses
        .iter()
        .map(|l| format!("# stricter: {l}\n"));
    let wider = generated
        .report
        .allowances
        .iter()
        .map(|a| format!("# wider: {a}\n"));
    doc.to_string() + &losses.chain(wider).collect::<String>()
}

/// The profile and report for the default policy, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_profile() {
    assert_golden("codex-default.toml", &render(&generated(DEFAULT_POLICY)));
}

#[test]
fn reads_are_granted_exactly_and_secrets_win() {
    let out = generated(DEFAULT_POLICY);
    assert_eq!(mode(&out, &[], ":minimal"), Some("read"));
    assert_eq!(mode(&out, &[], "/Users/me/.cargo"), Some("read"));
    assert_eq!(mode(&out, &[], "/Users/me/.ssh"), Some("deny"));
    assert_eq!(
        mode(&out, &[], "/Users/me/.cargo/credentials.toml"),
        Some("deny")
    );
    assert_eq!(
        mode(&out, &[], "/Users/me/.cargo/**/.env"),
        Some("deny"),
        "**/ below a root"
    );
    assert_eq!(mode(&out, &[], "/Users/me/.gitconfig"), Some("read"));
    assert_eq!(
        mode(&out, &[], "/Users/me/.gitconfig/**/.env"),
        None,
        "a file root has nothing below it"
    );
    for system in ["/usr/**/.env", "/etc/**/.env", "/tmp/**/.env.*"] {
        assert_eq!(
            mode(&out, &[], system),
            None,
            "{system}: Codex on Linux cannot list root-only directories"
        );
    }
    assert!(
        out.profile.get("extends").is_none(),
        ":workspace reads the whole disk"
    );
    let ws = [":workspace_roots"];
    assert_eq!(mode(&out, &ws, "."), Some("write"));
    assert_eq!(mode(&out, &ws, "**/.env"), Some("deny"));
    assert_eq!(
        mode(&out, &ws, ".git"),
        Some("read"),
        "an allow exclusion is read-only"
    );
    assert_eq!(
        mode(&out, &ws, "**/.git/**"),
        None,
        "a nested `.git` glob could only deny, which would hide every repository"
    );
    assert_eq!(mode(&out, &ws, ".moat"), Some("read"));
    assert_eq!(mode(&out, &ws, "**/.claude/settings.json"), Some("deny"));
    assert_eq!(
        mode(&out, &ws, "**/.claude"),
        None,
        "directory node left out"
    );
    assert_eq!(mode(&out, &[], ":tmpdir"), Some("write"));
}

#[test]
fn losses_name_the_exceptions_and_git() {
    let out = generated(DEFAULT_POLICY);
    let losses: Vec<String> = out.report.losses.iter().map(ToString::to_string).collect();
    assert!(
        losses
            .iter()
            .any(|l| l.contains("**/.env.example") && l.contains("re-allow"))
    );
    assert!(losses.iter().any(|l| l.contains("`.git` read-only")));
    let rules: Vec<&str> = out
        .report
        .allowances
        .iter()
        .map(|a| a.rule.as_str())
        .collect();
    for rule in [
        "codex.minimal",
        "sandbox.read_roots",
        "codex.tmpdir",
        "codex.directory-nodes",
        "codex.outside-home",
        "codex.nested-git",
    ] {
        assert!(rules.contains(&rule), "{rule}: {rules:?}");
    }
}

#[test]
fn deny_globs_are_repeated_only_below_roots_in_the_home() {
    let out = generated(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['**/.env']\n\
         sandbox:\n  read_roots: ['/etc', '/Users/me', '~/.cargo']\n",
    );
    assert_eq!(mode(&out, &[], "/etc"), Some("read"));
    assert_eq!(mode(&out, &[], "/etc/**/.env"), None);
    assert_eq!(mode(&out, &[], "/Users/me/**/.env"), Some("deny"));
    assert_eq!(mode(&out, &[], "/Users/me/.cargo/**/.env"), Some("deny"));
    assert_eq!(mode(&out, &[":workspace_roots"], "**/.env"), Some("deny"));
    let outside = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "codex.outside-home");
    assert_eq!(
        outside.map(|a| a.patterns.clone()),
        Some(vec!["/etc".into()])
    );

    let quiet = generated("version: 1\nsandbox:\n  read_roots: ['/etc']\n");
    assert!(
        !quiet
            .report
            .allowances
            .iter()
            .any(|a| a.rule == "codex.outside-home"),
        "nothing to repeat, nothing reported"
    );
}

#[test]
fn linux_denies_each_glob_name_directly_in_the_workspace_roots() {
    let mut out = generated(DEFAULT_POLICY);
    deny_names(&mut out);
    let ws = [":workspace_roots"];
    assert_eq!(mode(&out, &ws, ".env"), Some("deny"));
    assert_eq!(mode(&out, &ws, ".envrc"), Some("deny"));
    assert_eq!(
        mode(&out, &ws, ".moat"),
        Some("read"),
        "`.moat/**` is a tree"
    );
    assert_eq!(
        mode(&out, &ws, "bin"),
        None,
        "a missing bin must stay creatable"
    );
    assert_eq!(mode(&out, &ws, ".env.*"), None);
    // `.claude` itself is a write deny, so a missing one may be mounted over:
    // a command cannot create the settings file Claude Code would load (#421).
    // One entry per directory: two below a missing one break bubblewrap.
    assert_eq!(mode(&out, &ws, ".claude"), Some("read"));
    assert_eq!(mode(&out, &ws, ".cursor"), Some("read"));
    for file in [".claude/settings.local.json", ".cursor/hooks.json"] {
        assert_eq!(mode(&out, &ws, file), None, "{file}");
    }
    assert_eq!(
        mode(&out, &ws, ".codex"),
        None,
        "Codex keeps `.codex` read-only itself"
    );
    assert_eq!(mode(&out, &ws, "bin/moat"), None, "`bin` is no write deny");
    assert!(
        out.report
            .losses
            .iter()
            .any(|l| l.rule == "codex.linux-agent-dirs"),
        "the read-only directories are reported"
    );
    let globs = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "codex.linux-write-globs")
        .map(|a| a.patterns.clone())
        .unwrap_or_default();
    assert!(globs.contains(&"**/.env.*".to_owned()), "{globs:?}");
    assert!(globs.contains(&"**/bin/moat".to_owned()), "{globs:?}");

    let mut quiet = generated("version: 1\n");
    deny_names(&mut quiet);
    assert!(
        !quiet
            .report
            .allowances
            .iter()
            .any(|a| a.rule == "codex.linux-write-globs"),
        "no glob, nothing reported"
    );
}

#[test]
fn network_lists_domains_and_keeps_addresses_unlisted() {
    let out = generated(DEFAULT_POLICY);
    let net = &out.profile["network"];
    assert_eq!(net["enabled"].as_bool(), Some(true));
    assert_eq!(net["domains"]["github.com"].as_str(), Some("allow"));
    assert_eq!(
        net["domains"]["metadata.google.internal"].as_str(),
        Some("deny")
    );
    assert!(
        net["domains"].get("localhost").is_none(),
        "an ask is a deny"
    );
    let text = render(&out);
    assert!(!text.contains("169.254"), "{text}");
}

#[test]
fn the_profile_hands_traffic_to_moat_proxy_and_weakening_it_is_reported() {
    let own = generated(DEFAULT_POLICY);
    assert!(own.profile["network"].get("allow_upstream_proxy").is_none());
    assert_eq!(
        own.profile["network"]["allow_local_binding"].as_bool(),
        Some(false)
    );
    assert!(
        !own.report
            .allowances
            .iter()
            .any(|a| a.rule == "codex.upstream")
    );

    let out = generated("version: 1\nsandbox:\n  proxy_port: 18555\n");
    let net = &out.profile["network"];
    assert_eq!(net["allow_upstream_proxy"].as_bool(), Some(true));
    assert_eq!(net["allow_local_binding"].as_bool(), Some(false));
    let upstream = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "codex.upstream");
    assert!(upstream.is_some_and(|a| a.message.contains("http://127.0.0.1:18555")));

    let mut doc = DocumentMut::new();
    apply(&mut doc, &out).unwrap();
    assert!(
        weaknesses(&doc, true).is_empty(),
        "{:?}",
        weaknesses(&doc, true)
    );
    let net = &mut doc["permissions"][PROFILE]["network"];
    net["allow_upstream_proxy"] = toml_edit::value(false);
    net["allow_local_binding"] = toml_edit::value(true);
    let found = weaknesses(&doc, true).join("\n");
    for key in ["allow_upstream_proxy", "allow_local_binding"] {
        assert!(found.contains(key), "{key}: {found}");
    }
    assert!(!in_sync(&doc, &out));
}

#[test]
fn a_write_grant_needs_the_read_and_a_root_inside_a_deny_is_refused() {
    let out = generated(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.ssh/**']\n\
         allow:\n  - id: w\n    fs.write: ['/srv/out/**']\n\
         sandbox:\n  read_roots: ['~/.ssh/pub', '/usr']\n",
    );
    assert_eq!(mode(&out, &[], "/usr"), Some("read"));
    assert_eq!(mode(&out, &[], "/Users/me/.ssh/pub"), None);
    assert_eq!(
        mode(&out, &[], "/srv/out"),
        None,
        "write would grant reads the IR denies"
    );
    let losses: Vec<String> = out.report.losses.iter().map(ToString::to_string).collect();
    assert!(
        losses.iter().any(|l| l.contains("/srv/out/**")),
        "{losses:?}"
    );
}

/// The `moat` binary's paths are kept from writes without opening a read the
/// policy closes: read-only where readable, denied elsewhere.
#[test]
fn read_only_never_grants_a_read_the_policy_denies() {
    let mut out = generated(DEFAULT_POLICY);
    let paths = ["/data/t/moatd".to_owned(), "/srv/t".to_owned()];
    read_only(&mut out, &paths, |p| p.starts_with("/data/"));
    assert_eq!(mode(&out, &[], "/data/t/moatd"), Some("read"));
    assert_eq!(mode(&out, &[], "/srv/t"), Some("deny"));
}

/// Codex on Linux masks a denied directory with a read-only tmpfs, so a file
/// entry inside it would fail every command; the directory's entry covers it.
#[test]
fn read_only_leaves_out_a_path_its_listed_directory_covers() {
    let mut out = generated(DEFAULT_POLICY);
    let paths = [
        "/srv/t/moat".to_owned(),
        "/srv/t".to_owned(),
        "/data/t/moat".to_owned(),
        "/data/t".to_owned(),
        "/Users/me/.cargo/bin/moat".to_owned(),
        "/Users/me/.cargo/bin".to_owned(),
    ];
    read_only(&mut out, &paths, |p| p == "/data/t");
    assert_eq!(mode(&out, &[], "/srv/t"), Some("deny"));
    assert_eq!(mode(&out, &[], "/srv/t/moat"), None);
    assert_eq!(mode(&out, &[], "/data/t"), Some("read"));
    assert_eq!(mode(&out, &[], "/data/t/moat"), Some("deny"));
    // `~/.cargo` is a read root already: read-only, nothing to add.
    let mut out = generated(DEFAULT_POLICY);
    read_only(&mut out, &paths[4..], |p| p.starts_with("/Users/me/.cargo"));
    assert_eq!(mode(&out, &[], "/Users/me/.cargo/bin"), None);
    assert_eq!(mode(&out, &[], "/Users/me/.cargo/bin/moat"), None);
}

#[test]
fn protect_denies_the_codex_home_and_in_sync_ignores_other_keys() {
    let mut out = generated(DEFAULT_POLICY);
    protect(&mut out, std::path::Path::new("/cfg/codex"));
    assert_eq!(mode(&out, &[], "/cfg/codex"), Some("deny"));
    let mut doc: DocumentMut = "# mine\nmodel = \"o3\"\n".parse().unwrap();
    assert!(!in_sync(&doc, &out));
    assert!(
        weaknesses(&doc, false)
            .iter()
            .any(|w| w.contains("default_permissions"))
    );
    apply(&mut doc, &out).unwrap();
    assert!(in_sync(&doc, &out) && weaknesses(&doc, false).is_empty());
    let before = owned_part(&doc);
    doc["projects"]["/w"]["trust_level"] = toml_edit::value("trusted");
    assert_eq!(
        owned_part(&doc),
        before,
        "Codex's own keys are not OpenMoat's part"
    );
    assert!(
        doc.to_string().starts_with("# mine\nmodel = \"o3\"\n"),
        "{doc}"
    );
    doc["sandbox_mode"] = toml_edit::value("danger-full-access");
    assert!(
        weaknesses(&doc, false)
            .iter()
            .any(|w| w.contains("sandbox_mode"))
    );
}

#[test]
fn remove_restores_the_users_text() {
    let out = generated(DEFAULT_POLICY);
    for original in [
        "",
        "# mine\nmodel = \"o3\"\n\n[features]\nweb_search = true\n",
        "[features.network_proxy]\nenabled = false\nport = 3128\n",
        "[shell_environment_policy]\ninherit = \"core\"\n",
    ] {
        let mut doc: DocumentMut = original.parse().unwrap();
        apply(&mut doc, &out).unwrap();
        assert!(remove(&mut doc));
        // A proxy table is the user's: OpenMoat turned it on and leaves it.
        let expected = original.replace("enabled = false", "enabled = true");
        assert_eq!(doc.to_string(), expected, "after apply on {original:?}");
        assert!(!remove(&mut doc));
    }
}

#[test]
fn git_safe_bare_repository_follows_the_users_entries_and_is_pinned() {
    let out = generated(DEFAULT_POLICY);
    let original = "[shell_environment_policy]\nset = { CI = \"1\", GIT_CONFIG_COUNT = \"1\", \
                    GIT_CONFIG_KEY_0 = \"user.name\", GIT_CONFIG_VALUE_0 = \"me\" }\n";
    let mut doc: DocumentMut = original.parse().unwrap();
    apply(&mut doc, &out).unwrap();
    let set = &doc["shell_environment_policy"]["set"];
    let at = |key: &str| set.get(key).and_then(toml_edit::Item::as_str);
    assert_eq!(at("GIT_CONFIG_COUNT"), Some("2"));
    assert_eq!(at("GIT_CONFIG_KEY_1"), Some("safe.bareRepository"));
    assert_eq!(at("GIT_CONFIG_VALUE_1"), Some("explicit"));
    assert_eq!(at("CI"), Some("1"));
    assert!(in_sync(&doc, &out));
    let pinned = owned_part(&doc);
    assert!(
        pinned.contains("\"GIT_CONFIG_VALUE_1\"=\"explicit\""),
        "{pinned}"
    );
    doc["shell_environment_policy"]["set"]["GIT_CONFIG_COUNT"] = toml_edit::value("1");
    assert_ne!(owned_part(&doc), pinned, "dropping the entry is drift");
    assert!(!in_sync(&doc, &out));
    let mut doc: DocumentMut = original.parse().unwrap();
    apply(&mut doc, &out).unwrap();
    assert!(remove(&mut doc));
    assert_eq!(doc.to_string(), original);
}

/// `moat allow --dir` leaves `.git` out of its write grant: the directory is
/// writable, its own `.git` read-only, and the nested `**/.git/**` is no deny
/// glob, which would make every `.git` below it unreadable.
#[test]
fn an_allowed_directory_keeps_its_git_read_only_and_readable() {
    let policy = Policy::parse(
        "version: 1\nallow:\n  - id: approved-1\n    fs.read: ['/w/lib', '/w/lib/**']\n    \
         fs.write: ['/w/lib', '/w/lib/**', '!/w/lib/.git/**', '!/w/lib/**/.git/**']\n",
    )
    .expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    let out = generate_with(&ir, &["/Users/me".into()], None, |p| {
        p.starts_with("/w/lib")
    })
    .expect("generates");
    assert_eq!(mode(&out, &[], "/w/lib"), Some("write"), "{}", render(&out));
    assert_eq!(
        mode(&out, &[], "/w/lib/.git"),
        Some("read"),
        "{}",
        render(&out)
    );
    assert!(!render(&out).contains("/w/lib/**/.git"), "{}", render(&out));
    assert!(
        out.report
            .allowances
            .iter()
            .any(|a| a.rule == "codex.nested-git"),
        "{:?}",
        out.report.allowances
    );
}
