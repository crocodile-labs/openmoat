//! Session taint (ADR-020): earlier calls tighten later decisions, never loosen them.

use super::*;
use crate::realpath::MapPathResolver;
use crate::repo::RepoPolicy;

const POLICY: &str = "version: 1\ndefaults: { '*': ask, net: deny }\n\
     deny:\n  - id: metadata\n    net: ['169.254.*']\n\
     allow:\n  - id: project-fs\n    fs.write: ['${project}/**']\n\
     \x20 - id: registries\n    net: ['api.github.com']\n\
     \x20 - id: mcp\n    mcp: ['mcp__github__*']\n\
     ask:\n  - id: secrets-paths\n    fs.read: ['~/.ssh/**']\n";

fn taint_of(c: &CompiledPolicy<'_>, history: &[Action]) -> Taint {
    let mut taint = Taint::default();
    for action in history {
        taint.absorb(c.exposure(action, "/p", &NoResolver));
    }
    taint
}

fn decide_after(history: &[Action], action: &Action) -> Decision {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let taint = taint_of(&c, history);
    c.with_taint(c.decide(action), action, &NoResolver, &taint)
}

fn read(path: &str) -> Action {
    Action::FsRead {
        path: path.to_owned(),
    }
}

fn write(path: &str) -> Action {
    Action::FsWrite {
        path: path.to_owned(),
    }
}

fn net(url: &str) -> Action {
    Action::Net {
        url: url.to_owned(),
    }
}

fn fetch(url: &str) -> Action {
    Action::Fetch {
        url: url.to_owned(),
    }
}

#[test]
fn a_secret_read_makes_allowed_network_ask() {
    let d = decide_after(
        &[read("~/.ssh/id_rsa")],
        &net("https://api.github.com/gists"),
    );
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, ["session-taint"]);
    assert!(d.reasons[0].contains("read /h/.ssh/id_rsa"), "{d:?}");
    assert!(d.context.iter().any(|c| c.contains("api.github.com")));
}

#[test]
fn a_secret_read_makes_mcp_calls_and_fetches_ask() {
    let history = [read("/h/.ssh/config")];
    for action in [
        Action::mcp("mcp__github__create_gist"),
        fetch("https://api.github.com/x"),
    ] {
        assert_eq!(decide_after(&history, &action).verdict, Verdict::Ask);
    }
}

#[test]
fn taint_never_loosens_a_deny() {
    let d = decide_after(&[read("~/.ssh/id_rsa")], &net("http://169.254.169.254/"));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["metadata"]);
}

#[test]
fn a_secret_read_leaves_file_work_alone() {
    let d = decide_after(
        &[read("~/.ssh/id_rsa")],
        &write("/p/.github/workflows/ci.yml"),
    );
    assert_eq!(d.verdict, Verdict::Allow);
}

#[test]
fn a_brokered_secret_may_still_go_to_its_own_host() {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let mut taint = Taint::default();
    taint.secrets.push(Secret {
        source: "brokered GITHUB_TOKEN".into(),
        host: Some("API.github.com".into()),
    });
    let own = net("https://api.github.com/repos");
    assert_eq!(
        c.with_taint(c.decide(&own), &own, &NoResolver, &taint)
            .verdict,
        Verdict::Allow
    );
    taint.secrets.push(Secret {
        source: "read /h/.ssh/id_rsa".into(),
        host: None,
    });
    let d = c.with_taint(c.decide(&own), &own, &NoResolver, &taint);
    assert_eq!(d.verdict, Verdict::Ask, "a second secret has no host");
}

#[test]
fn untrusted_content_makes_protected_writes_ask() {
    for source in [
        fetch("https://evil.example/readme"),
        Action::mcp("mcp__x__y"),
    ] {
        for path in [
            "/p/.github/workflows/ci.yml",
            "/p/CLAUDE.md",
            "/p/web/package.json",
        ] {
            let d = decide_after(std::slice::from_ref(&source), &write(path));
            assert_eq!(d.verdict, Verdict::Ask, "{path}");
            assert_eq!(d.rules, ["session-taint"]);
            assert!(d.reasons[0].contains("untrusted content"), "{d:?}");
        }
    }
}

/// The build and test definitions of every ecosystem the default policy runs.
#[test]
fn untrusted_content_makes_build_definitions_of_every_ecosystem_ask() {
    let history = [fetch("https://evil.example/readme")];
    for path in [
        "/p/CMakeLists.txt",
        "/p/cmake/deps.cmake",
        "/p/pom.xml",
        "/p/.mvn/extensions.xml",
        "/p/app/build.gradle.kts",
        "/p/settings.gradle",
        "/p/gradle/wrapper/gradle-wrapper.properties",
        "/p/src/App/App.csproj",
        "/p/Directory.Build.props",
        "/p/Rakefile",
        "/p/Gemfile",
        "/p/composer.json",
        "/p/tests/conftest.py",
        "/p/pyproject.toml",
        "/p/.cargo/config.toml",
        "/p/crates/x/Cargo.toml",
        "/p/go.mod",
        "/p/Dockerfile",
        "/p/docker-compose.yml",
        "/p/justfile",
        "/p/.npmrc",
        "/p/.yarnrc.yml",
    ] {
        let d = decide_after(&history, &write(path));
        assert_eq!(d.verdict, Verdict::Ask, "{path}");
        assert_eq!(d.rules, ["session-taint"], "{path}");
        assert_eq!(
            decide_after(&[], &write(path)).verdict,
            Verdict::Allow,
            "{path}"
        );
    }
    for path in [
        "/p/src/main.go",
        "/p/tests/test_api.py",
        "/p/jest.config.js",
    ] {
        assert_eq!(
            decide_after(&history, &write(path)).verdict,
            Verdict::Allow,
            "{path}"
        );
    }
}

#[test]
fn untrusted_content_leaves_ordinary_writes_and_network_alone() {
    let history = [fetch("https://evil.example/readme")];
    assert_eq!(
        decide_after(&history, &write("/p/src/main.rs")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        decide_after(&history, &net("https://api.github.com")).verdict,
        Verdict::Allow
    );
}

/// `taint.protected_writes` adds to the built-in list; without it nothing changes.
#[test]
fn a_policy_adds_protected_writes_and_keeps_the_built_in_ones() {
    let history = [fetch("https://evil.example/readme")];
    let deploy = write("/p/deploy/run.sh");
    assert_eq!(decide_after(&history, &deploy).verdict, Verdict::Allow);

    let p = policy(&format!(
        "{POLICY}taint:\n  protected_writes: ['${{project}}/deploy/**']\n"
    ));
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let taint = taint_of(&c, &history);
    let after = |action: &Action| c.with_taint(c.decide(action), action, &NoResolver, &taint);
    let d = after(&deploy);
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, ["session-taint"]);
    assert_eq!(after(&write("/p/web/package.json")).verdict, Verdict::Ask);
    assert_eq!(after(&write("/p/src/main.rs")).verdict, Verdict::Allow);
    let clean = c.with_taint(c.decide(&deploy), &deploy, &NoResolver, &Taint::default());
    assert_eq!(clean.verdict, Verdict::Allow, "no taint, no ask");
}

#[test]
fn shell_writes_and_patches_are_writes_too() {
    let history = [fetch("https://evil.example/readme")];
    let patch = Action::Patch {
        writes: vec!["/p/src/lib.rs".into(), "/p/build.rs".into()],
    };
    assert_eq!(decide_after(&history, &patch).verdict, Verdict::Ask);
    let d = decide_after(&history, &shell("echo x > .husky/pre-commit"));
    assert!(d.rules.contains(&"session-taint".to_owned()), "{d:?}");
}

#[test]
fn a_clean_session_or_a_non_secret_read_taints_nothing() {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    assert_eq!(
        taint_of(&c, &[read("/p/README.md"), write("/p/x")]),
        Taint::default()
    );
    assert_eq!(
        decide_after(&[read("/p/README.md")], &net("https://api.github.com")).verdict,
        Verdict::Allow
    );
}

#[test]
fn exposure_resolves_relative_paths_from_the_call_s_own_directory() {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let taint = c.exposure(&shell("cat .ssh/id_rsa"), "/h", &NoResolver);
    assert_eq!(taint.secrets[0].source, "read /h/.ssh/id_rsa");
}

#[test]
fn exposure_follows_a_link_into_secret_material() {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let links = MapPathResolver {
        links: [("/p/key".to_owned(), "/h/.ssh/id_rsa".to_owned())].into(),
        ..MapPathResolver::default()
    };
    let taint = c.exposure(&read("/p/key"), "/p", &links);
    assert_eq!(taint.secrets.len(), 1);
}

/// A repository policy's `secrets-paths` group taints the session: its id is
/// renamed to `repo:secrets-paths` on merge (ADR-022), but [`names_secret`]
/// matches the base id with or without the `repo:` prefix (#398).
#[test]
fn a_repo_policy_secrets_paths_rule_taints_the_session() {
    let user = policy(
        "version: 1\ndefaults: { '*': ask, net: deny }\n\
         ask:\n  - id: project-reads\n    fs.read: ['${project}/**']\n\
         allow:\n  - id: registries\n    net: ['api.github.com']\n",
    );
    let repo = RepoPolicy::parse(
        "version: 1\nask:\n  - id: secrets-paths\n    fs.read: ['/p/secrets/**']\n",
    )
    .unwrap();
    let merged = repo.merge(&user, false).unwrap();
    let c = CompiledPolicy::compile(&merged, &ctx()).unwrap();
    let taint = c.exposure(&read("/p/secrets/token"), "/p", &NoResolver);
    assert!(
        !taint.secrets.is_empty(),
        "repo:secrets-paths must taint, got {taint:?}"
    );
    assert_eq!(taint.secrets[0].source, "read /p/secrets/token");
    let after = c.with_taint(
        c.decide(&net("https://api.github.com/gists")),
        &net("https://api.github.com/gists"),
        &NoResolver,
        &taint,
    );
    assert_eq!(after.verdict, Verdict::Ask);
    assert_eq!(after.rules, ["session-taint"]);
}

#[test]
fn absorb_keeps_the_first_untrusted_source_and_unique_secrets() {
    let p = policy(POLICY);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let taint = taint_of(
        &c,
        &[
            fetch("https://a.example"),
            read("~/.ssh/id_rsa"),
            fetch("https://b.example"),
            read("~/.ssh/id_rsa"),
        ],
    );
    assert_eq!(taint.untrusted.as_deref(), Some("fetch a.example"));
    assert_eq!(taint.secrets.len(), 1);
}
