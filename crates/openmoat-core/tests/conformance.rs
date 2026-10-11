//! Conformance suite: every fixture in `tests/conformance/*.yaml` is evaluated
//! against the shipped default policy (`openmoat_core::DEFAULT_POLICY`), with the
//! fixture's repository policy merged in when it names one. A fixture passes
//! when the verdict matches and every expected rule id is present in the decision.
//! A fixture with `session` is decided with the taint its earlier calls leave
//! (docs/POLICY.md §4.1).
//!
//! The suite is the executable form of the security claims in `docs/THREAT_MODEL.md` §3,
//! so it is strict about its own inputs: unknown keys, duplicate ids and
//! fixtures with zero or several actions are rejected.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use openmoat_core::{
    Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, MapPathResolver, MapResolver, Policy,
    RepoPolicy, Taint, TaintSecret, Verdict,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    /// Threat class from `docs/THREAT_MODEL.md` §3 (`T1`…`T12`). Required for attack and
    /// ask fixtures; benign fixtures may name the threat whose rule they keep
    /// from over-matching.
    #[serde(default)]
    threat: Option<String>,
    action: FixtureAction,
    expect: Expect,
    /// Program name → path it resolves to on the kernel search path.
    #[serde(default)]
    resolve: BTreeMap<String, String>,
    /// Program name → path recorded at install time.
    #[serde(default)]
    pins: BTreeMap<String, String>,
    /// Symlink path → target, as the filesystem would resolve it.
    #[serde(default)]
    links: BTreeMap<String, String>,
    /// Files that exist, for the expansion of glob operands (`cat .en?`).
    #[serde(default)]
    files: Vec<String>,
    /// Working directory and project for this fixture instead of `/p` and `/p`.
    context: Option<FixtureContext>,
    /// Earlier calls of the same session that ran, oldest first: the action is
    /// decided with the taint they leave (ADR-020). Their own verdicts do not
    /// matter here; a person may have approved them.
    #[serde(default)]
    session: Vec<FixtureAction>,
    /// A repository policy merged into the default policy (ADR-022).
    repo: Option<RepoFixture>,
}

/// `repo: { policy: "<yaml>", trusted: true }`: the project's
/// `.moat/policy.yaml`, and whether a person trusted it with `moat trust`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoFixture {
    policy: String,
    #[serde(default)]
    trusted: bool,
}

/// `context: { cwd: /Users/me }` is a session in the home directory, which the
/// CLI never trusts as a project; `project` names one explicitly.
/// `real_project` and `real_home` are those roots with their symlinks resolved,
/// as the CLI reports them when a root is reached through a link.
/// `moved_dirs` maps a default directory (`~/.claude`) to where an environment
/// variable (`CLAUDE_CONFIG_DIR`) moved it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureContext {
    cwd: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    real_project: Option<String>,
    #[serde(default)]
    real_home: Option<String>,
    #[serde(default)]
    moved_dirs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureAction {
    shell: Option<String>,
    fs_read: Option<String>,
    fs_write: Option<String>,
    net: Option<String>,
    /// A URL read by a host fetch tool (`WebFetch`).
    fetch: Option<String>,
    /// A query sent by a host search tool (`WebSearch`).
    web_search: Option<String>,
    mcp_tool: Option<McpFixture>,
    /// A host tool the adapter cannot classify: `{ host, tool }`.
    unknown_tool: Option<UnknownToolFixture>,
    /// Files a multi-file patch writes (Codex `apply_patch`).
    patch: Option<Vec<String>>,
    /// A command for a shell OpenMoat does not parse: `{ shell, command }`.
    foreign_shell: Option<ForeignShellFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownToolFixture {
    host: String,
    tool: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForeignShellFixture {
    shell: String,
    command: String,
}

/// `mcp_tool: "name"` or `mcp_tool: { name, reads, writes, hosts, unchecked }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum McpFixture {
    Name(String),
    Call {
        name: String,
        #[serde(default)]
        reads: Vec<String>,
        #[serde(default)]
        writes: Vec<String>,
        #[serde(default)]
        hosts: Vec<String>,
        unchecked: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    verdict: Verdict,
    #[serde(default)]
    rules: Vec<String>,
}

impl FixtureAction {
    fn into_action(self, id: &str) -> Action {
        let candidates = [
            self.shell.map(|command| Action::Shell { command }),
            self.fs_read.map(|path| Action::FsRead { path }),
            self.fs_write.map(|path| Action::FsWrite { path }),
            self.net.map(|url| Action::Net { url }),
            self.fetch.map(|url| Action::Fetch { url }),
            self.web_search.map(|query| Action::WebSearch { query }),
            self.patch.map(|writes| Action::Patch { writes }),
            self.unknown_tool.map(|u| Action::UnknownTool {
                host: u.host,
                tool: u.tool,
            }),
            self.foreign_shell.map(|f| Action::ForeignShell {
                shell: f.shell,
                command: f.command,
            }),
            self.mcp_tool.map(|m| match m {
                McpFixture::Name(name) => Action::mcp(name),
                McpFixture::Call {
                    name,
                    reads,
                    writes,
                    hosts,
                    unchecked,
                } => Action::McpTool {
                    name,
                    reads,
                    writes,
                    hosts,
                    unchecked,
                },
            }),
        ];
        let mut present: Vec<Action> = candidates.into_iter().flatten().collect();
        assert_eq!(
            present.len(),
            1,
            "fixture `{id}` must declare exactly one action"
        );
        present.remove(0)
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_fixtures(dir: &Path) -> Vec<(String, Fixture)> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixture files in {}", dir.display());

    let mut seen = BTreeSet::new();
    let mut fixtures = Vec::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&file).unwrap();
        let parsed: Vec<Fixture> =
            serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        for fixture in parsed {
            assert!(
                seen.insert(fixture.id.clone()),
                "duplicate fixture id `{}`",
                fixture.id
            );
            fixtures.push((name.clone(), fixture));
        }
    }
    fixtures
}

#[test]
fn default_policy_conformance() {
    let root = repo_root();
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy must lint");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };

    let compiled = CompiledPolicy::compile(&policy, &ctx).expect("default policy must compile");

    let fixtures = load_fixtures(&root.join("tests/conformance"));
    let total = fixtures.len();
    let mut report = String::new();
    let mut failed = 0usize;

    for (file, fixture) in fixtures {
        let action = fixture.action.into_action(&fixture.id);
        let resolver = MapResolver {
            resolved: fixture.resolve.clone(),
            pins: fixture.pins.clone(),
        };
        let links = MapPathResolver {
            links: fixture.links.clone(),
            files: fixture.files.clone(),
        };
        let merged = fixture.repo.as_ref().map(|r| {
            RepoPolicy::parse(&r.policy)
                .and_then(|repo| repo.merge(&policy, r.trusted))
                .unwrap_or_else(|e| panic!("{}: repo policy: {e}", fixture.id))
        });
        let own = (fixture.context.is_some() || merged.is_some()).then(|| {
            let ctx = fixture.context.as_ref().map_or_else(
                || ctx.clone(),
                |c| EvalContext {
                    cwd: c.cwd.clone(),
                    project: c.project.clone(),
                    real_project: c.real_project.clone(),
                    real_home: c.real_home.clone(),
                    moved_dirs: c.moved_dirs.clone().into_iter().collect(),
                    ..ctx.clone()
                },
            );
            CompiledPolicy::compile(merged.as_ref().unwrap_or(&policy), &ctx)
                .expect("default policy must compile")
        });
        let compiled = own.as_ref().unwrap_or(&compiled);
        let plain = compiled.decide_with(&action, &resolver, &links);
        // Taint only tightens: the worst session there is never loosens a verdict.
        let worst = compiled.with_taint(plain.clone(), &action, &links, &worst_taint());
        assert!(
            worst.verdict >= plain.verdict,
            "{}: taint loosened {:?} to {:?}",
            fixture.id,
            plain.verdict,
            worst.verdict
        );
        let cwd = fixture.context.as_ref().map_or(&ctx.cwd, |c| &c.cwd);
        let mut taint = Taint::default();
        for (n, earlier) in fixture.session.into_iter().enumerate() {
            let earlier = earlier.into_action(&format!("{}.session[{n}]", fixture.id));
            taint.absorb(compiled.exposure(&earlier, cwd, &links));
        }
        let decision = compiled.with_taint(plain, &action, &links, &taint);
        let missing: Vec<&String> = fixture
            .expect
            .rules
            .iter()
            .filter(|rule| !decision.rules.contains(rule))
            .collect();
        if decision.verdict != fixture.expect.verdict || !missing.is_empty() {
            failed += 1;
            let _ = writeln!(
                report,
                "  {file}/{id}: expected {expected:?} {rules:?}, got {got:?} {got_rules:?}\n    reasons: {reasons}",
                id = fixture.id,
                expected = fixture.expect.verdict,
                rules = fixture.expect.rules,
                got = decision.verdict,
                got_rules = decision.rules,
                reasons = decision.reasons.join(" | "),
            );
        }
    }

    assert!(
        failed == 0,
        "{failed} of {total} conformance fixtures failed:\n{report}"
    );
}

/// A session that read a secret and fetched untrusted content.
fn worst_taint() -> Taint {
    Taint {
        secrets: vec![TaintSecret {
            source: "read /Users/me/.ssh/id_rsa".into(),
            host: None,
        }],
        untrusted: Some("fetch evil.example".into()),
    }
}

/// Threat classes of `docs/THREAT_MODEL.md` §3, as listed in `docs/COVERAGE.md`.
const THREATS: [(&str, &str); 12] = [
    ("T1", "Secret exfiltration via shell"),
    ("T2", "Secret exfiltration via file tools"),
    ("T3", "Secret exfiltration via environment"),
    ("T4", "Destructive git / filesystem operations"),
    ("T5", "Supply-chain execution"),
    ("T6", "Environment poisoning"),
    ("T7", "Obfuscation and nested execution"),
    ("T8", "MCP tool poisoning / over-privileged tools"),
    ("T9", "Hook / policy tampering by the agent"),
    ("T10", "Hook supply chain (trojaned hook binary)"),
    ("T11", "Time-of-check / time-of-use, symlinks"),
    ("T12", "Network to unknown hosts"),
];

/// Every attack and ask fixture names a known threat, every threat has at least
/// one attack fixture, and `docs/COVERAGE.md` is the table generated from them.
/// Regenerate with `MOAT_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance`.
#[test]
fn threat_coverage_is_complete_and_documented() {
    let root = repo_root();
    let fixtures = load_fixtures(&root.join("tests/conformance"));
    let mut by_threat: BTreeMap<&str, Vec<(&str, &Fixture)>> = BTreeMap::new();
    let mut problems = Vec::new();
    for (file, fixture) in &fixtures {
        match fixture.threat.as_deref() {
            Some(t) if THREATS.iter().any(|(id, _)| *id == t) => {
                by_threat
                    .entry(t)
                    .or_default()
                    .push((file.as_str(), fixture));
            }
            Some(t) => problems.push(format!("{file}/{}: unknown threat `{t}`", fixture.id)),
            None if file != "benign.yaml" => {
                problems.push(format!("{file}/{}: missing `threat`", fixture.id));
            }
            None => {}
        }
    }
    let count = |t: &str, file: &str| {
        by_threat
            .get(t)
            .map_or(0, |v| v.iter().filter(|(f, _)| *f == file).count())
    };
    for (t, name) in THREATS {
        if count(t, "attacks.yaml") == 0 {
            problems.push(format!("{t} ({name}) has no attack fixture"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    let mut doc = String::from(
        "# Threat coverage\n\n\
         Generated from `tests/conformance/*.yaml` by the conformance suite; do not edit.\n\
         Regenerate with `MOAT_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance`.\n\
         Threat classes are defined in `docs/THREAT_MODEL.md` §3. A fixture is one tool call and\n\
         the verdict and rule ids the default policy must produce for it.\n\n\
         | Threat | Class | Attacks | Asks | Benign |\n|---|---|---|---|---|\n",
    );
    for (t, name) in THREATS {
        let _ = writeln!(
            doc,
            "| {t} | {name} | {} | {} | {} |",
            count(t, "attacks.yaml"),
            count(t, "ask.yaml"),
            count(t, "benign.yaml")
        );
    }
    for (t, name) in THREATS {
        let _ = write!(doc, "\n## {t}: {name}\n\n");
        for (file, f) in by_threat.get(t).into_iter().flatten() {
            let _ = writeln!(
                doc,
                "- `{}` ({}): {:?} [{}]",
                f.id,
                file.trim_end_matches(".yaml"),
                f.expect.verdict,
                f.expect.rules.join(", ")
            );
        }
    }
    let path = root.join("docs/COVERAGE.md");
    if std::env::var_os("MOAT_UPDATE_COVERAGE").is_some() {
        fs::write(&path, &doc).unwrap();
    }
    let current = fs::read_to_string(&path).unwrap_or_default();
    assert!(
        current.replace("\r\n", "\n") == doc,
        "docs/COVERAGE.md is out of date; run \
         `MOAT_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance`"
    );
}
