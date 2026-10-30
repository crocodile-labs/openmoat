//! Every fixture of `tests/conformance/*.yaml` through the SDK, against the
//! engine itself (ADR-046).
//!
//! For each fixture the engine's decision is made the way
//! `openmoat-core/tests/conformance.rs` makes it, straight from the core; the
//! SDK's decision is made through its public API alone (`Policy`, `Context`,
//! `Facts`, `Session`, `Engine`). The two must be identical (verdict, rules,
//! reasons and context), and the fixture's own expectation must hold.
//!
//! With `OPENMOAT_SDK_VECTORS=<file>`, the test also writes every fixture as a
//! JSON vector in the SDK's wire shapes with the engine's decision, which
//! `sdk/js/test/conformance.test.js` runs through the WebAssembly module
//! (`scripts/ci/sdk-js.sh`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core as core;
use openmoat_sdk::{
    Action, Context, DEFAULT_POLICY, Decision, Engine, Facts, McpCall, Policy, Session,
    UnknownToolCall, Verdict,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    #[serde(default)]
    #[expect(dead_code, reason = "the core's conformance test checks threats")]
    threat: Option<String>,
    #[serde(default)]
    #[expect(dead_code, reason = "the core's conformance test shows the reason")]
    why: Option<String>,
    action: FixtureAction,
    expect: Expect,
    #[serde(default)]
    resolve: BTreeMap<String, String>,
    #[serde(default)]
    pins: BTreeMap<String, String>,
    #[serde(default)]
    links: BTreeMap<String, String>,
    #[serde(default)]
    files: Vec<String>,
    context: Option<FixtureContext>,
    #[serde(default)]
    session: Vec<FixtureAction>,
    repo: Option<RepoFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoFixture {
    policy: String,
    #[serde(default)]
    trusted: bool,
}

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
    #[serde(default)]
    case_insensitive_paths: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureAction {
    shell: Option<String>,
    fs_read: Option<String>,
    fs_write: Option<String>,
    net: Option<String>,
    fetch: Option<String>,
    web_search: Option<String>,
    mcp_tool: Option<McpFixture>,
    unknown_tool: Option<UnknownToolFixture>,
    patch: Option<Vec<String>>,
    foreign_shell: Option<ForeignShellFixture>,
    unchecked: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownToolFixture {
    host: String,
    tool: String,
    #[serde(default)]
    reads: Vec<String>,
    #[serde(default)]
    writes: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForeignShellFixture {
    shell: String,
    command: String,
}

#[derive(Debug, Clone, Deserialize)]
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
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        opens: Vec<String>,
        unchecked: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    verdict: core::Verdict,
    #[serde(default)]
    rules: Vec<String>,
}

impl FixtureAction {
    /// The fixture's action in the SDK's shape, built with its public API.
    fn sdk(self, id: &str) -> Action {
        let mut present: Vec<Action> = [
            self.shell.map(Action::shell),
            self.fs_read.map(Action::read),
            self.fs_write.map(Action::write),
            self.net.map(Action::net),
            self.fetch.map(Action::fetch),
            self.web_search.map(|query| Action::WebSearch { query }),
            self.patch.map(|writes| Action::Patch { writes }),
            self.foreign_shell.map(|f| Action::ForeignShell {
                shell: f.shell,
                command: f.command,
            }),
            self.unknown_tool.map(|u| {
                Action::UnknownTool(
                    UnknownToolCall::new(u.host, u.tool)
                        .reads(u.reads)
                        .writes(u.writes)
                        .hosts(u.hosts)
                        .commands(u.commands),
                )
            }),
            self.mcp_tool.map(|m| match m {
                McpFixture::Name(name) => Action::mcp(McpCall::new(name)),
                McpFixture::Call {
                    name,
                    reads,
                    writes,
                    hosts,
                    commands,
                    opens,
                    unchecked,
                } => {
                    let call = McpCall::new(name)
                        .reads(reads)
                        .writes(writes)
                        .hosts(hosts)
                        .commands(commands)
                        .opens(opens);
                    Action::mcp(match unchecked {
                        Some(limit) => call.unchecked(limit),
                        None => call,
                    })
                }
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert_eq!(present.len(), 1, "fixture `{id}` must declare one action");
        let action = present.remove(0);
        match self.unchecked {
            Some(reason) => Action::unchecked(action, reason),
            None => action,
        }
    }

    /// The same action built for the engine directly, as the core's own
    /// conformance test builds it: the oracle, independent of the SDK.
    fn core(self) -> core::Action {
        let action = [
            self.shell.map(|command| core::Action::Shell { command }),
            self.fs_read.map(|path| core::Action::FsRead { path }),
            self.fs_write.map(|path| core::Action::FsWrite { path }),
            self.net.map(|url| core::Action::Net { url }),
            self.fetch.map(|url| core::Action::Fetch { url }),
            self.web_search
                .map(|query| core::Action::WebSearch { query }),
            self.patch.map(|writes| core::Action::Patch { writes }),
            self.unknown_tool.map(|u| core::Action::UnknownTool {
                host: u.host,
                tool: u.tool,
                reads: u.reads,
                writes: u.writes,
                hosts: u.hosts,
                commands: u.commands,
            }),
            self.foreign_shell.map(|f| core::Action::ForeignShell {
                shell: f.shell,
                command: f.command,
            }),
            self.mcp_tool.map(|m| match m {
                McpFixture::Name(name) => core::Action::mcp(name),
                McpFixture::Call {
                    name,
                    reads,
                    writes,
                    hosts,
                    commands,
                    opens,
                    unchecked,
                } => core::Action::McpTool {
                    name,
                    reads,
                    writes,
                    hosts,
                    commands,
                    opens,
                    unchecked,
                },
            }),
        ]
        .into_iter()
        .flatten()
        .next()
        .unwrap();
        match self.unchecked {
            Some(reason) => core::Action::unchecked(action, reason),
            None => action,
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_fixtures() -> Vec<Fixture> {
    let dir = repo_root().join("tests/conformance");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    let mut seen = BTreeSet::new();
    let mut fixtures = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        let parsed: Vec<Fixture> =
            core::yaml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for f in parsed {
            assert!(seen.insert(f.id.clone()), "duplicate fixture id `{}`", f.id);
            fixtures.push(f);
        }
    }
    fixtures
}

/// The conformance suite's default context: home `/Users/me`, project and cwd `/p`.
fn default_context() -> Context {
    Context::new("/Users/me", "/p").project("/p")
}

fn context_of(f: &Fixture) -> Context {
    let Some(c) = &f.context else {
        return default_context();
    };
    let mut ctx =
        Context::new("/Users/me", c.cwd.clone()).case_insensitive_paths(c.case_insensitive_paths);
    if let Some(p) = &c.project {
        ctx = ctx.project(p.clone());
    }
    if let Some(p) = &c.real_project {
        ctx = ctx.real_project(p.clone());
    }
    if let Some(p) = &c.real_home {
        ctx = ctx.real_home(p.clone());
    }
    for (default, moved) in &c.moved_dirs {
        ctx = ctx.moved_dir(default.clone(), moved.clone());
    }
    ctx
}

fn core_context_of(f: &Fixture) -> core::EvalContext {
    let base = core::EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    f.context
        .as_ref()
        .map_or(base.clone(), |c| core::EvalContext {
            cwd: c.cwd.clone(),
            project: c.project.clone(),
            real_project: c.real_project.clone(),
            real_home: c.real_home.clone(),
            moved_dirs: c.moved_dirs.clone().into_iter().collect(),
            case_insensitive_paths: c.case_insensitive_paths,
            ..base
        })
}

fn facts_of(f: &Fixture) -> Facts {
    let mut facts = Facts::new();
    for (name, path) in &f.resolve {
        facts = facts.program(name.clone(), path.clone());
    }
    for (name, path) in &f.pins {
        facts = facts.pinned(name.clone(), path.clone());
    }
    for (link, target) in &f.links {
        facts = facts.link(link.clone(), target.clone());
    }
    for file in &f.files {
        facts = facts.file(file.clone());
    }
    facts
}

/// What a compiled policy depends on in `f`: its context and repository policy.
/// Fixtures that share one share the compiled policy, on both sides.
fn compile_key(f: &Fixture) -> String {
    let repo = f.repo.as_ref().map(|r| (&r.policy, r.trusted));
    format!("{:?} {repo:?}", context_of(f))
}

/// Compiled policies, on each side, by [`compile_key`].
#[derive(Default)]
struct Compiled {
    core: BTreeMap<String, core::CompiledPolicy<'static>>,
    sdk: BTreeMap<String, Engine>,
}

/// The engine's decision for `f`, straight from the core.
fn engine_decision(f: &Fixture, policy: &core::Policy, cache: &mut Compiled) -> core::Decision {
    let ctx = core_context_of(f);
    let compiled = cache.core.entry(compile_key(f)).or_insert_with(|| {
        let merged = f.repo.as_ref().map_or_else(
            || policy.clone(),
            |r| {
                core::RepoPolicy::parse(&r.policy)
                    .and_then(|repo| repo.merge(policy, r.trusted))
                    .unwrap()
            },
        );
        core::CompiledPolicy::compile_owned(merged, &ctx).unwrap()
    });
    let resolver = core::MapResolver {
        resolved: f.resolve.clone(),
        pins: f.pins.clone(),
    };
    let links = core::MapPathResolver {
        links: f.links.clone(),
        files: f.files.clone(),
    };
    let mut taint = core::Taint::default();
    for earlier in &f.session {
        taint.absorb(compiled.exposure(&earlier.clone().core(), &ctx.cwd, &links));
    }
    let action = f.action.clone().core();
    let plain = compiled.decide_with(&action, &resolver, &links);
    compiled.with_taint(plain, &action, &links, &taint)
}

/// The SDK's decision for `f`, through its public API only.
fn sdk_decision(f: &Fixture, cache: &mut Compiled) -> Decision {
    let engine = cache.sdk.entry(compile_key(f)).or_insert_with(|| {
        let mut policy = Policy::parse(DEFAULT_POLICY).unwrap();
        if let Some(r) = &f.repo {
            policy = policy.with_repository(&r.policy, r.trusted).unwrap();
        }
        Engine::new(policy, &context_of(f)).unwrap()
    });
    let facts = facts_of(f);
    let mut session = Session::new();
    for earlier in &f.session {
        session.record(engine, &earlier.clone().sdk(&f.id), &facts);
    }
    engine.decide_with(&f.action.clone().sdk(&f.id), &facts, &session)
}

#[test]
fn every_fixture_decides_through_the_sdk_as_through_the_engine() {
    let policy = core::Policy::parse(core::DEFAULT_POLICY).unwrap();
    let fixtures = load_fixtures();
    assert!(fixtures.len() > 1000, "only {} fixtures", fixtures.len());
    let mut problems = Vec::new();
    let mut vectors = Vec::new();
    let mut cache = Compiled::default();
    for f in &fixtures {
        let engine = engine_decision(f, &policy, &mut cache);
        let sdk = sdk_decision(f, &mut cache);
        let same = sdk.verdict.as_str() == engine.verdict.as_str()
            && sdk.rules == engine.rules
            && sdk.reasons == engine.reasons
            && sdk.context == engine.context;
        if !same {
            problems.push(format!("{}: engine {engine:?}, sdk {sdk:?}", f.id));
        }
        let missing: Vec<_> = f
            .expect
            .rules
            .iter()
            .filter(|r| !sdk.rules.contains(r))
            .collect();
        if sdk.verdict.as_str() != f.expect.verdict.as_str() || !missing.is_empty() {
            problems.push(format!(
                "{}: expected {:?} {:?}, sdk {:?} {:?}",
                f.id, f.expect.verdict, f.expect.rules, sdk.verdict, sdk.rules
            ));
        }
        vectors.push(json!({
            "id": f.id,
            "context": context_of(f),
            "repository": f.repo.as_ref().map(|r| json!({"policy": r.policy, "trusted": r.trusted})),
            "facts": facts_of(f),
            "session": f.session.iter().map(|a| a.clone().sdk(&f.id)).collect::<Vec<_>>(),
            "action": f.action.clone().sdk(&f.id),
            "expect": {
                "verdict": engine.verdict.as_str(),
                "rules": engine.rules,
                "reasons": engine.reasons,
                "context": engine.context,
            },
        }));
    }
    assert!(
        problems.is_empty(),
        "{} of {} fixtures differ:\n{}",
        problems.len(),
        fixtures.len(),
        problems.join("\n")
    );
    if let Some(path) = std::env::var_os("OPENMOAT_SDK_VECTORS") {
        fs::write(&path, serde_json::to_string(&vectors).unwrap()).unwrap();
    }
}

/// The wire forms the vectors use read back into the same values, so a vector
/// means to the JavaScript package what it means here.
#[test]
fn wire_forms_round_trip() {
    for f in load_fixtures() {
        let action = f.action.clone().sdk(&f.id);
        let text = serde_json::to_string(&action).unwrap();
        assert_eq!(
            serde_json::from_str::<Action>(&text).unwrap(),
            action,
            "{}",
            f.id
        );
        let ctx = context_of(&f);
        let text = serde_json::to_string(&ctx).unwrap();
        assert_eq!(
            serde_json::from_str::<Context>(&text).unwrap(),
            ctx,
            "{}",
            f.id
        );
    }
    assert_eq!(Verdict::Ask.as_str(), "ask");
}
