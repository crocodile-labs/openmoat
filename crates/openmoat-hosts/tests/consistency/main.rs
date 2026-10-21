//! Cross-host consistency: one user intent gets one verdict, whichever agent
//! host sends it.
//!
//! Each row names a fixture of `tests/conformance/*.yaml`. Its action is written
//! as the payload of every host route that has a tool for it (the shapes of
//! `tests/fixtures/hosts/<host>/`), parsed by that host's adapter, decided by the
//! default policy as `moat guard` does (`decide_with`, `with_taint`,
//! `Host::decided`, `Host::answer`), and the verdict the host receives must be the
//! fixture's, translated only where the docs say a host cannot receive it
//! ([`received`]). Every rule the fixture names must be in the decision.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::{
    Action, CompiledPolicy, DEFAULT_POLICY, Decision, EvalContext, MapPathResolver, MapResolver,
    Policy, Taint, Verdict,
};
use openmoat_hosts::{HookEvent, Host};
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

mod attacks;
mod payloads;

use payloads::{copilot, cursor, cursor_tool, gemini, openclaw, pi};

/// The part of a conformance fixture this suite reads. A fixture with its own
/// context, session, repository policy, links or resolver is not a plain
/// intent, so a row naming one fails ([`fixture`]).
#[derive(Deserialize)]
struct Fixture {
    id: String,
    action: FixtureAction,
    expect: Expect,
    context: Option<IgnoredAny>,
    session: Option<IgnoredAny>,
    repo: Option<IgnoredAny>,
    links: Option<IgnoredAny>,
    resolve: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct FixtureAction {
    shell: Option<String>,
    fs_read: Option<String>,
    fs_write: Option<String>,
    fetch: Option<String>,
}

#[derive(Deserialize)]
struct Expect {
    verdict: Verdict,
    #[serde(default)]
    rules: Vec<String>,
}

/// What a row asks for, as the fixture states it.
#[derive(Clone, Debug)]
enum Intent {
    Shell(String),
    Read(String),
    Write(String),
    Fetch(String),
}

/// One way a host sends a tool call to `moat guard`.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// Claude Code `PreToolUse` in the `default` permission mode.
    ClaudeCode,
    /// Claude Code `PreToolUse` in `bypassPermissions`, which asks no one.
    ClaudeCodeNoPrompt,
    /// Codex `PreToolUse`.
    Codex,
    /// Cursor `beforeShellExecution`.
    CursorShell,
    /// Cursor `beforeReadFile`.
    CursorReadFile,
    /// Cursor `preToolUse`.
    CursorPreTool,
    /// OpenClaw `before_tool_call`, through OpenMoat's plugin.
    OpenClaw,
    /// GitHub Copilot CLI `preToolUse`.
    CopilotCli,
    /// pi `tool_call` in its terminal UI, through OpenMoat's extension.
    Pi,
    /// Gemini CLI `BeforeTool`.
    GeminiCli,
}

const ROUTES: [Route; 10] = [
    Route::ClaudeCode,
    Route::ClaudeCodeNoPrompt,
    Route::Codex,
    Route::CursorShell,
    Route::CursorReadFile,
    Route::CursorPreTool,
    Route::OpenClaw,
    Route::CopilotCli,
    Route::Pi,
    Route::GeminiCli,
];

impl Route {
    fn host(self) -> Host {
        match self {
            Self::ClaudeCode | Self::ClaudeCodeNoPrompt => Host::ClaudeCode,
            Self::Codex => Host::Codex,
            Self::CursorShell | Self::CursorReadFile | Self::CursorPreTool => Host::Cursor,
            Self::OpenClaw => Host::OpenClaw,
            Self::CopilotCli => Host::CopilotCli,
            Self::Pi => Host::Pi,
            Self::GeminiCli => Host::GeminiCli,
        }
    }
}

const CWD: &str = "/p";
const HOME: &str = "/Users/me";

/// The verdict a host receives for `expected`, where the docs say it cannot
/// receive that verdict as is.
fn received(route: Route, expected: Verdict) -> Verdict {
    match (route, expected) {
        // Codex hooks cannot ask, so an `ask` reaches Codex as a deny that says how
        // to approve it (docs/INSTALL.md hosts table, `Host::answer`). Nor does
        // Claude Code in `bypassPermissions` or `dontAsk`, which puts no question
        // to a person; there a `defer` stays Claude Code's own
        // (`HookEvent::PreToolUseNoAsk`).
        (Route::Codex | Route::ClaudeCodeNoPrompt, Verdict::Ask) => Verdict::Deny,
        // Cursor does not enforce `ask` on `preToolUse` or `beforeReadFile`: it is
        // sent as a deny. Those file tools have no flow of their own for a
        // `defer` either, so OpenMoat asks itself, which is again a deny there
        // (ADR-025, docs/INSTALL.md hosts table, `Host::decided`).
        (Route::CursorReadFile | Route::CursorPreTool, Verdict::Ask | Verdict::Defer) => {
            Verdict::Deny
        }
        (_, verdict) => verdict,
    }
}

/// The payload `route` sends for `intent` and the action its adapter must
/// read from it, or why the route has no tool for it.
fn payload(route: Route, intent: &Intent) -> Result<(Value, Action), &'static str> {
    let shell = |command: &str| Action::Shell {
        command: command.to_owned(),
    };
    // Both Claude Code routes send the same tools; only the permission mode differs.
    let tools = match route {
        Route::ClaudeCodeNoPrompt => Route::ClaudeCode,
        other => other,
    };
    match (tools, intent) {
        (Route::ClaudeCode | Route::Codex, Intent::Shell(c)) => Ok((
            pre_tool_use(route, "Bash", &json!({ "command": c })),
            shell(c),
        )),
        (Route::ClaudeCode, Intent::Read(p)) => Ok((
            pre_tool_use(route, "Read", &json!({ "file_path": p })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::ClaudeCode, Intent::Write(p)) => Ok((
            pre_tool_use(
                route,
                "Edit",
                &json!({ "file_path": p, "old_string": "old", "new_string": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::ClaudeCode, Intent::Fetch(u)) => Ok((
            pre_tool_use(
                route,
                "WebFetch",
                &json!({ "url": u, "prompt": "summarise" }),
            ),
            Action::Fetch { url: u.clone() },
        )),
        // Codex reads files through its shell; the shell rows cover that.
        (Route::Codex, Intent::Read(_)) => Err("Codex has no file read tool"),
        (Route::Codex, Intent::Write(p)) => {
            let patch = format!("*** Begin Patch\n*** Add File: {p}\n+new\n*** End Patch\n");
            Ok((
                pre_tool_use(route, "apply_patch", &json!({ "command": patch })),
                Action::Patch {
                    writes: vec![p.clone()],
                },
            ))
        }
        // docs/INSTALL.md: Codex does not hook web search or hosted tools.
        (Route::Codex, Intent::Fetch(_)) => Err("Codex has no hooked fetch tool"),
        (Route::CursorShell, Intent::Shell(c)) => Ok((
            cursor(&json!({
                "hook_event_name": "beforeShellExecution", "command": c,
                "cwd": CWD, "sandbox": false,
            })),
            shell(c),
        )),
        (Route::CursorShell, _) => Err("beforeShellExecution carries only commands"),
        (Route::CursorReadFile, Intent::Read(p)) => Ok((
            cursor(&json!({
                "hook_event_name": "beforeReadFile", "file_path": p,
                "content": "", "attachments": [],
            })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::CursorReadFile, _) => Err("beforeReadFile carries only file reads"),
        // `Shell` on `preToolUse` is left ungoverned by design: the same command
        // is decided on `beforeShellExecution` (cursor/pre_tool.rs).
        (Route::CursorPreTool, Intent::Shell(_)) => Err("Shell is decided on its own event"),
        (Route::CursorPreTool, Intent::Read(p)) => Ok((
            cursor_tool("Read", &json!({ "file_path": p })),
            Action::FsRead { path: p.clone() },
        )),
        // Cursor's third-party hooks reference: an edit is reported as `Write`.
        (Route::CursorPreTool, Intent::Write(p)) => Ok((
            cursor_tool("Write", &json!({ "file_path": p, "content": "new" })),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::CursorPreTool, Intent::Fetch(u)) => Ok((
            cursor_tool("WebFetch", &json!({ "url": u })),
            Action::Fetch { url: u.clone() },
        )),
        (Route::OpenClaw, Intent::Shell(c)) => {
            Ok((openclaw("exec", &json!({ "command": c })), shell(c)))
        }
        (Route::OpenClaw, Intent::Read(p)) => Ok((
            openclaw("read", &json!({ "path": p })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::OpenClaw, Intent::Write(p)) => Ok((
            openclaw(
                "edit",
                &json!({ "path": p, "edits": [{ "oldText": "old", "newText": "new" }] }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::OpenClaw, Intent::Fetch(u)) => Ok((
            openclaw("web_fetch", &json!({ "url": u, "extractMode": "markdown" })),
            Action::Fetch { url: u.clone() },
        )),
        (Route::CopilotCli, Intent::Shell(c)) => {
            Ok((copilot("bash", &json!({ "command": c })), shell(c)))
        }
        (Route::CopilotCli, Intent::Read(p)) => Ok((
            copilot("view", &json!({ "path": p })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::CopilotCli, Intent::Write(p)) => Ok((
            copilot(
                "edit",
                &json!({ "path": p, "old_str": "old", "new_str": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::CopilotCli, Intent::Fetch(u)) => Ok((
            copilot("web_fetch", &json!({ "url": u })),
            Action::Fetch { url: u.clone() },
        )),
        (Route::Pi, Intent::Shell(c)) => Ok((pi("bash", &json!({ "command": c })), shell(c))),
        (Route::Pi, Intent::Read(p)) => Ok((
            pi("read", &json!({ "path": p })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::Pi, Intent::Write(p)) => Ok((
            pi(
                "edit",
                &json!({ "path": p, "edits": [{ "oldText": "old", "newText": "new" }] }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::Pi, Intent::Fetch(_)) => Err("pi has no fetch tool"),
        // On Windows Gemini CLI runs PowerShell, which is never classified.
        (Route::GeminiCli, Intent::Shell(_)) if cfg!(windows) => {
            Err("Gemini CLI runs PowerShell on Windows")
        }
        (Route::GeminiCli, Intent::Shell(c)) => Ok((
            gemini("run_shell_command", &json!({ "command": c })),
            shell(c),
        )),
        (Route::GeminiCli, Intent::Read(p)) => Ok((
            gemini("read_file", &json!({ "file_path": p })),
            Action::FsRead { path: p.clone() },
        )),
        (Route::GeminiCli, Intent::Write(p)) => Ok((
            gemini(
                "replace",
                &json!({ "file_path": p, "old_string": "old", "new_string": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        (Route::GeminiCli, Intent::Fetch(u)) => Ok((
            gemini("web_fetch", &json!({ "prompt": format!("Summarise {u}") })),
            Action::Fetch { url: u.clone() },
        )),
        (Route::ClaudeCodeNoPrompt, _) => unreachable!("sends Claude Code's tools"),
    }
}

/// Claude Code and Codex `PreToolUse` (`tests/fixtures/hosts/{claude-code,codex}`).
fn pre_tool_use(route: Route, tool: &str, input: &Value) -> Value {
    match route {
        Route::Codex => json!({
            "session_id": "codex-1", "turn_id": "t-1", "cwd": CWD,
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_use_id": "call_1", "tool_input": input,
        }),
        Route::ClaudeCodeNoPrompt => json!({
            "session_id": "claude-2", "cwd": CWD, "permission_mode": "bypassPermissions",
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": input, "tool_use_id": "toolu_2",
        }),
        _ => json!({
            "session_id": "claude-1", "cwd": CWD, "permission_mode": "default",
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": input, "tool_use_id": "toolu_1",
        }),
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The conformance fixture `id`, which must be a plain intent.
fn fixture(id: &str) -> (Intent, Expect) {
    let dir = repo_root().join("tests/conformance");
    for name in ["attacks.yaml", "ask.yaml", "benign.yaml"] {
        let text = fs::read_to_string(dir.join(name)).expect("conformance file");
        let fixtures: Vec<Fixture> = openmoat_core::yaml::from_str(&text).expect(name);
        let Some(f) = fixtures.into_iter().find(|f| f.id == id) else {
            continue;
        };
        let extras = [&f.context, &f.session, &f.repo, &f.links, &f.resolve];
        assert!(
            extras.iter().all(|e| e.is_none()),
            "{id}: not a plain intent (context, session, repo, links or resolve)"
        );
        let a = f.action;
        let intent = match (a.shell, a.fs_read, a.fs_write, a.fetch) {
            (Some(c), None, None, None) => Intent::Shell(c),
            (None, Some(p), None, None) => Intent::Read(p),
            (None, None, Some(p), None) => Intent::Write(p),
            (None, None, None, Some(u)) => Intent::Fetch(u),
            _ => panic!("{id}: the action is not one shell, fs_read, fs_write or fetch"),
        };
        return (intent, f.expect);
    }
    panic!("no conformance fixture `{id}`");
}

/// What the host receives for `payload`, decided as `moat guard` decides it
/// with no session history, grant or lock drift.
fn decide(host: Host, payload: &str) -> Result<(Action, Decision), String> {
    let request = host.parse_request(payload).map_err(|e| e.to_string())?;
    let action = request
        .action
        .clone()
        .ok_or("the adapter left the call ungoverned")?;
    let ctx = EvalContext {
        home: HOME.into(),
        project: Some(CWD.into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: request.cwd.clone().unwrap_or_else(|| CWD.into()),
        case_insensitive_paths: false,
    };
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy must lint");
    let compiled = CompiledPolicy::compile(&policy, &ctx).expect("default policy must compile");
    let links = MapPathResolver::default();
    let decision = compiled.decide_with(&action, &MapResolver::default(), &links);
    let decision = compiled.with_taint(decision, &action, &links, &Taint::default());
    let decision = host.decided(&request.event, decision);
    Ok((action, host.answer(&request.event, &decision)))
}

/// Every route of the row's intent gets the fixture's verdict and rules.
fn check(id: &str) {
    let (intent, expect) = fixture(id);
    let mut checked = Vec::new();
    let mut mismatches = Vec::new();
    for route in ROUTES {
        let Ok((payload, want_action)) = payload(route, &intent) else {
            continue;
        };
        let want = received(route, expect.verdict);
        match decide(route.host(), &payload.to_string()) {
            Err(error) => mismatches.push(format!("{route:?}: {error}")),
            Ok((action, _)) if action != want_action => {
                mismatches.push(format!(
                    "{route:?}: read as {action:?}, not {want_action:?}"
                ));
            }
            Ok((_, got)) => {
                let missing: Vec<_> = expect
                    .rules
                    .iter()
                    .filter(|r| !got.rules.contains(r))
                    .collect();
                if got.verdict != want || !missing.is_empty() {
                    mismatches.push(format!(
                        "{route:?}: expected {want:?} {:?}, got {:?} {:?}",
                        expect.rules, got.verdict, got.rules
                    ));
                }
            }
        }
        checked.push(route);
    }
    assert!(
        checked.len() >= 2,
        "{id}: fewer than two routes, nothing to compare"
    );
    assert!(
        mismatches.is_empty(),
        "{id} ({intent:?}):\n  {}",
        mismatches.join("\n  ")
    );
}

/// The event a payload is answered for, so a route that changes event cannot
/// slip past [`received`] unseen.
#[test]
fn routes_use_the_events_the_translation_assumes() {
    let read = Intent::Read("/p/x".into());
    let shell = Intent::Shell("true".into());
    for (route, intent, event) in [
        (Route::ClaudeCode, &shell, HookEvent::PreToolUse),
        (
            Route::ClaudeCodeNoPrompt,
            &shell,
            HookEvent::PreToolUseNoAsk,
        ),
        (Route::Codex, &shell, HookEvent::PreToolUse),
        (Route::CursorShell, &shell, HookEvent::PreToolUse),
        (Route::CursorReadFile, &read, HookEvent::PreToolUseNoAsk),
        (Route::CursorPreTool, &read, HookEvent::PreToolUseNoAsk),
        (Route::OpenClaw, &shell, HookEvent::PreToolUse),
        (Route::CopilotCli, &read, HookEvent::PreToolUse),
        (Route::Pi, &shell, HookEvent::PreToolUse),
        (Route::GeminiCli, &read, HookEvent::PreToolUse),
    ] {
        let (payload, _) = payload(route, intent).expect("route has the tool");
        let request = route.host().parse_request(&payload.to_string()).unwrap();
        assert_eq!(request.event, event, "{route:?}");
    }
}

macro_rules! rows {
    ($($(#[$meta:meta])* $name:ident => $id:literal,)*) => {
        $( $(#[$meta])* #[test] fn $name() { check($id); } )*
    };
}

rows! {
    // Reading a protected file: a file tool, and a shell command for every host.
    read_protected_file => "T2-read-aws-credentials",
    read_protected_file_by_shell => "T1-cat-ssh-key",
    read_dotenv_in_project => "T2-read-dotenv-in-project",
    read_dotenv_by_shell => "T2-shell-dotenv-without-prefix",
    // The agent changing OpenMoat's own policy, or deleting the home directory.
    write_moat_policy => "T9-edit-moat-policy",
    file_tool_deletes_home => "T4-file-tool-deletes-home",
    // A known token sent off its service: by shell, and by a fetch tool to an
    // allowed host of another service.
    token_to_wrong_host_by_shell => "T1-token-in-curl-header",
    token_to_wrong_host_by_fetch => "T12-token-in-fetch-query-to-allowed-host",
    // Writing a CI workflow, which runs later: a file tool, and a shell redirect.
    write_ci_workflow => "ask-write-github-workflow",
    write_ci_workflow_by_shell => "ask-echo-into-github-workflow",
    // Installing a near miss of a popular package name.
    package_near_miss_npm => "T5-npm-typosquat",
    package_near_miss_pip => "T5-pip-typosquat",
    // A plain install, left to the host (defer).
    plain_install_defers => "defer-install-a-dependency",
    // Plain project work.
    plain_project_edit => "benign-write-source",
    plain_project_read => "benign-read-relative",
    // Fetches: a registry is allowed, an unknown host is left to the host.
    allowed_fetch => "benign-webfetch-registry",
    unknown_host_fetch_defers => "ask-webfetch-unknown-host",
}
