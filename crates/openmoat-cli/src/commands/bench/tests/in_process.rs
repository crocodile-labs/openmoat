//! The scenarios of ADR-039 and the benign and MCP categories decided
//! in-process: the default policy, the session's taint from its earlier
//! steps, the files each session wrote and the session-code check, as
//! `openmoat guard` applies them, without hook payloads
//! or an audit log on disk the end-to-end bench needs. An MCP step is the
//! action `openmoat mcp proxy` decides too (ADR-045). Each runs with and
//! without an OS sandbox.

use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, CompiledPolicy, Decision, EvalContext, NoResolver, Policy, Verdict};
use openmoat_hosts::Host;
use std::time::{Duration, Instant};

use super::super::scenario::{Call, Scenario, scenarios};
use crate::home::Home;
use crate::realpath::FsPathResolver;
use crate::session_code;
use crate::taint::{self, provenance};

const HOME: &str = "/Users/me";

/// The scenarios whose steps depend on what the session wrote.
const SESSION_CODE: &[&str] = &[
    "agent-written-script-reads-the-ssh-key",
    "agent-written-shell-script-runs",
    "agent-written-script-through-inline-code",
    "inline-code-appends-to-a-shell-start-up-file",
    "inline-code-builds-the-secret-path",
    "inline-code-builds-the-token-name-or-host",
    "interpreter-inline-code",
];

fn action(call: &Call, proj: &str) -> Option<Action> {
    let path = |p: &str| match p.strip_prefix("~/") {
        Some(rest) => format!("{HOME}/{rest}"),
        None => format!("{proj}/{p}"),
    };
    Some(match call {
        Call::Shell(command) => Action::Shell {
            command: command.clone(),
        },
        Call::Read(p) => Action::FsRead { path: path(p) },
        Call::Write(p) | Call::Edit(p) => Action::FsWrite { path: path(p) },
        Call::Fetch(url) => Action::Fetch { url: url.clone() },
        Call::Mcp { server, tool, args } => {
            openmoat_hosts::mcp_call_action(&format!("mcp__{server}__{tool}"), args).ok()?
        }
    })
}

/// Every mismatch of `scenario` on a host that is `sandboxed` or not.
fn run(scenario: &Scenario, sandboxed: bool) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let proj = crate::context::path_string(&dir.path().canonicalize().unwrap()) + "/proj";
    let home = Home::at(dir.path().join("state"));
    let store = Store::open(&dir.path().join("audit.db")).unwrap();
    let policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
    let ctx = EvalContext {
        home: HOME.to_owned(),
        project: Some(proj.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: proj.clone(),
        case_insensitive_paths: false,
    };
    let compiled = CompiledPolicy::compile(&policy, &ctx).unwrap();
    let host = Host::GeminiCli;
    let mut problems = Vec::new();
    for (i, step) in scenario.steps.iter().enumerate() {
        let Some(action) = action(&step.call().unwrap(), &proj) else {
            return Vec::new();
        };
        let decided = compiled.decide_with(&action, &NoResolver, &FsPathResolver);
        // What the steps before exposed the session to, folded from the audit
        // log as the guard folds it (`session-taint` after untrusted content).
        let mut save = |_: &taint::CacheWrite| {};
        let mut progress = taint::Progress {
            deadline: Instant::now() + Duration::from_secs(10),
            save: &mut save,
            folded: 0,
        };
        let (session, _) =
            taint::of_session(&store, host, "s", &compiled, &proj, &mut progress).unwrap();
        let decided = compiled.with_taint(decided, &action, &FsPathResolver, &session.taint);
        let seen = provenance::observe(
            &store,
            &compiled,
            &provenance::Call {
                session: "s",
                action: &action,
                content: None,
                untrusted: session.taint.untrusted.as_deref(),
            },
        )
        .unwrap();
        let call = session_code::Call {
            home: &home,
            host,
            session: "s",
            action: &action,
            cwd: &proj,
            user_home: HOME,
            writes: &seen.written,
            within_run: false,
        };
        let decision: Decision = session_code::checked(
            &call,
            &compiled,
            &store,
            decided,
            (crate::time::now_ms(), &|| sandboxed),
        )
        .unwrap();
        let id = store
            .record(&NewEvent {
                host: host.id(),
                session_id: "s",
                call_id: None,
                cwd: None,
                tool: "t",
                action: Some(&action),
                decision: &decision,
                latency_us: 0,
            })
            .unwrap();
        if decision.verdict != Verdict::Deny {
            seen.write(&store, id, host.id(), "s").unwrap();
        }
        let (expect, rule) = step.expected(sandboxed);
        let rule_ok = rule.is_none_or(|r| decision.rules.iter().any(|d| d == r));
        if decision.verdict != expect || !rule_ok {
            problems.push(format!(
                "{} step {i} (sandboxed: {sandboxed}): expected {expect:?} {rule:?}, got {:?} {:?}",
                scenario.id, decision.verdict, decision.rules
            ));
        }
    }
    problems
}

#[test]
fn session_code_benign_and_mcp_scenarios_hold_in_process() {
    let mut problems = Vec::new();
    let mut ran = 0;
    for (category, scenario) in scenarios().unwrap() {
        if !["benign", "mcp"].contains(&category) && !SESSION_CODE.contains(&scenario.id.as_str()) {
            continue;
        }
        for sandboxed in [false, true] {
            ran += 1;
            problems.extend(run(&scenario, sandboxed));
        }
    }
    assert!(ran >= 2 * SESSION_CODE.len(), "{ran}");
    assert!(problems.is_empty(), "{problems:#?}");
}
