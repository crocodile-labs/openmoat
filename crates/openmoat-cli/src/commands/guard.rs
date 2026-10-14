//! `moat guard --host <id>`: the hook entry point.
//!
//! Reads one hook payload from stdin, decides, records, and answers on stdout.
//! Every failure path produces a `deny` response and exit code 2: a kernel
//! that cannot evaluate must not let the action through.

use std::io::{self, Read as _, Write as _};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{KnownSecrets, NewEvent, Store};
use openmoat_core::{CompiledPolicy, Decision, Verdict};
use openmoat_hosts::{HookEvent, HookRequest, Host};

use crate::approvals::{self, Grants};
use crate::cli::GuardArgs;
use crate::context;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::integrity::{self, INTEGRITY_RULE, Lock};
use crate::realpath::FsPathResolver;
use crate::{hangs, render, secrets, taint, time};

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const UNGOVERNED_RULE: &str = "ungoverned";
const KERNEL_ERROR_RULE: &str = "kernel-error";
const CONFIG_CHANGE_RULE: &str = "config-change";
const SESSION_GRANT_RULE: &str = "approved-session";

pub fn run(args: &GuardArgs) -> Code {
    let host = args.host;
    deny_when_over_budget(host);
    // A panic would exit 101, which Claude Code treats as a non-blocking hook
    // failure, i.e. the call would proceed. Turn it into an explicit deny.
    if let Ok(code) = std::panic::catch_unwind(|| decide_and_respond(host)) {
        return code;
    }
    let decision = kernel_error(&anyhow::Error::msg("internal error while deciding"));
    respond(host, &HookEvent::default(), &decision)
}

/// A hook the host times out counts as failed, and most hosts then run the
/// call, so after [`GUARD_BUDGET_S`] the guard denies on its own, in the
/// default event's format; exit 2 denies whatever the event. The deny goes to
/// the side file of [`hangs`], not the audit log: what is stuck may be the log.
fn deny_when_over_budget(host: Host) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(GUARD_BUDGET_S));
        let decision = kernel_error(&anyhow::Error::msg(format!(
            "no decision within {GUARD_BUDGET_S} s"
        )));
        if let Some(code) = answer_once(host, &HookEvent::default(), &decision) {
            if let Ok(home) = Home::locate() {
                hangs::record(&home, host, time::now_ms());
            }
            std::process::exit(code as i32);
        }
    });
}

/// Whether a response was written: the decision's or the budget's deny,
/// whichever comes first. The guard answers once.
static RESPONDED: Mutex<bool> = Mutex::new(false);

/// [`answer_once`]; when the budget's deny came first, its exit code.
fn respond(host: Host, event: &HookEvent, decision: &Decision) -> Code {
    answer_once(host, event, decision).unwrap_or(Code::Deny)
}

/// Write `decision` for `event` and return the exit code that goes with it, or
/// `None` when a response was already written.
fn answer_once(host: Host, event: &HookEvent, decision: &Decision) -> Option<Code> {
    let mut responded = RESPONDED.lock().unwrap_or_else(PoisonError::into_inner);
    if *responded {
        return None;
    }
    *responded = true;
    let response = host.render_response(event, decision);
    let mut stdout = io::stdout().lock();
    // An empty response is `defer` (ADR-025): no output at all, not even a newline.
    let written = if response.is_empty() {
        Ok(())
    } else {
        writeln!(stdout, "{response}")
    };
    if let Err(error) = written.and_then(|()| stdout.flush()) {
        // Without a response the host falls back to its own default, which
        // may be to proceed; exit 2 is the one signal every host honours.
        eprintln!("moat: could not write the hook response: {error}");
        return Some(Code::Deny);
    }
    Some(match decision.verdict {
        Verdict::Allow | Verdict::Defer | Verdict::Ask => Code::Ok,
        // `Deny`, and any verdict added to the core later, blocks the call.
        _ => {
            // Hosts may show hook stderr in a terminal; the reason quotes the call.
            eprintln!("{}", render::clean(&openmoat_hosts::reason_line(decision)));
            Code::Deny
        }
    })
}

fn decide_and_respond(installed_for: Host) -> Code {
    let started = Instant::now();

    // The event is read separately so a payload that cannot be parsed is still
    // refused in the format its hook expects.
    let mut host = installed_for;
    let mut event = HookEvent::default();
    let mut known = KnownSecrets::default();
    let (request, mut decision) = match read_stdin() {
        Ok(payload) => {
            // The Continue CLI runs the Claude Code hook but cannot ask.
            let continue_env = std::env::var_os(openmoat_hosts::CONTINUE_ENV).is_some();
            host = installed_for.sender(&payload, continue_env);
            event = host.event_of(&payload);
            evaluate(host, &payload, &mut known)
                .unwrap_or_else(|error| (None, kernel_error(&error)))
        }
        Err(error) => (None, kernel_error(&error)),
    };

    // Where the host has no flow of its own for `defer`, OpenMoat asks (ADR-025).
    if let Some(r) = &request {
        decision = host.decided(&r.event, decision);
    }
    // The audit log is part of the decision: a call that cannot be recorded
    // is not allowed, so a missing or unwritable log cannot hide activity.
    if let Err(error) = record(host, request.as_ref(), &decision, started, known) {
        decision = kernel_error(&error.context("audit log unavailable"));
    }

    let event = request.as_ref().map_or(event, |r| r.event.clone());
    // What the host receives can be stricter than what was decided and recorded
    // (Codex and the Continue CLI cannot ask, so an `ask` reaches them as a `deny`).
    let decision = host.answer(&event, &decision);
    respond(host, &event, &decision)
}

/// Decide one hook payload. `known` gets the brokered secret values to mask in
/// the audit row as soon as the policy is loaded, so it holds them even when a
/// later step fails.
fn evaluate(
    host: Host,
    payload: &str,
    known: &mut KnownSecrets,
) -> Result<(Option<HookRequest>, Decision)> {
    let request = host
        .parse_request(payload)
        .context("parsing hook payload")?;

    if let HookEvent::ConfigChange {
        source,
        change_type,
    } = &request.event
    {
        let change = change_type.as_deref().unwrap_or("changed");
        let decision =
            config_change_decision(&Home::locate()?, request.action.as_ref(), source, change)?;
        return Ok((Some(request), decision));
    }
    // Lock before decide, ungoverned tools included: an `allow` while pinned
    // files drifted would tell whoever tampered that nothing noticed.
    let home = Home::locate()?;
    if let Some(decision) = integrity::violation(&home)? {
        return Ok((Some(request), decision));
    }
    let Some(action) = &request.action else {
        return Ok((Some(request), ungoverned()));
    };
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving working directory")?;
    let ctx = context::eval_context(&home, Some(&cwd), None)?;
    let policy = crate::repo::effective_policy(&home, &ctx)?;
    *known = secrets::known(&policy.secrets, &ctx.home)?;
    let snapshot = Snapshot::load(&home.environment_path())?;
    let compiled = CompiledPolicy::compile(&policy, &ctx)?;
    let mut decision = compiled.decide_with(action, &snapshot, &FsPathResolver);
    // A grant a person made with `moat allow` turns an `ask` or a `defer` into an
    // `allow` (Cursor's file tools ask for a defer, so they need it); a deny stays a deny.
    if matches!(decision.verdict, Verdict::Ask | Verdict::Defer)
        && let Some(asked) = approvals::approvable(action, Some(&ctx.cwd), &ctx.home)
        && Grants::load(&home.grants_path())?.matches(
            host.id(),
            &request.session_id,
            &asked,
            crate::time::now_ms(),
        )
    {
        decision = Decision::new(Verdict::Allow);
        decision.rules.push(SESSION_GRANT_RULE.to_owned());
        decision
            .reasons
            .push("approved for this session with `moat allow`".to_owned());
    }
    // After the grant: taint only tightens, and a grant made before the
    // session read a secret did not approve sending that secret anywhere.
    let taint = taint::of_session(&home, host, &request.session_id, &compiled, &ctx.cwd)?;
    let decision = compiled.with_taint(decision, action, &FsPathResolver, &taint);
    Ok((Some(request), decision))
}

fn record(
    host: Host,
    request: Option<&HookRequest>,
    decision: &Decision,
    started: Instant,
    known: KnownSecrets,
) -> Result<()> {
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    let store = Store::open_existing(&home.audit_path())?.with_secrets(known);
    let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let event = NewEvent {
        host: host.id(),
        session_id: request.map_or("unknown", |r| r.session_id.as_str()),
        call_id: request.and_then(|r| r.call_id.as_deref()),
        cwd: request.and_then(|r| r.cwd.as_deref()),
        tool: request.map_or("unknown", |r| r.tool.as_str()),
        action: request.and_then(|r| r.action.as_ref()),
        decision,
        latency_us,
    };
    let id = store.record(&event)?;
    // A deferred call is the agent's to decide; OpenMoat stays quiet about it.
    if !matches!(decision.verdict, Verdict::Allow | Verdict::Defer) {
        eprintln!("moat: trace {id}  (moat show {id})");
    }
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut payload = String::new();
    io::stdin()
        .lock()
        .take(MAX_PAYLOAD_BYTES)
        .read_to_string(&mut payload)
        .context("reading hook payload from stdin (must be UTF-8)")?;
    if payload.trim().is_empty() {
        bail!("empty hook payload on stdin");
    }
    Ok(payload)
}

/// A settings file changed on disk. While any pinned file drifted, no change
/// is loaded: the session keeps the old settings and the drift is reported.
/// Otherwise a pinned file loads (it matches the lock), a settings-review copy
/// of one loads only if it leaves the pinned file as is, and an unpinned file
/// is audited and allowed.
fn config_change_decision(
    home: &Home,
    action: Option<&openmoat_core::Action>,
    source: &str,
    change: &str,
) -> Result<Decision> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let lock = Lock::load(&lock_path)?;
    // Checked whatever file the change names: settings load together, so an
    // unpinned file's change would also load a tampered pinned one (every tool
    // call is denied then anyway).
    let drift = lock.verify();
    if !drift.is_empty() {
        return Ok(drift_blocks_change(&drift));
    }
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
    let path = match action {
        Some(openmoat_core::Action::FsWrite { path }) => std::path::Path::new(path),
        Some(_) => bail!("config change for something other than a file"),
        // Claude Code may report a change without naming the file. Every pin
        // matches, and refusing the change would block the user's own edits
        // while protecting nothing the lock does not already cover.
        None => {
            decision.reasons.push(format!(
                "{source} {change} (no file named); every file pinned by OpenMoat matches the policy lock"
            ));
            return Ok(decision);
        }
    };
    // A settings-review copy holds exactly what its target will become, so the
    // target's pin decides: block unless the copy leaves the pinned file as is.
    // Only a person re-pins, and the hook cannot tell an owner's accept in
    // `/settings-review` from an agent's, so any edit of a pinned file is refused.
    if let Some(target) = path.to_str().and_then(openmoat_hosts::proposal_target)
        && lock.pins(std::path::Path::new(&target))
    {
        if let Some(drift) = lock.verify_proposal(path, std::path::Path::new(&target)) {
            let mut deny = Decision::new(Verdict::Deny);
            deny.rules.push(INTEGRITY_RULE.to_owned());
            deny.reasons.push(format!(
                "{drift}; OpenMoat pinned {target}, so the proposal is not applied. Edit the file yourself and run `moat doctor --accept` to change it"
            ));
            return Ok(deny);
        }
        decision
            .reasons
            .push(format!("{} leaves {target} as pinned", path.display()));
        return Ok(decision);
    }
    let pinned = if lock.pins(path) {
        "matches the policy lock"
    } else {
        "not pinned by OpenMoat"
    };
    decision
        .reasons
        .push(format!("{} {change}; {pinned}", path.display()));
    Ok(decision)
}

fn drift_blocks_change(drift: &[crate::integrity::Drift]) -> Decision {
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(format!(
            "{d} outside OpenMoat; the change is not loaded into this session. Run `moat doctor` to inspect, `moat doctor --accept` to accept it"
        ));
    }
    decision
}

fn ungoverned() -> Decision {
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push(UNGOVERNED_RULE.to_owned());
    decision
        .reasons
        .push("tool is outside policy scope".to_owned());
    decision
}

fn kernel_error(error: &anyhow::Error) -> Decision {
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(KERNEL_ERROR_RULE.to_owned());
    decision
        .reasons
        .push(format!("kernel could not evaluate this action: {error:#}"));
    decision
}
