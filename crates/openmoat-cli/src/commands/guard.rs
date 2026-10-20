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
use crate::guard_relay::{self, MAX_PAYLOAD_BYTES};
use crate::hangs::{self, Phase};
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::integrity::{self, Drift};
use crate::realpath::FsPathResolver;
use crate::{push, render, secrets, taint, time};

mod config_change;
mod drift;

const UNGOVERNED_RULE: &str = "ungoverned";
const KERNEL_ERROR_RULE: &str = "kernel-error";
const SESSION_GRANT_RULE: &str = "approved-session";

/// How far into [`GUARD_BUDGET_S`] the session's taint may be folded, leaving
/// time to record: a session too long to fold in time is denied with a
/// recorded reason, its progress kept, rather than by the budget's deny.
const TAINT_BUDGET: Duration = Duration::from_secs(GUARD_BUDGET_S * 2 / 3);

pub fn run(args: &GuardArgs) -> Code {
    let host = args.host;
    deny_when_over_budget(host, Instant::now());
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
/// The line names the phase the guard was in and how long it had run, so a
/// slow machine can be told from a stuck step.
fn deny_when_over_budget(host: Host, started: Instant) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(GUARD_BUDGET_S));
        let phase = hangs::current();
        let decision = kernel_error(&anyhow::Error::msg(format!(
            "no decision within {GUARD_BUDGET_S} s"
        )));
        if let Some(code) = answer_once(host, &HookEvent::default(), &decision) {
            if let Ok(home) = Home::locate() {
                let elapsed_ms = started.elapsed().as_millis();
                hangs::record(&home, host, time::now_ms(), phase, elapsed_ms);
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
    // Inside `moat run` the sandbox holds no OpenMoat home: the run decides (ADR-028).
    if let Some(endpoint) = guard_relay::configured(&|var| std::env::var(var).ok()) {
        return relayed(installed_for, endpoint, started);
    }

    // The event is read separately so a payload that cannot be parsed is still
    // refused in the format its hook expects.
    let mut host = installed_for;
    let mut event = HookEvent::default();
    let mut out = Evaluated::default();
    hangs::enter(Phase::Stdin);
    let (request, mut decision) = match read_stdin() {
        Ok(payload) => {
            // The Continue CLI runs the Claude Code hook but cannot ask.
            let continue_env = std::env::var_os(openmoat_hosts::CONTINUE_ENV).is_some();
            host = installed_for.sender(&payload, continue_env);
            event = host.event_of(&payload);
            evaluate(host, &payload, &mut out, started)
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
    let recorded = Recorded {
        request: request.as_ref(),
        decision: &decision,
        drifted: &out.drifted,
        started,
        known: out.known,
        cache: out.cache,
        provenance: out.provenance,
    };
    if let Err(error) = record(host, recorded) {
        decision = kernel_error(&error.context("audit log unavailable"));
    }

    hangs::enter(Phase::Answer);
    let event = request.as_ref().map_or(event, |r| r.event.clone());
    // What the host receives can be stricter than what was decided and recorded
    // (Codex and the Continue CLI cannot ask, so an `ask` reaches them as a `deny`).
    let decision = host.answer(&event, &decision);
    respond(host, &event, &decision)
}

/// Under `moat run`: the call goes to the run's process outside the sandbox,
/// and its answer is printed as it came. Whatever fails denies here, in the
/// format the payload's hook expects; nothing is recorded from in here.
fn relayed(installed_for: Host, endpoint: Result<guard_relay::Endpoint>, started: Instant) -> Code {
    hangs::enter(Phase::Stdin);
    let payload = match read_stdin() {
        Ok(payload) => payload,
        Err(error) => {
            return respond(installed_for, &HookEvent::default(), &kernel_error(&error));
        }
    };
    let continue_env = std::env::var_os(openmoat_hosts::CONTINUE_ENV).is_some();
    let host = installed_for.sender(&payload, continue_env);
    let event = host.event_of(&payload);
    let budget = Duration::from_secs(GUARD_BUDGET_S).saturating_sub(started.elapsed());
    hangs::enter(Phase::Relay);
    match endpoint.and_then(|e| e.decide(installed_for, &payload, continue_env, budget)) {
        Ok(reply) => {
            hangs::enter(Phase::Answer);
            relay_once(&reply)
        }
        Err(error) => {
            let error = error.context("`moat run` did not decide this call");
            respond(host, &event, &kernel_error(&error))
        }
    }
}

/// Print `reply` as the guard outside the sandbox wrote it, unless the
/// budget's deny came first.
fn relay_once(reply: &guard_relay::Reply) -> Code {
    let mut responded = RESPONDED.lock().unwrap_or_else(PoisonError::into_inner);
    if *responded {
        return Code::Deny;
    }
    *responded = true;
    let mut stdout = io::stdout().lock();
    let written = stdout
        .write_all(&reply.stdout)
        .and_then(|()| stdout.flush());
    let _ = io::stderr().lock().write_all(&reply.stderr);
    if let Err(error) = written {
        eprintln!("moat: could not write the hook response: {error}");
        return Code::Deny;
    }
    if reply.code == 0 {
        Code::Ok
    } else {
        Code::Deny
    }
}

/// What deciding a call leaves for [`record`], besides the decision.
#[derive(Default)]
struct Evaluated {
    /// The brokered secret values to mask in the audit row, set as soon as
    /// the policy is loaded, so it holds them even when a later step fails.
    known: KnownSecrets,
    /// The session's fold to store, written with the record so the call
    /// opens one writable handle.
    cache: Option<taint::CacheWrite>,
    /// The settings drift the lock let the call be decided through
    /// ([`integrity::check`]).
    drifted: Vec<Drift>,
    /// The file provenance rows the call adds when it runs (ADR-029).
    provenance: taint::provenance::Seen,
}

/// Decide one hook payload, filling `out` as it goes. `started` is when the
/// guard started, which its budget counts from.
fn evaluate(
    host: Host,
    payload: &str,
    out: &mut Evaluated,
    started: Instant,
) -> Result<(Option<HookRequest>, Decision)> {
    hangs::enter(Phase::Lock);
    let request = host
        .parse_request(payload)
        .context("parsing hook payload")?;

    if let HookEvent::ConfigChange {
        source,
        change_type,
    } = &request.event
    {
        let change = change_type.as_deref().unwrap_or("changed");
        let decision = config_change::decision(&Home::locate()?, &request, source, change)?;
        return Ok((Some(request), decision));
    }
    // Lock before decide, ungoverned tools included: an `allow` while pinned
    // files drifted would tell whoever tampered that nothing noticed. Drift of
    // only Claude Code toggles and permission lists changes no decision, so the
    // call is decided as usual and the drift recorded (`integrity/relaxed.rs`).
    let home = Home::locate()?;
    let checked = integrity::check(&home)?;
    if let Some(decision) = checked.deny {
        return Ok((Some(request), decision));
    }
    out.drifted = checked.relaxed;
    // A server whose definition a person has not accepted runs a command
    // nobody reviewed; only its own tool calls are held back (ADR-026).
    if let Some(openmoat_core::Action::McpTool { name, .. }) = &request.action {
        let cwd = request.cwd.as_deref().map(std::path::Path::new);
        if let Some(decision) = crate::mcp::violation(&home, host, cwd, name)? {
            return Ok((Some(request), decision));
        }
    }
    let Some(action) = &request.action else {
        return Ok((Some(request), ungoverned(host)));
    };
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving working directory")?;
    hangs::enter(Phase::Context);
    let ctx = context::eval_context(&home, Some(&cwd), None)?;
    let policy = crate::repo::effective_policy(&home, &ctx)?;
    out.known = secrets::known(&policy.secrets, &ctx.home)?;
    let snapshot = Snapshot::load(&home.environment_path())?;
    hangs::enter(Phase::Compile);
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
    // A grant made after the session read untrusted content answers that
    // content's ask for this exact call (taint.rs).
    hangs::enter(Phase::Taint);
    let store = home.open_audit()?;
    // A long fold saves what it reached as it goes, on a writable handle, so
    // the next call reads on even if this one runs out of time.
    let audit = home.audit_path();
    let mut save = |write: &taint::CacheWrite| {
        if let Ok(writable) = Store::open_existing(&audit) {
            write.write(&writable);
        }
    };
    // A call that got here late on a loaded machine still gets a moment to
    // read on a few events from its cache row.
    let mut progress = taint::Progress {
        deadline: (started + TAINT_BUDGET).max(Instant::now() + Duration::from_secs(1)),
        save: &mut save,
        folded: 0,
    };
    let (session, write) = taint::of_session(
        &store,
        host,
        &request.session_id,
        &compiled,
        &ctx.cwd,
        &mut progress,
    )?;
    out.cache = write;
    let seen = taint::provenance::Call {
        session: &request.session_id,
        action,
        content: request.content.as_deref(),
        untrusted: session.taint.untrusted.as_deref(),
    };
    out.provenance = taint::provenance::observe(&store, &compiled, &seen)?;
    drop(store);
    let tainted = compiled.with_taint(decision.clone(), action, &FsPathResolver, &session.taint);
    let call = taint::Call {
        home: &home,
        host,
        session: &request.session_id,
        action,
        cwd: &ctx.cwd,
        user_home: &ctx.home,
    };
    let decision = taint::answered(
        &call,
        &compiled,
        &session,
        decision,
        tainted,
        crate::time::now_ms(),
    )?;
    // Last: a push is checked for what it would publish (push.rs); only tightens.
    let tainted = session.taint.untrusted.is_some() || !session.taint.secrets.is_empty();
    let decision = push::check(&compiled.pushes(action), &out.known, tainted, decision);
    Ok((Some(request), decision))
}

/// What [`record`] writes.
struct Recorded<'a> {
    request: Option<&'a HookRequest>,
    decision: &'a Decision,
    /// Settings drift the call was decided through; the first call of a
    /// session records it with its row, and the host's answer stays as decided.
    drifted: &'a [Drift],
    started: Instant,
    known: KnownSecrets,
    cache: Option<taint::CacheWrite>,
    provenance: taint::provenance::Seen,
}

/// Record the decision, after the session cache on the same handle. The cache
/// write never waits for the lock and its result is ignored; it is a separate
/// statement before the record's own transaction, so it cannot touch the
/// hash chain.
fn record(host: Host, recorded: Recorded<'_>) -> Result<()> {
    let Recorded {
        request,
        decision,
        drifted,
        started,
        known,
        cache,
        provenance,
    } = recorded;
    hangs::enter(Phase::Record);
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    let store = Store::open_existing(&home.audit_path())?;
    if let Some(cache) = cache {
        hangs::enter(Phase::Cache);
        // Before `with_secrets`: the cache is keyed as the unmasked reader reads it.
        cache.write(&store);
        hangs::enter(Phase::Record);
    }
    let store = store.with_secrets(known);
    let noted = match request {
        Some(r) => drift::noted(&store, &r.session_id, decision, drifted)?,
        None => None,
    };
    let decision = noted.as_ref().unwrap_or(decision);
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
    // A call that may have run wrote and read what it named (ADR-029); like
    // the row, provenance that cannot be written fails the call.
    if let Some(r) = request
        && taint::ran(host, decision.verdict)
    {
        provenance.write(&store, id, host.id(), &r.session_id)?;
    }
    // Under `moat run`, the run's proxy applies this session's taint too
    // (ADR-027); a link that cannot be written fails the call like the row.
    let run = std::env::var(taint::run::RUN_SESSION_ENV).ok();
    if let (Some(run), Some(r)) = (taint::run::run_session(run.as_deref()), request) {
        taint::run::link(&store, run, host, &r.session_id)?;
    }
    // A deferred call is the agent's to decide; OpenMoat stays quiet about it.
    if !matches!(decision.verdict, Verdict::Allow | Verdict::Defer) {
        eprintln!("moat: trace {id}  (moat show {id})");
    }
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut payload = String::new();
    // One byte past the limit tells a payload that is too large from one that
    // only ends there; cut off, it would fail as malformed JSON instead.
    io::stdin()
        .lock()
        .take(MAX_PAYLOAD_BYTES + 1)
        .read_to_string(&mut payload)
        .context("reading hook payload from stdin (must be UTF-8)")?;
    if payload.len() as u64 > MAX_PAYLOAD_BYTES {
        bail!(
            "this tool call is larger than {} MiB, more than OpenMoat reads, so it is \
             refused; ask the agent to write the file in smaller parts",
            MAX_PAYLOAD_BYTES / (1024 * 1024)
        );
    }
    if payload.trim().is_empty() {
        bail!("empty hook payload on stdin");
    }
    Ok(payload)
}

/// A tool OpenMoat does not govern is recorded, and the host decides it as if no
/// hook had answered (ADR-025): an `allow` would skip the host's own prompt and
/// permission rules for a tool nobody checked. Cursor's hooks have no "no
/// decision", so there it is an `allow`; the tools it sends ungoverned are
/// checked by their own hook events or name no path (`cursor/pre_tool.rs`).
fn ungoverned(host: Host) -> Decision {
    let verdict = if host == Host::Cursor {
        Verdict::Allow
    } else {
        Verdict::Defer
    };
    let mut decision = Decision::new(verdict);
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
