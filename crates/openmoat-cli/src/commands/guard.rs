//! `moat guard --host <id>`: the hook entry point.
//!
//! Reads one hook payload from stdin, decides, records, and answers on stdout.
//! Every failure path produces a `deny` response and exit code 2: a kernel
//! that cannot evaluate must not let the action through.

use std::io::{self, Read as _, Write as _};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{KnownSecrets, Store};
use openmoat_core::{CompiledPolicy, Decision, Verdict};
use openmoat_hosts::{HookEvent, HookRequest, Host};
use record::{Recorded, record};

use crate::approvals::{self, Grants};
use crate::cli::GuardArgs;
use crate::context;
use crate::environment::{Snapshot, WithOwnBinary};
use crate::exit::Code;
use crate::guard_relay::{self, MAX_PAYLOAD_BYTES};
use crate::hangs::{self, Phase};
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::integrity::{self, Drift};
use crate::realpath::FsPathResolver;
use crate::{notice, push, render, secrets, session_code, taint, time};

mod capture;
mod config_change;
mod drift;
mod placed;
mod post_tool_use;
mod record;
mod required;
mod session_start;
mod unseen;

pub(crate) const UNGOVERNED_RULE: &str = "ungoverned";
pub(crate) const KERNEL_ERROR_RULE: &str = "kernel-error";
const SESSION_GRANT_RULE: &str = "approved-session";

/// How far into [`GUARD_BUDGET_S`] the session's taint may be folded, leaving
/// time to record: a session too long to fold in time is denied with a
/// recorded reason, its progress kept, rather than by the budget's deny.
pub(crate) const TAINT_BUDGET: Duration = Duration::from_secs(GUARD_BUDGET_S * 2 / 3);

/// The least time a call that got here late on a loaded machine still gets to
/// read on a few events from its session's cache row.
const MIN_TAINT_TIME: Duration = Duration::from_secs(1);

pub fn run(args: &GuardArgs) -> Code {
    let host = args.host;
    // The hook's command line names the state directory; the environment the
    // host gave the hook does not get to (ADR-071).
    if let Some(word) = &args.home
        && let Err(error) = crate::home::pin(word, std::env::var_os(crate::home::ENV).as_deref())
    {
        let error = error.context("the hook's state directory");
        if args.heartbeat {
            eprintln!("moat: {error:#}");
            return Code::Deny;
        }
        return respond(host, &HookEvent::default(), &kernel_error(&error));
    }
    if args.heartbeat {
        return heartbeat(host);
    }
    deny_when_over_budget(host, Instant::now());
    // A panic would exit 101, which Claude Code treats as a non-blocking hook
    // failure, i.e. the call would proceed. Turn it into an explicit deny.
    // The deny is in the format of the payload's event once it was read.
    let by_run = args.relayed;
    let mut event = HookEvent::default();
    let decided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decide_and_respond(host, by_run, &mut event)
    }));
    if let Ok(code) = decided {
        return code;
    }
    let decision = kernel_error(&anyhow::Error::msg("internal error while deciding"));
    respond(host, &event, &decision)
}

/// Debug builds panic where this variable names, so the end-to-end tests can
/// show that a panic on the guard path is a deny (invariant 4). Release builds
/// do not read it.
#[cfg(debug_assertions)]
const PANIC_ENV: &str = "MOAT_TEST_PANIC_AT";

/// Panic when [`PANIC_ENV`] names `point`: the test of invariant 4 needs a
/// real panic on the guard path.
#[cfg(debug_assertions)]
fn fault_point(point: &str) {
    assert!(
        std::env::var(PANIC_ENV).ok().is_none_or(|v| v != point),
        "{PANIC_ENV}={point}"
    );
}

#[cfg(not(debug_assertions))]
fn fault_point(_: &str) {}

/// `--heartbeat`: the plugin's report that its host loaded it (ADR-042). No
/// call is decided and nothing is read from stdin or written to stdout; a
/// report that cannot be written exits 2, which the plugin ignores. Inside
/// `openmoat run` the sandbox holds no state directory: the report is skipped,
/// and the run's decisions for the host show the plugin loaded instead.
fn heartbeat(host: Host) -> Code {
    let home = Home::locate().ok();
    let env = |var: &str| std::env::var(var).ok();
    if let guard_relay::Relay::Inside(_) = guard_relay::relay(&env, home.as_ref()) {
        return Code::Ok;
    }
    match Home::locate().and_then(|home| crate::heartbeat::report(&home, host, time::now_ms())) {
        Ok(()) => Code::Ok,
        Err(error) => {
            eprintln!("moat: could not record that {host} loaded the plugin: {error:#}");
            Code::Deny
        }
    }
}

/// A hook the host times out counts as failed, and most hosts then run the
/// call, so after [`GUARD_BUDGET_S`] the guard denies on its own, in the
/// default event's format; exit 2 denies whatever the event. The deny goes to
/// the side file of [`hangs`], not the audit log: what is stuck may be the log.
/// The line names the phase the guard was in and how long it had run, so a
/// slow machine can be told from a stuck step. Exiting while the main thread is
/// inside the audit store's `BEGIN IMMEDIATE` is deliberate (fail closed): the
/// OS drops the write lock, and the next open of the log drops the unfinished row.
fn deny_when_over_budget(host: Host, started: Instant) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(GUARD_BUDGET_S));
        let phase = hangs::current();
        let decision = kernel_error(&anyhow::Error::msg(format!(
            "no decision within {GUARD_BUDGET_S} s"
        )));
        if let Some(code) = answer_once(host, &Answer::To(&HookEvent::default()), &decision) {
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
    answer_once(host, &Answer::To(event), decision).unwrap_or(Code::Deny)
}

/// What a response answers: the call the payload described, or, when it could
/// not be read, only its event.
enum Answer<'a> {
    For(&'a HookRequest),
    To(&'a HookEvent),
}

/// Write `decision` for `answer` and return the exit code that goes with it, or
/// `None` when a response was already written.
fn answer_once(host: Host, answer: &Answer<'_>, decision: &Decision) -> Option<Code> {
    let mut responded = RESPONDED.lock().unwrap_or_else(PoisonError::into_inner);
    if *responded {
        return None;
    }
    *responded = true;
    let response = match answer {
        Answer::For(request) => host.render_response_for(request, decision),
        Answer::To(event) => host.render_response(event, decision),
    };
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
        Verdict::Allow | Verdict::Defer | Verdict::Review => Code::Ok,
        // `Deny`, and any verdict added to the core later, blocks the call.
        _ => {
            // Hosts may show hook stderr in a terminal; the reason quotes the call.
            eprintln!(
                "{}",
                render::clean_lines(&openmoat_hosts::reason_line(decision))
            );
            Code::Deny
        }
    })
}

/// `by_run`: `openmoat run` relayed the call from inside its sandbox
/// (`--relayed`). `event` is set to the payload's event as soon as it is read,
/// for the deny [`run`] answers with if this panics.
fn decide_and_respond(installed_for: Host, by_run: bool, event: &mut HookEvent) -> Code {
    let started = Instant::now();
    // Inside `moat run` the sandbox holds no OpenMoat home: the run decides
    // (ADR-028). Only there: a guard that can open its lock, or that no sandbox
    // of `openmoat run` holds, decides itself whatever its environment says.
    let env = |var: &str| std::env::var(var).ok();
    let stray_relay = match guard_relay::relay(&env, Home::locate().ok().as_ref()) {
        guard_relay::Relay::Inside(endpoint) => return relayed(installed_for, endpoint, started),
        guard_relay::Relay::Outside => true,
        guard_relay::Relay::Unset => false,
    };

    // The event is read separately so a payload that cannot be parsed is still
    // refused in the format its hook expects.
    let mut host = installed_for;
    let mut out = Evaluated::default();
    hangs::enter(Phase::Stdin);
    let (mut request, mut decision) = match read_stdin(installed_for) {
        Ok(payload) => {
            // The Continue CLI runs the Claude Code hook but cannot prompt.
            host = installed_for.sender(&payload, caller_set());
            *event = host.event_of(&payload);
            // What a call returned: nothing to decide or record (ADR-057).
            if matches!(event, HookEvent::PostToolUse { .. }) {
                return post_tool_use::answer(host, &payload, event);
            }
            // Inside `openmoat run` only when the run relayed it and named its session.
            let run = std::env::var(taint::run::RUN_SESSION_ENV).ok();
            let within_run = by_run && taint::run::run_session(run.as_deref()).is_some();
            evaluate(host, &payload, &mut out, (started, within_run))
                .unwrap_or_else(|error| (None, kernel_error(&error)))
        }
        Err(error) => (None, kernel_error(&error)),
    };

    // Where the host would approve a `review` no person sees, it is a deny.
    if let Some(r) = &mut request
        && decision.verdict == Verdict::Review
    {
        unseen::mark(host, r);
    }
    // Where the host has no flow of its own for `defer`, OpenMoat holds the call for review (ADR-025).
    // Last: a `review` a person approved from another device runs once, and
    // one not yet sent is sent (ADR-078); anything else is left as it is.
    if let Some(r) = &request {
        decision = crate::remote::gated(r, host.decided(&r.event, decision), &out.known);
    }
    // What the agent and its person read about a deny or review (ADR-059);
    // presentation only, never recorded. A deny that replaces the decision
    // below carries its own, without the call ([`kernel_error`]).
    let call = request
        .as_ref()
        .map(|r| (r.tool.as_str(), r.action.as_ref()));
    decision.notice = notice::of(&decision, &out.titles, call, &out.known);
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
        relayed: by_run,
    };
    if let Err(error) = record(host, recorded) {
        decision = kernel_error(&error.context("audit log unavailable"));
    } else if let Some(pending) = &out.proxy_credential
        && let Err(error) = pending.write()
    {
        decision = kernel_error(&error.context("writing the session's environment file"));
    }
    if stray_relay {
        // A note beside the call's row; the call stays as decided.
        record::relay_outside(host, request.as_ref());
    }

    hangs::enter(Phase::Answer);
    let event = request
        .as_ref()
        .map_or_else(|| event.clone(), |r| r.event.clone());
    // What the host receives can be stricter than what was decided and recorded
    // (Codex and the Continue CLI cannot prompt, so a `review` reaches them as a `deny`).
    let decision = host.answer(&event, &decision);
    let code = match &request {
        Some(request) => answer_once(host, &Answer::For(request), &decision).unwrap_or(Code::Deny),
        None => respond(host, &event, &decision),
    };
    // Only once the host has its answer (ADR-081): live audit delivery runs
    // detached and changes nothing above.
    crate::delivery::kick_located();
    code
}

/// Whether this hook has the variable of a host running another host's hook.
fn caller_set() -> bool {
    Host::caller_variable().is_some_and(|variable| std::env::var_os(variable).is_some())
}

/// Under `moat run`: the call goes to the run's process outside the sandbox,
/// and its answer is printed as it came. Whatever fails denies here, in the
/// format the payload's hook expects; nothing is recorded from in here.
fn relayed(installed_for: Host, endpoint: Result<guard_relay::Endpoint>, started: Instant) -> Code {
    hangs::enter(Phase::Stdin);
    let payload = match read_stdin(installed_for) {
        Ok(payload) => payload,
        Err(error) => {
            return respond(installed_for, &HookEvent::default(), &kernel_error(&error));
        }
    };
    let caller_set = caller_set();
    let host = installed_for.sender(&payload, caller_set);
    let event = host.event_of(&payload);
    let budget = Duration::from_secs(GUARD_BUDGET_S).saturating_sub(started.elapsed());
    hangs::enter(Phase::Relay);
    match endpoint.and_then(|e| e.decide(installed_for, &payload, caller_set, budget)) {
        Ok(reply) => {
            hangs::enter(Phase::Answer);
            relay_once(&reply)
        }
        Err(error) => {
            let error = error.context("`openmoat run` did not decide this call");
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

/// What deciding a call leaves for [`record()`], besides the decision.
#[derive(Default)]
struct Evaluated {
    /// The brokered secret values to mask in the audit row, set as soon as
    /// the policy is loaded, so it holds them even when a later step fails.
    known: KnownSecrets,
    /// The session's fold to store, written with the record so the call
    /// opens one writable handle.
    cache: Option<taint::CacheWrite>,
    /// The settings drift the lock let the call be decided through ([`integrity::check`]).
    drifted: Vec<Drift>,
    /// The file provenance rows the call adds when it runs (ADR-029).
    provenance: taint::provenance::Seen,
    /// A session start's `openmoat proxy` credential, written to the
    /// session's environment file once its row is recorded (ADR-044).
    proxy_credential: Option<session_start::Pending>,
    /// The titles the person's policy gives the decision's rules, for the
    /// block message (ADR-059).
    titles: notice::Titles,
}

/// Decide one hook payload, filling `out` as it goes. `started` is when the
/// guard started, which its budget counts from; `within_run`, whether the call
/// runs inside `openmoat run`'s sandbox.
fn evaluate(
    host: Host,
    payload: &str,
    out: &mut Evaluated,
    (started, within_run): (Instant, bool),
) -> Result<(Option<HookRequest>, Decision)> {
    hangs::enter(Phase::Lock);
    let request = host
        .parse_request(payload)
        .context("parsing hook payload")?;
    fault_point("evaluate");
    let home = Home::locate()?;

    if let HookEvent::SessionStart { .. } = &request.event {
        let env = |name: &str| std::env::var_os(name);
        let (decision, pending) = session_start::decision(&home, &request, &env, within_run)?;
        out.proxy_credential = pending;
        return Ok((Some(request), decision));
    }
    if let HookEvent::ConfigChange {
        source,
        change_type,
    } = &request.event
    {
        let change = change_type.as_deref().unwrap_or("changed");
        let decision = config_change::decision(&home, &request, source, change)?;
        return Ok((Some(request), decision));
    }
    // Lock before decide, ungoverned tools included: an `allow` while pinned
    // files drifted would tell whoever tampered that nothing noticed. Drift of
    // only Claude Code toggles and permission lists changes no decision, so the
    // call is decided as usual and the drift recorded (`integrity/relaxed.rs`).
    let verified = integrity::check(&home)?;
    if let Some(decision) = verified.checked.deny {
        return Ok((Some(request), decision));
    }
    out.drifted = verified.checked.relaxed;
    // From here each pinned state file is read as the lock check matched it.
    let home = verified.home;
    let request = placed::placed(&home, host, request, &out.drifted)?;
    // A server whose definition a person has not accepted runs a command
    // nobody reviewed; only its own tool calls are held back (ADR-026).
    if let Some(openmoat_core::Action::McpTool { name, .. }) = &request.action {
        let cwd = request.cwd.as_deref().map(std::path::Path::new);
        if let Some(decision) = crate::mcp::violation(&home, &verified.lock, host, cwd, name)? {
            return Ok((Some(request), decision));
        }
    }
    let Some(action) = &request.action else {
        let call = required::Call {
            home: &home,
            host,
            drifted: &out.drifted,
            within_run,
        };
        let decision = required::ungoverned(&call, &request, ungoverned(host));
        return Ok((Some(request), decision));
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
    // An agent below the level the policy requires gets no decision but this
    // deny, on every call (ADR-064); nothing to read when none is required.
    let call = required::Call {
        home: &home,
        host,
        drifted: &out.drifted,
        within_run,
    };
    if let Some(decision) = required::unmet(&call, &policy) {
        return Ok((Some(request), decision));
    }
    let snapshot = Snapshot::load_in(&home)?;
    hangs::enter(Phase::Compile);
    let compiled = CompiledPolicy::compile(&policy, &ctx)?;
    let programs = WithOwnBinary {
        snapshot: &snapshot,
        binary: &verified.lock.binary,
    };
    let decision = compiled.decide_with(action, &programs, &FsPathResolver);
    // A write that leaves a project settings file turning its host's hook off;
    // only tightens, and before the grant, which cannot lift a deny.
    let decision = crate::project_settings::written::checked(&home, &request, &ctx, decision);
    hangs::enter(Phase::Taint);
    let store = home.open_audit()?;
    // A part of the call that came from untrusted output the session read
    // (ADR-057); before the grant, so a person's grant for this exact call
    // answers it.
    let session_of = (host, request.session_id.as_str());
    let mut decision =
        taint::injected::checked(&home, &store, session_of, &compiled, action, decision)?;
    // A grant a person made with `moat allow` turns a `review` or a `defer` into an
    // `allow` (Cursor's file tools get a review for a defer, so they need it); a deny stays a deny.
    if matches!(decision.verdict, Verdict::Review | Verdict::Defer)
        && let Some(reviewed) = approvals::approvable(action, Some(&ctx.cwd), &ctx.home)
        && Grants::load_in(&home)?.matches(
            approvals::Scope {
                host: host.id(),
                session_id: &request.session_id,
                project: &approvals::project_in(&ctx),
            },
            &reviewed,
            crate::time::now_ms(),
        )
    {
        decision = Decision::new(Verdict::Allow);
        decision.rules.push(SESSION_GRANT_RULE.to_owned());
        decision
            .reasons
            .push("approved for this session with `openmoat allow`".to_owned());
    }
    // After the grant: taint only tightens, and a grant made before the
    // session read a secret did not approve sending that secret anywhere.
    // A grant made after the session read untrusted content answers that
    // content's review for this exact call (taint.rs).
    // A long fold saves what it reached as it goes, on a writable handle, so
    // the next call reads on even if this one runs out of time.
    let audit = home.audit_path();
    let mut save = |write: &taint::CacheWrite| {
        if let Ok(writable) = Store::open_existing(&audit) {
            write.write(&writable);
        }
    };
    let mut progress = taint::Progress {
        deadline: (started + TAINT_BUDGET).max(Instant::now() + MIN_TAINT_TIME),
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
        edits: &request.edits,
        untrusted: session.taint.untrusted.as_deref(),
    };
    out.provenance = taint::provenance::observe(&store, &compiled, &seen)?;
    let tainted = compiled.with_taint(decision.clone(), action, &FsPathResolver, &session.taint);
    let call = taint::Call {
        home: &home,
        store: &store,
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
    // A send of data after the session collected files outside the project
    // (ADR-061, proposed): decided where a rule names `@staging-egress`,
    // otherwise only recorded in the reasons.
    let decision = compiled.with_staging(
        decision,
        action,
        &FsPathResolver,
        &session.staging,
        &taint::is_dir,
    );
    // Code this session wrote, run with no OS sandbox below the hook; only
    // tightens (ADR-039). Part of the taint phase: it reads the audit log.
    let code = session_code::Call {
        home: &home,
        host,
        session: &request.session_id,
        action,
        cwd: &ctx.cwd,
        user_home: &ctx.home,
        writes: &out.provenance.written,
        within_run,
    };
    let sandboxed = || crate::protection::os_sandboxed_by_lock(&home, host, &out.drifted);
    let decision = session_code::checked(
        &code,
        &compiled,
        &store,
        decision,
        (crate::time::now_ms(), &sandboxed),
    )?;
    // Another MCP server's result carried into a tool that acts; only
    // tightens (ADR-058).
    let flow = crate::mcp::flow::Sink {
        home: &home,
        store: &store,
        host,
        session: &request.session_id,
        action,
        arguments: request.mcp_arguments.as_deref(),
        policy: compiled.policy(),
    };
    let decision = crate::mcp::flow::checked(&flow, decision)?;
    drop(store);
    // Last: a push is checked for what it would publish (push.rs); only tightens.
    let tainted = session.taint.untrusted.is_some() || !session.taint.secrets.is_empty();
    let pushes = compiled.pushes(action);
    let decision = push::check(&pushes, &snapshot, &out.known, tainted, decision);
    out.titles = notice::Titles::of(compiled.policy(), &decision);
    Ok((Some(request), decision))
}

/// The hook payload on stdin, up to the limit for `host`: [`MAX_PAYLOAD_BYTES`]
/// for each copy of the call's arguments its payload carries
/// ([`openmoat_hosts::HostSpec::payload_copies`]), so a file is refused at the
/// same size whichever agent writes it.
fn read_stdin(host: Host) -> Result<String> {
    let limit = guard_relay::payload_limit(host);
    let mut payload = String::new();
    // One byte past the limit tells a payload that is too large from one that
    // only ends there; cut off, it would fail as malformed JSON instead.
    io::stdin()
        .lock()
        .take(limit + 1)
        .read_to_string(&mut payload)
        .context("reading hook payload from stdin (must be UTF-8)")?;
    if payload.len() as u64 > limit {
        bail!(
            "this tool call's arguments are larger than {} MiB, more than OpenMoat checks in \
             one call, so it is refused unchecked; write the file in smaller parts (create \
             it, then append to it)",
            MAX_PAYLOAD_BYTES / (1024 * 1024)
        );
    }
    if payload.trim().is_empty() {
        bail!("empty hook payload on stdin");
    }
    capture::keep(host, &payload);
    Ok(payload)
}

/// A tool OpenMoat does not govern is recorded, and the host decides it as if no
/// hook had answered (ADR-025): an `allow` would skip the host's own prompt and
/// permission rules for a tool nobody checked. A host whose hooks have no "no
/// decision" gets an `allow` instead (`Reviews::ungoverned`).
fn ungoverned(host: Host) -> Decision {
    let mut decision = Decision::new(host.spec().reviews.ungoverned);
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
    // Its words are OpenMoat's own (ADR-059), so the deny that answers a
    // panic, the budget or an unwritable log reads as every other one does.
    decision.notice = notice::of(
        &decision,
        &notice::Titles::default(),
        None,
        &KnownSecrets::default(),
    );
    decision
}
