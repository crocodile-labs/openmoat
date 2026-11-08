//! The side outside the sandbox: `moat run` decides each relayed hook call.
//!
//! A call whose token matches is decided by `moat guard`, started by this
//! process outside the sandbox with this process's access: the lock check,
//! policy, taint and audit row are exactly those of a hook outside `moat run`,
//! and [`RUN_SESSION_ENV`] makes it write the run's link row. A call with
//! another token is recorded and gets no answer.
//!
//! Every process in the run's sandbox holds the token, not only the agent's
//! hooks, so the token alone does not say whose call it is (ADR-070). The
//! service decides only calls of the run's own agent ([`Scope`]): the host
//! `openmoat run` started, or for a program OpenMoat does not know, the host
//! of the first call, and the sessions that are the run's: one the audit log
//! has never seen, or one the agent resumes with its own session start. A
//! call for another host or another session is refused with a row in the
//! run's session ([`RULE_HOST`], [`RULE_SESSION`]) and a deny.

use std::io::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{EventId, NewEvent, Store};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{HookEvent, Host};
use openmoat_proxy::coalesce::{Coalesce, INTERVAL, counted};
use openmoat_proxy::{LocalService, constant_time_eq};
use zeroize::Zeroizing;

use super::wire::{MAX_OUTPUT, REQUEST_MAGIC, Reply, Request};
use super::{SOCKET_ENV, Stream, TOKEN_ENV};
use crate::exit::Code;
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::taint::run::{LINK_HOST, RUN_SESSION_ENV, run_session};

/// The rule of the row a call with a wrong token leaves.
pub const RULE_TOKEN: &str = "run-guard-token";
/// The rule of the row a call for another agent than the run's leaves.
pub const RULE_HOST: &str = "run-guard-host";
/// The rule of the row a call in a session that is not the run's leaves.
pub const RULE_SESSION: &str = "run-guard-session";
/// The most agent sessions one run decides calls for: a start, `/clear`s,
/// resumes and subagents with sessions of their own fit well within it.
pub const MAX_SESSIONS: usize = 64;

/// Whose calls the run decides.
#[derive(Debug, Default)]
struct Scope {
    /// The run's agent; `None` until the first call when the program is no
    /// agent OpenMoat knows.
    host: Option<Host>,
    /// The agent sessions taken so far.
    sessions: Vec<String>,
}

/// A call outside the run's [`Scope`]: its row's rule and reason.
struct Refused {
    rule: &'static str,
    reason: String,
}

/// One run's decision service.
pub struct Service {
    home: Home,
    run: String,
    token: Zeroizing<Vec<u8>>,
    moat: PathBuf,
    scope: Mutex<Scope>,
    /// Calls with a wrong token not in a row yet.
    wrong_tokens: Coalesce<1>,
}

impl Drop for Service {
    /// The run ends: the wrong tokens still counted get their row.
    fn drop(&mut self) {
        for (_, count) in self.wrong_tokens.rest() {
            let _ = self.record_wrong_tokens(count);
        }
    }
}

impl Service {
    /// The service of run session `run`, which wants `token`. Calls are
    /// decided by `moat`, the binary this process runs, for `agent`, the host
    /// of the program the run started (`None`: no agent OpenMoat knows).
    pub fn new(home: Home, run: &str, token: &[u8], moat: PathBuf, agent: Option<Host>) -> Self {
        Self {
            home,
            run: run.to_owned(),
            token: Zeroizing::new(token.to_vec()),
            moat,
            scope: Mutex::new(Scope {
                host: agent,
                sessions: Vec::new(),
            }),
            wrong_tokens: Coalesce::default(),
        }
    }

    /// Read one call from `stream` and answer it. An error means no answer:
    /// the sandboxed guard then denies.
    pub fn answer(&self, mut stream: impl Stream) -> Result<()> {
        stream.set_timeouts(Duration::from_secs(GUARD_BUDGET_S))?;
        // Wrong tokens counted since their last row, once that row is old enough.
        for (_, count) in self.wrong_tokens.due(Instant::now()) {
            self.record_wrong_tokens(count)?;
        }
        let request = Request::read_from(&mut stream)?;
        if !constant_time_eq(&request.token, &self.token) {
            // Any local process can send these: a row for the first, then
            // one per interval with the count (`openmoat_proxy::coalesce`).
            if let Some(count) = self.wrong_tokens.refused(0, Instant::now()) {
                self.record_refused(&request.host, count)?;
            }
            bail!("a hook call with a wrong token");
        }
        let host: Host = request.host.parse()?;
        if let Err(refused) = self.admit(host, &request)? {
            self.record_out_of_scope(&refused)?;
            return Reply {
                nonce: request.nonce.clone(),
                code: Code::Deny as u8,
                stdout: Vec::new(),
                stderr: format!("moat: {}\n", refused.reason).into_bytes(),
            }
            .write_to(&mut stream);
        }
        let reply = self.decide(host, &request)?;
        reply.write_to(&mut stream)
    }

    /// Whether `request`, a call `host`'s hook sent, is the run's to decide;
    /// a payload the guard cannot parse is, and it denies it.
    fn admit(&self, host: Host, request: &Request) -> Result<Result<(), Refused>> {
        let sender = host.sender(&request.payload, request.continue_cli);
        let mut scope = self.scope.lock().unwrap_or_else(PoisonError::into_inner);
        match scope.host {
            None => scope.host = Some(host),
            Some(agent) if agent == host || agent == sender => {}
            Some(agent) => {
                return Ok(Err(Refused {
                    rule: RULE_HOST,
                    reason: format!(
                        "a hook call for {} came from inside this `openmoat run` of {}, so it was \
                         not decided: the run decides only its own agent's calls",
                        host.id(),
                        agent.id()
                    ),
                }));
            }
        }
        let Ok(parsed) = sender.parse_request(&request.payload) else {
            return Ok(Ok(()));
        };
        let session = parsed.session_id;
        if scope.sessions.contains(&session) {
            return Ok(Ok(()));
        }
        let refuse = |why: &str| {
            Ok(Err(Refused {
                rule: RULE_SESSION,
                reason: format!(
                    "a hook call from inside this `openmoat run` named a session that is not the \
                     run's ({why}), so it was not decided"
                ),
            }))
        };
        if run_session(Some(&session)).is_some() {
            return refuse("an `openmoat run` session");
        }
        if scope.sessions.len() >= MAX_SESSIONS {
            return refuse(&format!("the run already has {MAX_SESSIONS} sessions"));
        }
        let store = Store::open_existing(&self.home.audit_path())?;
        let first = store.session_page(&session, EventId(0), 1)?;
        let resumed = matches!(parsed.event, HookEvent::SessionStart { .. });
        match first.first() {
            None => {}
            // The agent's own session start brings a session it ran before into the run.
            Some(row) if resumed && row.host == sender.id() => {}
            Some(_) => return refuse("one the audit log already holds from outside the run"),
        }
        scope.sessions.push(session);
        Ok(Ok(()))
    }

    /// `moat guard --host <host>` outside the sandbox, on the request's payload.
    fn decide(&self, host: Host, request: &Request) -> Result<Reply> {
        let mut command = Command::new(&self.moat);
        command
            // `--relayed`: the call comes from inside this run's sandbox, which
            // holds the commands it runs (ADR-039). An argument, not a variable,
            // so a host's settings cannot claim it for a hook outside the run.
            .args(["guard", "--host", host.id(), "--relayed"])
            .env(RUN_SESSION_ENV, &self.run)
            .env_remove(SOCKET_ENV)
            .env_remove(TOKEN_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if request.continue_cli {
            command.env(openmoat_hosts::CONTINUE_ENV, "1");
        } else {
            command.env_remove(openmoat_hosts::CONTINUE_ENV);
        }
        // Where a payload that names no directory ran.
        let cwd = Path::new(&request.cwd);
        if cwd.is_absolute() && cwd.is_dir() {
            command.current_dir(cwd);
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("starting {}", self.moat.display()))?;
        let mut stdin = child
            .stdin
            .take()
            .context("no standard input for the guard")?;
        let payload = request.payload.clone();
        // A guard that stops reading (over its time limit) only ends the write.
        let writer = std::thread::spawn(move || stdin.write_all(payload.as_bytes()));
        let output = child.wait_with_output()?;
        let _ = writer.join();
        let mut reply = Reply {
            nonce: request.nonce.clone(),
            // Exit 2, the one code every host honours, unless the guard said 0.
            code: if output.status.code() == Some(Code::Ok as i32) {
                Code::Ok as u8
            } else {
                Code::Deny as u8
            },
            stdout: output.stdout,
            stderr: output.stderr,
        };
        if reply.stdout.len() > MAX_OUTPUT || reply.stderr.len() > MAX_OUTPUT {
            reply.code = 2;
            reply.stdout.clear();
            reply.stderr =
                b"moat: the guard's answer is too large to relay, so the call is denied\n".to_vec();
        }
        Ok(reply)
    }

    /// A row in the run's session for a call with a wrong token, standing for
    /// `count` such calls since the last row. The host it claimed is named
    /// only when it is one OpenMoat knows.
    fn record_refused(&self, claimed: &str, count: u64) -> Result<()> {
        let host = claimed
            .parse::<Host>()
            .map_or("an unknown host", |h| h.id());
        if count > 1 {
            return self.record_wrong_tokens(count);
        }
        self.record_row(
            RULE_TOKEN,
            format!(
                "a hook call for {host} came with a wrong token for this `openmoat run`, so it was \
                 not decided"
            ),
        )
    }

    /// One row for `count` calls with a wrong token since the last such row.
    fn record_wrong_tokens(&self, count: u64) -> Result<()> {
        self.record_row(
            RULE_TOKEN,
            format!(
                "{} came with a wrong token for this `openmoat run` since the last such row (at \
                 most one per {} s), so none was decided",
                counted(count, "hook call", "hook calls"),
                INTERVAL.as_secs()
            ),
        )
    }

    /// A row in the run's session for a call outside its [`Scope`].
    fn record_out_of_scope(&self, refused: &Refused) -> Result<()> {
        self.record_row(refused.rule, refused.reason.clone())
    }

    /// A deny row in the run's session: host [`LINK_HOST`], tool `guard`.
    fn record_row(&self, rule: &str, reason: String) -> Result<()> {
        let decision = Decision::single(Verdict::Deny, rule, reason);
        let store = Store::open_existing(&self.home.audit_path())?;
        store.record(&NewEvent {
            host: LINK_HOST,
            session_id: &self.run,
            call_id: None,
            cwd: None,
            tool: "guard",
            action: None,
            decision: &decision,
            latency_us: 0,
        })?;
        Ok(())
    }
}

impl LocalService for Service {
    fn prefix(&self) -> &[u8] {
        REQUEST_MAGIC
    }

    fn serve(&self, client: &TcpStream) {
        // Nothing to tell a caller that gets no answer; its guard denies.
        let _ = self.answer(client);
    }
}
