//! The side outside the sandbox: `moat run` decides each relayed hook call.
//!
//! A call whose token matches is decided by `moat guard`, started by this
//! process outside the sandbox with this process's access: the lock check,
//! policy, taint and audit row are exactly those of a hook outside `moat run`,
//! and [`RUN_SESSION_ENV`] makes it write the run's link row. A call with
//! another token is recorded and gets no answer.

use std::io::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::Host;
use openmoat_proxy::{LocalService, constant_time_eq};
use zeroize::Zeroizing;

use super::wire::{MAX_OUTPUT, REQUEST_MAGIC, Reply, Request};
use super::{SOCKET_ENV, Stream, TOKEN_ENV};
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::taint::run::{LINK_HOST, RUN_SESSION_ENV};

/// The rule of the row a call with a wrong token leaves.
pub const RULE_TOKEN: &str = "run-guard-token";

/// One run's decision service.
pub struct Service {
    home: Home,
    run: String,
    token: Zeroizing<Vec<u8>>,
    moat: PathBuf,
}

impl Service {
    /// The service of run session `run`, which wants `token`. Calls are
    /// decided by `moat`, the binary this process runs.
    pub fn new(home: Home, run: &str, token: &[u8], moat: PathBuf) -> Self {
        Self {
            home,
            run: run.to_owned(),
            token: Zeroizing::new(token.to_vec()),
            moat,
        }
    }

    /// Read one call from `stream` and answer it. An error means no answer:
    /// the sandboxed guard then denies.
    pub fn answer(&self, mut stream: impl Stream) -> Result<()> {
        stream.set_timeouts(Duration::from_secs(GUARD_BUDGET_S))?;
        let request = Request::read_from(&mut stream)?;
        if !constant_time_eq(&request.token, &self.token) {
            self.record_refused(&request.host)?;
            bail!("a hook call with a wrong token");
        }
        let host: Host = request.host.parse()?;
        let reply = self.decide(host, &request)?;
        reply.write_to(&mut stream)
    }

    /// `moat guard --host <host>` outside the sandbox, on the request's payload.
    fn decide(&self, host: Host, request: &Request) -> Result<Reply> {
        let mut command = Command::new(&self.moat);
        command
            .args(["guard", "--host", host.id()])
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
            code: if output.status.code() == Some(0) {
                0
            } else {
                2
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

    /// A row in the run's session for a call with a wrong token. The host it
    /// claimed is named only when it is one OpenMoat knows.
    fn record_refused(&self, claimed: &str) -> Result<()> {
        let host = claimed
            .parse::<Host>()
            .map_or("an unknown host", |h| h.id());
        let decision = Decision::single(
            Verdict::Deny,
            RULE_TOKEN,
            format!(
                "a hook call for {host} came with a wrong token for this `openmoat run`, so it was \
                 not decided"
            ),
        );
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
