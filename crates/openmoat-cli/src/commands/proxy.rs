//! `moat proxy [--listen 127.0.0.1:<port>]`: the default-deny egress proxy
//! (ADR-020, `openmoat-proxy`).
//!
//! Starts only from an intact installation: the policy lock must match, so a
//! tampered policy is never compiled into a long-running proxy. The policy is
//! read once; restart the proxy after changing it. Every brokered secret
//! (`secrets:`) is read at start-up; one that cannot be read stops it. `moat run`
//! serves the same proxy, secrets included, from a thread of its own.
//!
//! `moat proxy install` / `uninstall` / `status` manage the per-user service
//! (launchd on macOS, systemd user unit on Linux; refused on Windows) that
//! keeps the proxy running without the user starting it themselves (#272).

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, CompiledPolicy, EvalContext, Policy, Secret};
use openmoat_proxy::{
    Broker, Connection, Credential, Limits, Proxy, RULE_AUDIT, RecordError, Recorder, Sessions,
    SystemResolver,
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::cli::Format;
use crate::cli::{ProxyArgs, ProxyStatusArgs};
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity;
use crate::render::Deferred;
use crate::secrets;
use crate::taint::run::RunTaint;

use super::service;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::service::State;

/// Where `moat proxy` listens when neither `--listen` nor `sandbox.proxy_port` says.
const DEFAULT_PORT: u16 = 18080;

pub fn run(args: &ProxyArgs) -> Result<Code> {
    if let Some(listen) = args.listen.filter(|a| !a.ip().is_loopback()) {
        bail!("--listen {listen} is not a loopback address; the proxy would serve other machines");
    }
    let home = installed()?;
    let policy = home.load_policy()?;
    let hosts_port = crate::sandbox::proxy_port(&policy);
    let listen = args.listen.unwrap_or_else(|| {
        SocketAddr::from((Ipv4Addr::LOCALHOST, hosts_port.unwrap_or(DEFAULT_PORT)))
    });
    let exit = Exit::open(
        &home,
        policy,
        context::eval_context(&home, None, None)?,
        None,
    )?;
    let listener = TcpListener::bind(listen).with_context(|| format!("listening on {listen}"))?;
    let addr = listener
        .local_addr()
        .context("reading the listening address")?;
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "moat proxy: listening on {addr} (audit session {})",
        exit.session()
    )?;
    // The host sandboxes cannot send a credential, so this proxy serves
    // without sessions (ADR-027); `moat run` serves its own that needs one.
    writeln!(
        std::io::stderr(),
        "moat proxy: note: no session credentials here, so any local process may use this \
         proxy and session taint does not apply to it; `openmoat run` serves one that requires them"
    )?;
    if let Some(port) = hosts_port.filter(|p| *p != addr.port()) {
        writeln!(
            std::io::stderr(),
            "moat proxy: note: the host sandboxes send traffic to port {port} (`sandbox.proxy_port`), not here"
        )?;
    }
    // Only what the agent may know: the id, host, header and placeholder.
    for s in exit.secrets() {
        writeln!(
            stdout,
            "moat proxy: secret `{}` goes to {} in {}; give the agent {}",
            s.id,
            s.host,
            s.header,
            s.placeholder()
        )?;
    }
    stdout.flush()?;
    drop(stdout);
    exit.serve(&listener)?;
    Ok(Code::Ok)
}

/// `moat proxy install`: write and start the per-user service.
pub fn install() -> Result<Code> {
    crate::terminal::refuse_agent("openmoat proxy install")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat proxy install` must be run by a person in a terminal, not from a hook \
             or script: starting a user service touches the host OS"
        );
    }
    let home = installed()?;
    let binary = crate::install::hook_binary()?;
    let manager = service::manager(&home)?;
    let path = manager.install(&binary, home.root())?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "✔ {} installed and started: {}",
        service::display_name(),
        path.display()
    )?;
    writeln!(
        out,
        "  the proxy restarts on failure; a policy-lock exit does not loop-restart.",
    )?;
    writeln!(
        out,
        "  `openmoat proxy status` reports its state; `openmoat proxy uninstall` removes it.",
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `moat proxy uninstall`: stop and remove the per-user service.
pub fn uninstall() -> Result<Code> {
    crate::terminal::refuse_agent("openmoat proxy uninstall")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat proxy uninstall` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    let manager = service::manager(&home)?;
    let mut out = Deferred::default();
    match manager.uninstall()? {
        Some(path) => writeln!(
            out,
            "✔ {} removed: {}",
            service::display_name(),
            path.display()
        )?,
        None => writeln!(out, "· {} was not installed", service::display_name())?,
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// `moat proxy status`: report the service's state.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn status(args: &ProxyStatusArgs) -> Result<Code> {
    let home = Home::locate()?;
    let manager = service::manager(&home)?;
    let state = manager.state()?;
    let path = manager.file_path()?;
    if args.format == Format::Json {
        crate::render::json(&serde_json::json!({
            "service": service::display_name(),
            "path": path,
            "state": state,
        }))?;
        return Ok(Code::Ok);
    }
    let mut out = Deferred::default();
    writeln!(
        out,
        "{}  {}",
        service::display_name(),
        state.describe(&path)
    )?;
    out.finish()?;
    let code = match state {
        State::Running | State::NotInstalled => Code::Ok,
        _ => Code::Usage,
    };
    Ok(code)
}

/// Restart the service when it is installed and running. `moat sandbox sync`
/// calls this after re-pinning the lock so the proxy picks up the new policy
/// (which it reads once at start-up). A missing service is fine: the user has
/// not opted in to a service yet.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn restart_if_installed(home: &Home) -> Result<Option<String>> {
    let manager = service::manager(home)?;
    let state = manager.state()?;
    match state {
        State::Running | State::Stopped => {
            manager.restart()?;
            Ok(Some(format!("{} restarted", service::display_name())))
        }
        _ => Ok(None),
    }
}

/// `moat doctor` and `moat status` lines for the user service: not installed
/// is silent (opt-in), installed is a line, drift / crashloop is a problem.
/// Returns `(ok, text)` so the caller renders the icon. Silent on platforms
/// without a service story (Windows): `moat proxy install` refuses there, so
/// there is nothing to report under `moat doctor`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn service_line(home: &Home) -> Option<(bool, String)> {
    let manager = service::manager(home).ok()?;
    let state = manager.state().ok()?;
    let path = manager.file_path().ok()?;
    match state {
        State::NotInstalled => None,
        State::Running => Some((true, format!("service          {}", state.describe(&path)))),
        _ => Some((false, format!("service          {}", state.describe(&path)))),
    }
}

/// Windows: no user service to report on (#272), so `moat proxy status`
/// refuses with the way to keep the proxy up instead of a made-up state.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn status(_args: &ProxyStatusArgs) -> Result<Code> {
    bail!(
        "no user service on {} yet (#272); run `openmoat proxy` in a terminal to keep the proxy up",
        std::env::consts::OS
    )
}

/// Windows: nothing is ever installed, so `moat sandbox sync` restarts nothing.
/// The manager is still resolved, so a missing home fails as it does elsewhere.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn restart_if_installed(home: &Home) -> Result<Option<String>> {
    service::manager(home)?;
    Ok(None)
}

/// Windows: `moat doctor` and `moat status` have no service line.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn service_line(_home: &Home) -> Option<(bool, String)> {
    None
}

/// The `moat doctor` and `moat status` line for the proxy the host sandboxes
/// send traffic to, and whether something listens there. A stopped proxy
/// leaves those commands without network rather than with direct network.
/// Found by trying to bind the port rather than connecting, so a running
/// `moat proxy` records nothing.
pub(super) fn listening_line(port: u16) -> (bool, String) {
    let bound = TcpListener::bind((Ipv4Addr::LOCALHOST, port));
    if matches!(bound, Err(e) if e.kind() == std::io::ErrorKind::AddrInUse) {
        (true, format!("listening on 127.0.0.1:{port}"))
    } else {
        let text = format!(
            "WARNING: nothing listens on 127.0.0.1:{port}, so sandboxed commands have no \
             network; start `openmoat proxy` (keep it running as a user service)"
        );
        (false, text)
    }
}

/// The installation, refused when it is missing or its policy lock shows
/// drift, so a tampered policy is never compiled into a sandbox or a proxy.
pub(super) fn installed() -> Result<Home> {
    let home = Home::locate()?;
    home.require_exists()?;
    if let Some(drift) = integrity::violation(&home)? {
        bail!("policy lock drift: {}", drift.reasons.join("; "));
    }
    Ok(home)
}

/// What one proxy serves with: the policy, the brokered secrets and the audit
/// log. It owns them, so `moat run` can serve from another thread.
pub(super) struct Exit {
    policy: Policy,
    ctx: EvalContext,
    broker: Broker,
    recorder: AuditLog,
    run: Option<RunSession>,
    /// `moat run`'s decisions for its sandboxed hooks, on the same port (ADR-028).
    local: Option<crate::guard_relay::Service>,
}

/// Session mode (ADR-027): the one session `moat run` serves, and the
/// project's effective policy its taint is folded with, as the guard does.
struct RunSession {
    credential: Credential,
    home: Home,
    effective: Policy,
}

impl Exit {
    /// Fails when the policy does not compile, a secret's source cannot be read,
    /// or the audit log cannot be opened. With `credential`, the proxy serves
    /// that session alone and records under its id (`moat run`); without, it
    /// serves any local client under a `proxy-<ms>` session (`moat proxy`).
    pub(super) fn open(
        home: &Home,
        policy: Policy,
        ctx: EvalContext,
        credential: Option<Credential>,
    ) -> Result<Self> {
        // `moat run` knows its project: the repository policy's deny rules
        // refuse hosts at its proxy too (its allow rules never widen it).
        let policy = if credential.is_some() {
            crate::repo::with_repo_denies(home, &ctx, policy)?
        } else {
            policy
        };
        CompiledPolicy::compile(&policy, &ctx)?;
        let (broker, known) = secrets::broker(&policy.secrets, &ctx.home)?;
        let audit_path = home.audit_path();
        let store = Store::open_existing(&audit_path)
            .with_context(|| format!("opening {}", audit_path.display()))?
            .with_secrets(known);
        let session = credential.as_ref().map_or_else(
            || format!("proxy-{}", crate::time::now_ms()),
            |c| c.session().to_owned(),
        );
        let run = match credential {
            Some(credential) => {
                let effective = crate::repo::effective_policy(home, &ctx)?;
                CompiledPolicy::compile(&effective, &ctx)?;
                Some(RunSession {
                    credential,
                    home: home.clone(),
                    effective,
                })
            }
            None => None,
        };
        Ok(Self {
            policy,
            ctx,
            broker,
            recorder: AuditLog {
                store: Mutex::new(store),
                session,
            },
            run,
            local: None,
        })
    }

    /// Serve `service` on the proxy's port too.
    pub(super) fn with_guard(mut self, service: crate::guard_relay::Service) -> Self {
        self.local = Some(service);
        self
    }

    /// The audit session the proxy records under.
    pub(super) fn session(&self) -> &str {
        &self.recorder.session
    }

    /// The policy's brokered secrets: ids, hosts, headers and placeholders only;
    /// their values stay in the broker.
    pub(super) fn secrets(&self) -> &[Secret] {
        &self.policy.secrets
    }

    /// Serve `listener` until accepting fails.
    pub(super) fn serve(self, listener: &TcpListener) -> Result<()> {
        let compiled = CompiledPolicy::compile(&self.policy, &self.ctx)?;
        let limits = Limits::default();
        let proxy = |sessions| Proxy {
            policy: &compiled,
            resolver: &SystemResolver,
            recorder: &self.recorder,
            limits: &limits,
            loopback_ok: &[],
            broker: &self.broker,
            allow_ech: self
                .policy
                .sandbox
                .as_ref()
                .is_some_and(|s| s.proxy_allow_ech),
            sessions,
            local: self
                .local
                .as_ref()
                .map(|s| s as &dyn openmoat_proxy::LocalService),
        };
        let Some(run) = self.run else {
            return proxy(None).serve(listener).context("accepting connections");
        };
        let effective = CompiledPolicy::compile(&run.effective, &self.ctx)?;
        let id = run.credential.session().to_owned();
        let lookup = RunTaint::new(run.home, &id, &effective, &self.ctx.cwd);
        let sessions = Sessions::new(vec![run.credential], &lookup);
        proxy(Some(&sessions))
            .serve(listener)
            .context("accepting connections")
    }
}

/// Proxy decisions in the audit log: host `proxy`, the method as the tool, and
/// a `net` action naming `connect://host:port` or `http://host:port`. Never the
/// path: it may carry secrets, and no rule looks at it yet.
struct AuditLog {
    store: Mutex<Store>,
    session: String,
}

impl Recorder for AuditLog {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        let action = c.destination.map(|(host, port)| {
            let scheme = if c.method == Some("CONNECT") {
                "connect"
            } else {
                "http"
            };
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            Action::Net {
                url: format!("{scheme}://{host}:{port}"),
            }
        });
        let event = NewEvent {
            host: "proxy",
            session_id: c.session.unwrap_or(&self.session),
            call_id: None,
            cwd: None,
            tool: c.method.unwrap_or("unknown"),
            action: action.as_ref(),
            decision: c.decision,
            latency_us: c.latency_us,
        };
        let store = self
            .store
            .lock()
            .map_err(|_| RecordError("audit writer poisoned by an earlier panic".to_owned()))?;
        store
            .record(&event)
            .map(drop)
            .map_err(|e| RecordError(e.to_string()))
    }

    fn unrecorded(&self, error: &RecordError) {
        // The proxy has refused the connection; stderr is the one place left
        // to say why, since the audit log is what failed.
        eprintln!("{}", unrecorded_line(error));
    }
}

fn unrecorded_line(error: &RecordError) -> String {
    format!("moat proxy: {RULE_AUDIT}: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_record_is_reported_as_before() {
        let error = RecordError("disk full".to_owned());
        assert_eq!(
            unrecorded_line(&error),
            "moat proxy: proxy-audit: audit log unavailable: disk full"
        );
    }
}
