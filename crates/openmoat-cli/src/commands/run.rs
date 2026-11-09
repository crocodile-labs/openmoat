//! `moat run [--isolate] [--write PATH]… -- <agent> [args]`: the Lightweight
//! tier, and with `--isolate` the Isolated tier on Linux (ADR-018).
//!
//! The agent and every command it starts share one sandbox generated from the
//! policy for the project in the current directory. Their only network is a
//! `moat proxy` this process serves on a loopback port: the sandbox allows that
//! port alone, and the proxy refuses loopback destinations, so no other local
//! service is reachable through it either. The agent's hooks, which cannot
//! reach OpenMoat's home from in there, have their calls decided on that same
//! port by this process (`crate::guard_relay`, ADR-028).

// `platform` is this OS's module: `confine(policy, ctx, grants, program, state)
// -> Confined` (Lightweight) and `isolate(…)` (Isolated), refused on Linux where
// a grant would show the state directory `state`, whose `command()` takes
// the agent's arguments and environment, `report()` lists the losses and
// allowances, `warning()` says where the network is restricted by port only,
// and `status()` runs the agent in its sandbox; `inside(args)` is what
// bubblewrap starts in its sandbox; `port_only_network()` is `moat doctor`'s
// warning for the same; `terminals()` lists the terminal devices this
// process's standard streams are on, the only ones the sandbox opens.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod release_age;
mod required;
mod temp;
pub mod tier;
mod tool_shell;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as platform;

use std::ffi::OsStr;
use std::io::Write as _;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Policy, SecretSource};
use openmoat_proxy::Credential;
use zeroize::Zeroizing;

use super::proxy::{self, Exit};
use super::sandbox::write_report;
use crate::cli::{IsolatedArgs, Netns, RunArgs};
use crate::context::{self, path_string};
use crate::environment::find_on_path;
use crate::exit::Code;
use crate::guard_relay::{self, Service, random_hex};
use crate::home::Home;
use crate::proxy_ca::{Trust, request_poc};
use crate::sandbox::Grants;
use crate::sandbox::Report;
use crate::sandbox::git_env;
use crate::sandbox::kerberos;
use crate::sandbox::own_login::{self, Owner};
use crate::taint::run::RUN_SESSION_ENV;
use temp::RunTemp;

/// What a proxy-aware program reads to find its proxy.
const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

pub fn run(args: &RunArgs) -> Result<Code> {
    let home = proxy::installed()?;
    let ctx = context::eval_context(&home, None, None)?;
    if ctx.project.is_none() {
        bail!(
            "`openmoat run` confines the agent to a project: start it in the project, not in \
             your home directory, one of its ancestors or a filesystem root"
        );
    }
    let (name, rest) = args.command.split_first().context("no agent to run")?;
    // The sandbox checks the file it starts, not a link to it.
    let program = resolve(name)?;
    let owner = Owner::of(&name.to_string_lossy(), &path_string(&program));
    // Before anything starts: the level the policy requires of this program.
    required::check(&home, &ctx, owner, &name.to_string_lossy())?;
    // A bare repository a command plants (no `.git` name) is used only when named.
    let git = git_env::add(&|var| std::env::var(var).ok())?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("listening on a loopback port for the proxy")?;
    let port = listener.local_addr()?.port();
    let mut policy = home.load_policy()?;
    crate::install::self_paths::protect_recorded(&home, &mut policy)?;
    // Kerberos tickets: the default caches and the session's own, wherever
    // `KRB5CCNAME` puts it, denied in this sandbox too.
    let ccname = std::env::var("KRB5CCNAME").ok();
    kerberos::for_run(&mut policy, ccname.as_deref());
    // A temp directory of the run's own instead of the shared one; under
    // `--isolate` the shared one is an empty `tmpfs` already.
    let run_temp = (!args.isolate).then(RunTemp::create).transpose()?;
    // TLS termination (ADR-043), checked before anything starts: a CA that is
    // missing, not pinned or not covering a host stops the run here. The
    // agent's clients trust it through files in the run's temp directory.
    let terminating = crate::proxy_ca::load(&home, &policy)?;
    let trust = terminating
        .as_ref()
        .map(|t| match &run_temp {
            Some(temp) => Trust::write_in(&t.cert_pem, Path::new(&temp.path())),
            None => Trust::write(&t.cert_pem),
        })
        .transpose()?;
    let ca_notice = terminating.as_ref().and_then(|t| t.notice.clone());
    let agent_host = match owner {
        Owner::Agent(host) => Some(host),
        Owner::Unknown => None,
    };
    // Tool commands do not receive the relay token (ADR-075): what commands
    // may write must not hold the wrapper that keeps it from them.
    let write_roots: Vec<String> = ctx
        .project
        .iter()
        .cloned()
        .chain(run_temp.as_ref().map(RunTemp::path))
        .chain(args.writes.iter().map(|w| resolved(w)))
        .collect();
    let tool_shell = tool_shell::prepare(agent_host, &write_roots)?;
    if let Some(notice) = tool_shell::off_notice(agent_host, tool_shell.as_ref()) {
        eprintln!("{notice}");
    }
    let grants = Grants {
        proxy_port: Some(port),
        tmpdir: run_temp.as_ref().map(RunTemp::path),
        program: Some(path_string(&program)),
        writes: args.writes.iter().map(|w| resolved(w)).collect(),
        // The person's other terminals stay out of reach of the agent's commands.
        terminals: platform::terminals(),
        trust: trust.as_ref().map(|t| path_string(t.dir())),
        tool_shell: tool_shell.as_ref().map(tool_shell::ToolShell::grant),
    };
    let state = home.root();
    // The agent runs inside the sandbox and must read its own login there; every
    // other agent's stays denied (ADR-054). The hook decides with the whole policy.
    let (sandboxed, kept) = own_login::for_session(&policy, &ctx, owner, &grants.writes);
    let mut agent = if args.isolate {
        platform::isolate(&sandboxed, &ctx, grants, &program, state)?
    } else {
        platform::confine(&sandboxed, &ctx, grants, &program, state)?
    };
    own_login::report(agent.report_mut(), &kept, &ctx);
    refuse_port_only(args.netns, agent.warning())?;
    agent.command().args(rest);
    let release_age = package_release_age(&policy, ctx.project.as_deref());
    agent.command().envs(release_age.vars);
    // The proxy reads a brokered secret from this process's environment; the
    // agent gets only the placeholder, never the variable that holds the value.
    for name in env_secrets(&policy) {
        agent.command().env_remove(name);
    }
    // The proxy serves this session alone (ADR-027): each request must carry
    // the credential in the proxy URL, and the run's id ties the agent's
    // hook sessions to it, so their taint applies to its requests.
    let credential = session_credential()?;
    let listener_addr = listener.local_addr()?;
    let url = credential.proxy_url(listener_addr);
    let run_session = credential.session().to_owned();
    // The hooks the agent starts run in its sandbox, without OpenMoat's home:
    // this process decides their calls on the proxy's port (ADR-028).
    // Only the calls of the agent this run starts, in its own sessions (ADR-070).
    let (guard, guard_token) = guard_service(&home, &run_session, agent_host)?;
    let exit = Exit::open(&home, policy, ctx, Some(credential))?
        .with_guard(guard)
        .with_tls(terminating.map(|t| t.tls))
        .with_requests(request_poc::requests()?);
    notice(&program, port, exit.session(), &agent, args)?;
    let notices = ca_notice
        .into_iter()
        .chain(release_age.notices)
        .chain(request_poc::notice())
        .chain(trust.iter().filter_map(Trust::notice));
    for line in notices {
        eprintln!("{line}");
    }
    std::thread::spawn(move || {
        if let Err(error) = exit.serve(&listener) {
            eprintln!("moat run: the proxy stopped, so the agent has no network: {error:#}");
        }
    });
    for var in PROXY_VARS {
        agent.command().env(var, url.as_str());
    }
    agent.command().env(RUN_SESSION_ENV, &run_session);
    agent
        .command()
        .env(guard_relay::SOCKET_ENV, listener_addr.to_string())
        .env(guard_relay::TOKEN_ENV, guard_token.as_str());
    if let Some(wrapper) = &tool_shell {
        wrapper.apply(agent.command());
    }
    agent
        .command()
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    agent.command().envs(git);
    if let Some(temp) = &run_temp {
        agent.command().env(temp::TMPDIR, temp.path());
    }
    // Set last, over any the person had: what the agent's clients trust.
    for (var, path) in trust.iter().flat_map(Trust::env) {
        agent.command().env(var, path);
    }
    // Ctrl-C at the terminal reaches the agent and OpenMoat alike. The agent decides
    // what it means; OpenMoat keeps running, or the proxy would die under the agent.
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::new(AtomicBool::new(false)),
    )
    .context("keeping OpenMoat running on Ctrl-C")?;
    let status = agent
        .status()
        .with_context(|| format!("starting {}", program.display()))?;
    Ok(if status.success() {
        Code::Ok
    } else {
        Code::Failed
    })
}

/// Inside bubblewrap (`moat run --isolate`, and `moat run`'s network
/// namespace on Linux): serve the proxy on loopback, apply
/// the Landlock rules and seccomp filter, and start the agent.
pub fn inside(args: &IsolatedArgs) -> Result<Code> {
    platform::inside(args)
}

/// When this process was started as a run's tool-shell wrapper (ADR-075), the
/// code to exit with once the real shell could not start.
pub fn tool_shell_entry() -> Option<Code> {
    tool_shell::entry()
}

/// A fresh credential for this run's proxy: session `run-<ms>-<8 hex>` and a
/// token of 64 hex characters (256 bits), both from the system's random source.
fn session_credential() -> Result<Credential> {
    let random = random_hex(36).context("making the proxy credential")?;
    let session = format!("run-{}-{}", crate::time::now_ms(), &random[..8]);
    Ok(Credential::new(&session, random[8..].as_bytes())?)
}

/// The service that decides the agent's hook calls on the proxy's port
/// (ADR-028), for the calls of `agent` (ADR-070), and its token of 64 hex
/// characters (256 bits).
fn guard_service(
    home: &Home,
    run_session: &str,
    agent: Option<openmoat_hosts::Host>,
) -> Result<(Service, Zeroizing<String>)> {
    let token = random_hex(32).context("making the hook token")?;
    let moat = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("locating the moat binary")?;
    let service = Service::new(home.clone(), run_session, token.as_bytes(), moat, agent);
    Ok((service, token))
}

/// A project's package-manager configuration this large or larger is not read:
/// it is a configuration file, not a lockfile.
const MAX_PACKAGE_CONFIG_BYTES: u64 = 1 << 20;

/// npm and uv skip versions published within the policy's release age
/// (ADR-030), unless the person set their own cut-off.
fn package_release_age(policy: &Policy, project: Option<&str>) -> release_age::ReleaseAge {
    let in_project = |file: &str| project.map(|p| Path::new(p).join(file));
    let small = |path: &Path| {
        let small = std::fs::metadata(path).is_ok_and(|m| m.len() < MAX_PACKAGE_CONFIG_BYTES);
        small.then(|| std::fs::read_to_string(path).ok()).flatten()
    };
    let var = |name: &str| std::env::var(name).ok();
    release_age::env(
        policy.package_min_release_age_days(),
        crate::time::now_ms(),
        &release_age::Found {
            inherited: &|name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()),
            project_has: &|file| in_project(file).is_some_and(|p| p.exists()),
            project_file: &|file| small(&in_project(file)?),
            user_file: &|tool| {
                let home = crate::home::user_home().ok();
                small(&release_age::user_config_path(tool, &var, home)?)
            },
        },
    )
}

/// The environment variables the policy's brokered secrets are read from.
fn env_secrets(policy: &Policy) -> Vec<String> {
    policy
        .secrets
        .iter()
        .filter_map(|s| match &s.source {
            SecretSource::Env(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// The executable `name` starts, symlinks resolved. A bare name is looked up
/// in `PATH`'s absolute entries only ([`find_on_path`]): `openmoat run` starts
/// the agent, and a relative entry would let the repository it opens pick it.
fn resolve(name: &OsStr) -> Result<PathBuf> {
    let path = Path::new(name);
    let found = if path.components().count() > 1 {
        Some(path.to_path_buf())
    } else {
        find_on_path(&name.to_string_lossy())
    };
    let found = found.with_context(|| format!("{} is not on PATH", path.display()))?;
    std::fs::canonicalize(&found).with_context(|| format!("resolving {}", found.display()))
}

/// `path` with its symlinks resolved, or made absolute when it does not exist yet.
fn resolved(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).or_else(|_| context::absolute(path));
    path_string(resolved.as_deref().unwrap_or(path))
}

/// Why `moat run` cannot sandbox on this machine (no backend, or a macOS
/// older than its floor); `None` when it can. `moat mcp wrap` starts servers
/// in it by default only where it can.
pub fn unavailable() -> Option<String> {
    platform::unavailable()
}

/// Why `moat run` here would restrict the agent's network by port only, if it
/// would (Linux without a usable bubblewrap), for `moat doctor`.
pub fn port_only_network() -> Option<String> {
    platform::port_only_network()
}

/// On Linux, whether the system's bubblewrap is installed; `None` elsewhere,
/// where plain `moat run` has no gap inside the project to name ([`tier`]).
pub fn bubblewrap() -> Option<bool> {
    platform::bubblewrap()
}

/// Refuse to start, under `--netns=require`, an agent whose network is
/// restricted by port only (`port_only`, the platform's warning).
fn refuse_port_only(netns: Netns, port_only: Option<&str>) -> Result<()> {
    match (netns, port_only) {
        (Netns::Require, Some(why)) => bail!(
            "`openmoat run --netns=require`: the agent cannot get a network of its own here, so \
             it does not start.\n{why}"
        ),
        _ => Ok(()),
    }
}

/// What the user must know before the agent starts, on standard error.
fn notice(
    program: &Path,
    port: u16,
    session: &str,
    agent: &platform::Confined,
    args: &RunArgs,
) -> Result<()> {
    let report: &Report = agent.report();
    let mut err = std::io::stderr().lock();
    let sees = if args.isolate {
        "; it sees only the project, the read roots and --write paths"
    } else {
        ""
    };
    // The tests find the port after "proxy on 127.0.0.1:" in either line.
    let network = if agent.warning().is_some() {
        format!("network only to port {port} on any host, OpenMoat's proxy")
    } else {
        "network only through OpenMoat's proxy".to_owned()
    };
    writeln!(
        err,
        "moat run: {} in a sandbox made from the policy{sees}, {network} on 127.0.0.1:{port} \
         (audit session {session})",
        program.display()
    )?;
    if let Some(warning) = agent.warning() {
        writeln!(err, "{warning}")?;
    }
    if let Some(open) = tier::notice(platform::bubblewrap(), args.isolate) {
        writeln!(err, "{open}")?;
    }
    if args.verbose {
        writeln!(
            err,
            "  proxy: 127.0.0.1:{port}\n  \
             turn the agent's own sandbox off (Codex: --sandbox danger-full-access): sandboxes \
             do not nest, so the agent's cannot start in here. This one holds the agent and \
             every command it starts together, so it is less precise per command than the \
             agent's own sandbox."
        )?;
        write_report(&mut err, report)?;
    } else {
        writeln!(
            err,
            "moat run: turn the agent's own sandbox off (Codex: --sandbox danger-full-access); \
             sandbox ready ({} stricter, {} wider; --verbose for details)",
            report.losses.len(),
            report.allowances.len()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Netns, refuse_port_only};

    #[test]
    fn require_refuses_a_port_only_network() {
        let why = "moat run: the network is restricted by port only";
        let refused = refuse_port_only(Netns::Require, Some(why)).unwrap_err();
        assert!(format!("{refused:#}").contains("--netns=require"));
        assert!(format!("{refused:#}").contains(why));
        assert!(refuse_port_only(Netns::Require, None).is_ok());
        assert!(
            refuse_port_only(Netns::Auto, Some(why)).is_ok(),
            "the default"
        );
        assert!(refuse_port_only(Netns::Auto, None).is_ok());
    }
}
