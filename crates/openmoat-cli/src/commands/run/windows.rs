//! `openmoat run` on Windows (ADR-115): the agent under a write-restricted
//! token, in a job object, with the proxy variables pointing at the run's
//! proxy. A preview tier that holds writes and the process tree, and says
//! plainly what it does not hold:
//!
//! - **Writes.** The token's restricting SIDs (`sandbox/write_token.rs`)
//!   are granted on the project, the run's temp directory and `--write`
//!   paths only, so a write anywhere else fails, unless the place grants
//!   `Everyone` write. Policy denies inside those roots that name a place
//!   that exists get deny entries; the rest stay the hook's.
//! - **Reads are not restricted.** Windows checks a write-restricted token's
//!   restricting SIDs on writes only; every read deny rule is the hook's.
//! - **The network is not held by the operating system.** No Windows
//!   Filtering Platform filter: `HTTP_PROXY` and `HTTPS_PROXY` send programs
//!   that honour them through the run's proxy, and one that ignores them
//!   connects directly. The run's boundary record and protection score say
//!   so (`proxy_variables`, `wfp_network` missing).
//! - **The process tree.** The agent starts suspended, is put in a job that
//!   kills every process in it when the run ends and lets none break away,
//!   and its own token and job are read back before it runs a single
//!   instruction; anything not confirmed stops it.
//!
//! Once a person ran `openmoat agent-account setup` (ADR-129), a run whose
//! account record matches the system starts the agent as that account
//! instead (`windows/account.rs`): its writes need the account granted,
//! which it is on the write roots alone, and the places the policy's read
//! denies name get deny entries for it, so Windows refuses those reads too.
//! The network is held as above in both.
//!
//! There is no Isolated tier here. The Win32 calls are in `windows/win32.rs`
//! and `windows/account/`, the files of this tier with `unsafe`.

use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context as _, Result, bail};
use openmoat_core::boundary::{LaunchCheck, Mechanism, NetworkMode, Restriction};
use openmoat_core::{EvalContext, Policy};

use super::command_line;
use crate::cli::IsolatedArgs;
use crate::context::{path_string, strip_verbatim};
use crate::exit::Code;
use crate::sandbox::write_token::{self, Entry, Plan};
use crate::sandbox::{Grants, Report};

pub mod account;
mod acl;
mod win32;

/// Why the network is not the agent's own here: what `--netns=require`, a
/// policy's `require.run: full-boundary` and the protection score name.
const NETWORK_GAP: &str = "Windows: `openmoat run` sets HTTP_PROXY and HTTPS_PROXY to its proxy, \
     and nothing in the operating system holds the network (no Windows Filtering Platform \
     filter yet), so a program that ignores the variables connects directly";

/// What the run says before the agent starts, beside the network.
const WARNING: &str = "moat run: Windows preview tier: writes outside the project, the run's \
     temp directory and --write paths are refused by a write-restricted token; reads are not \
     restricted (the hook decides them) and the network goes through the proxy only for \
     programs that honour HTTP_PROXY";

/// What the run says before the agent starts as the agent account.
const ACCOUNT_WARNING: &str = "moat run: Windows preview tier, as the agent account (ADR-129): \
     writes outside the project, the run's temp directory and --write paths, and the reads the \
     policy denies in your profile, are refused by Windows; the network goes through the proxy \
     only for programs that honour HTTP_PROXY (the network filters are the next step)";

/// How the agent starts.
enum Mode {
    /// Under the write-restricted token whose SIDs `Plan` grants (ADR-115).
    Token(Plan),
    /// As the agent account (ADR-129).
    Account(Box<account::Active>),
}

/// The agent, ready to start under its token or as the agent account.
pub struct Confined {
    command: Command,
    report: Report,
    mode: Mode,
    /// The project, which git must take from another account's files.
    project: Option<String>,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
    state: &Path,
) -> Result<Confined> {
    if let Some(why) = command_line::refused(&program.to_string_lossy()) {
        bail!("{why}");
    }
    let tmpdir = grants.tmpdir.clone();
    let exists = |path: &str| Path::new(path).exists();
    let active = account::active(state);
    let state = path_string(state);
    let (report, mode) = if let Some(active) = active {
        let plan =
            crate::sandbox::account_plan(policy, ctx, grants, &exists, &active.record.profile)?;
        refuse_state(plan.roots.iter(), &state)?;
        active.apply(&plan)?;
        (plan.report, Mode::Account(Box::new(active)))
    } else {
        let generated = crate::sandbox::write_token_plan(policy, ctx, grants, &exists)?;
        refuse_state(generated.plan.roots.iter().map(|(root, _)| root), &state)?;
        apply(&generated.plan)?;
        (generated.report, Mode::Token(generated.plan))
    };
    // `canonicalize` gave a verbatim path (`\\?\C:\…`), which the program
    // would then see as its own name; start it by its plain one.
    let mut command = Command::new(strip_verbatim(&program.to_string_lossy()));
    // Windows programs take their temp directory from these, not `TMPDIR`.
    if let Some(temp) = tmpdir {
        let native = temp.replace('/', "\\");
        command.env("TEMP", &native).env("TMP", &native);
    }
    Ok(Confined {
        command,
        report,
        mode,
        project: ctx.project.clone(),
    })
}

/// A write root at or inside OpenMoat's state directory is refused: its
/// access list holds exactly two entries (ADR-083), and the run would add one.
fn refuse_state<'a>(roots: impl Iterator<Item = &'a String>, state: &str) -> Result<()> {
    let state = state.to_lowercase();
    for root in roots {
        let root = root.to_lowercase();
        if root == state || root.starts_with(&format!("{}/", state.trim_end_matches('/'))) {
            bail!(
                "`openmoat run` refuses a write grant on OpenMoat's state directory ({root}): \
                 commands must never write it"
            );
        }
    }
    Ok(())
}

/// Set every entry of `plan` that is not there yet. The first run in a large
/// project waits while Windows hands the root's entry to every file below.
fn apply(plan: &Plan) -> Result<()> {
    for entry in &plan.entries {
        let path = Path::new(&entry.path);
        let have = crate::state_acl::descriptor(path)
            .ok()
            .and_then(|d| d.aces)
            .unwrap_or_default();
        if !write_token::needs_change(&have, entry) {
            continue;
        }
        if entry.allows {
            eprintln!(
                "moat run: granting this run's own SID write on {} (once per folder; it names no \
                 account)",
                entry.path
            );
        }
        set(entry).with_context(|| format!("setting the access list of {}", entry.path))?;
    }
    Ok(())
}

fn set(entry: &Entry) -> Result<()> {
    acl::add_entry(
        &wide(&entry.path.replace('/', "\\"))?,
        &entry.sid,
        (entry.allows, entry.mask, entry.inherit),
    )
}

/// `text` as NUL-terminated UTF-16.
fn wide(text: &str) -> Result<Vec<u16>> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    if units.contains(&0) {
        bail!("{text} holds a NUL character");
    }
    units.push(0);
    Ok(units)
}

pub fn isolate(_: &Policy, _: &EvalContext, _: Grants, _: &Path, _: &Path) -> Result<Confined> {
    bail!(
        "`openmoat run --isolate` runs on Linux only (bubblewrap); Windows has the preview tier \
         alone: `openmoat run` without --isolate"
    )
}

pub fn inside(_: &IsolatedArgs) -> Result<Code> {
    bail!("only `openmoat run --isolate` on Linux starts this")
}

/// What Windows itself sets for a process, kept under `openmoat run`'s
/// environment allowlist (ADR-077): where Windows, the person's profile and
/// the programs are, and what a console program reads.
pub const BASE_ENV: &[&str] = &[
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "PATHEXT",
    "Path",
    "USERPROFILE",
    // Not Windows' own, but git and other ports read it: as the agent
    // account the agent must still find the person's settings (ADR-129).
    "HOME",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "COMPUTERNAME",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PSModulePath",
];

/// None: every supported Windows has restricted tokens and job objects.
pub fn unavailable() -> Option<String> {
    None
}

/// Nothing in the operating system holds the network here.
pub const NETWORK: NetworkMode = NetworkMode::ProxyVariables;

/// Why `openmoat run --listen` is refused on Windows (ADR-108 §7, ADR-115):
/// nothing in the tier holds the network.
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature on every platform: Linux's lets `--listen` through"
)]
pub fn listen_refused_here(port: u16) -> Option<String> {
    Some(format!(
        "`openmoat run --listen {port}` is refused here: nothing in this system's tier holds \
         the network, so nothing could keep the port to this machine; start the agent \
         without `openmoat run`, under its hook"
    ))
}

/// No tool-shell wrapper on Windows (ADR-075 links `bash` and `zsh`): tool
/// commands keep the relay token, and the record says why.
pub const TOOL_SHELL_GAP: Option<&str> =
    Some("Windows: `openmoat run` has no tool-shell wrapper there yet");

/// `openmoat mcp wrap` does not put servers under this preview tier by
/// default: most are started through `npx`, a batch file it does not start,
/// and the tier holds writes only. `--sandbox` still asks for it.
pub const MCP_SANDBOX_BY_DEFAULT: bool = false;

/// The restrictions a Windows run plans: as the agent account (ADR-129), the
/// account, the job and the read denies, each confirmed on the agent's
/// process before it runs; otherwise (ADR-115) the token and the job, with
/// read denial named as what the account would bring. The network filter is
/// listed in both so the score counts it as missing.
pub fn restrictions(
    _isolated: bool,
    _port_only: bool,
    _kernel: Option<&crate::sandbox::landlock::abi::Kernel>,
    as_account: bool,
) -> Vec<Restriction> {
    let writes = if as_account {
        Mechanism::AgentAccount
    } else {
        Mechanism::RestrictedToken
    };
    vec![
        Restriction::planned(writes, true, true),
        Restriction::planned(Mechanism::JobObject, true, true),
        Restriction::planned(Mechanism::WfpNetwork, false, false),
        Restriction::planned(Mechanism::WindowsReadDeny, as_account, as_account),
    ]
}

/// Whether a run with the state directory `state` starts the agent as the
/// agent account (ADR-129), for `--print-boundary`, which confines nothing.
pub fn agent_account(state: &Path) -> bool {
    account::active(state).is_some()
}

/// None: Landlock is Linux's (ADR-082).
pub fn landlock() -> Option<crate::sandbox::landlock::abi::Kernel> {
    None
}

/// None: the port-only warning is Linux's; here the score names the network.
pub fn port_only_network() -> Option<String> {
    None
}

/// The agent gets no network of its own here.
#[expect(
    clippy::unnecessary_wraps,
    reason = "Linux decides at run time; every platform file shares the signature"
)]
pub fn no_network_namespace() -> Option<String> {
    Some(NETWORK_GAP.to_owned())
}

/// No Isolated tier on Windows.
pub fn isolation() -> super::isolation::Offered {
    super::isolation::Offered::Not
}

/// None: bubblewrap is Linux's.
pub fn bubblewrap() -> Option<bool> {
    None
}

/// None: no agent sandbox here uses user namespaces.
pub fn bubblewrap_userns() -> Option<std::result::Result<(), String>> {
    None
}

/// None: the run's report names what stays open inside the project.
pub fn project_open(_: &Policy, _: &EvalContext) -> Option<String> {
    None
}

/// No wrapper is linked on Windows ([`TOOL_SHELL_GAP`]).
pub fn link_tool_shell(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// No wrapper on Windows.
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature on every platform: Linux's adds a Landlock layer, which can fail"
)]
pub fn seal_tool_shell() -> Result<()> {
    Ok(())
}

/// No wrapper on Windows, so it is never started.
pub fn exec_tool_shell(_: &mut Command) -> std::io::Error {
    std::io::ErrorKind::Unsupported.into()
}

/// None: Windows consoles are not device paths a grant could name.
pub fn terminals() -> Vec<String> {
    Vec::new()
}

/// Whether this process runs under a restricted token: what the hook relay
/// takes as being inside a Windows run (`guard_relay/inside/windows.rs`).
pub fn in_restricted_token() -> bool {
    win32::current_token_restricted()
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        &mut self.command
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    pub fn report_mut(&mut self) -> &mut Report {
        &mut self.report
    }

    /// The tier's warning, which also makes the record name the network as
    /// weaker (`run.rs` reads it as the port-only one).
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the method every platform's `Confined` has; Linux's may have none"
    )]
    pub fn warning(&self) -> Option<&str> {
        Some(match self.mode {
            Mode::Token(_) => WARNING,
            Mode::Account(_) => ACCOUNT_WARNING,
        })
    }

    /// None: the report names what stays open inside the project.
    #[expect(
        clippy::unused_self,
        reason = "the method every platform's `Confined` has; Linux's reads itself"
    )]
    pub fn project_notice(&self) -> Option<&str> {
        None
    }

    /// False: `sandbox.project_top` is Linux's (ADR-090).
    #[expect(
        clippy::unused_self,
        reason = "the method every platform's `Confined` has; Linux's reads itself"
    )]
    pub fn project_top_open(&self) -> bool {
        false
    }

    /// Whether the agent starts as the agent account (ADR-129).
    pub fn agent_account(&self) -> bool {
        matches!(self.mode, Mode::Account(_))
    }

    /// Start the agent suspended under the token (or as the agent account)
    /// and in the job, read both back from its process, tell `on_launch`
    /// (which writes the boundary row and refuses what is missing), and only
    /// then let it run; wait for it, and end every process left in the job.
    pub fn status(
        mut self,
        on_launch: impl FnOnce(Option<LaunchCheck>) -> Result<()>,
    ) -> Result<ExitStatus> {
        if let (Mode::Account(_), Some(project)) = (&self.mode, &self.project) {
            // The project's files are the person's, and git refuses a
            // repository another account owns unless it is named safe.
            let vars = safe_directory(&self.command, project)?;
            self.command.envs(vars);
        }
        let program: Vec<u16> = self.command.get_program().encode_wide().collect();
        let args: Vec<Vec<u16>> = self
            .command
            .get_args()
            .map(|a| a.encode_wide().collect())
            .collect();
        let line = command_line::command_line(&program, &args)?;
        let inherited = std::env::vars_os()
            .map(|(name, value)| (units(&name), units(&value)))
            .collect();
        let changes = self
            .command
            .get_envs()
            .map(|(name, value)| (units(name), value.map(units)))
            .collect();
        let env = command_line::environment_block(inherited, changes)?;
        let mut application = program;
        application.push(0);
        let job = win32::Job::new().context("making the job object")?;
        let (started, check) = match &self.mode {
            Mode::Token(plan) => {
                let token = win32::restricted_token(&plan.sids()).context("making the token")?;
                let started = win32::start(&token, &job, &application, line, &env)?;
                let check = LaunchCheck {
                    restricted_token: Some(true),
                    agent_token_restricted: Some(started.token_restricted),
                    job_object: Some(true),
                    agent_in_job: Some(started.in_job),
                    ..LaunchCheck::default()
                };
                (started, check)
            }
            Mode::Account(active) => {
                let started = active.start(&job, &application, line, &env)?;
                let check = LaunchCheck {
                    agent_account: Some(true),
                    agent_token_account: Some(started.user_is_account),
                    job_object: Some(true),
                    agent_in_job: Some(started.started.in_job),
                    read_denies: Some(true),
                    ..LaunchCheck::default()
                };
                (started.started, check)
            }
        };
        if let Err(error) = on_launch(Some(check)) {
            job.terminate();
            return Err(error);
        }
        started.resume()?;
        let code = started.wait();
        // Whatever the agent left running ends with the run.
        job.terminate();
        Ok(ExitStatus::from_raw(code?))
    }
}

/// The `GIT_CONFIG_*` variables that add `safe.directory=<project>` after
/// those `command` and this process already set (git reads the key only
/// from protected configuration, which these are).
fn safe_directory(command: &Command, project: &str) -> Result<Vec<(String, String)>> {
    let set: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    let lookup = |var: &str| match set.iter().find(|(name, _)| name.eq_ignore_ascii_case(var)) {
        Some((_, value)) => value.clone(),
        None => std::env::var(var).ok(),
    };
    crate::sandbox::git_env::append(
        &lookup,
        vec![("safe.directory".to_owned(), project.to_owned())],
    )
}

fn units(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().collect()
}
