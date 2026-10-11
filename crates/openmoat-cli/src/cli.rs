//! Command-line grammar.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use openmoat_hosts::Host;

mod policy;

pub use policy::{ActionKind, CheckArgs, CompileArgs, LintArgs, PolicyCommand, UpgradeArgs};

#[derive(Debug, Parser)]
#[command(
    name = "moat",
    version = concat!(env!("CARGO_PKG_VERSION"), " (OpenMoat)"),
    about = "OpenMoat: decides what AI coding agents may do, and records every decision",
    long_about = "OpenMoat decides what AI coding agents may do on this machine and records\n\
                  every decision.\n\
                  The hook decides each call; the operating system also bounds commands inside the\n\
                  agents' sandboxes `moat init` configures and under `moat run`. Outside them an\n\
                  allowed command runs with your permissions (`moat status` shows each agent's level).\n\
                  Exit codes: 0 allow/ok, 1 the agent `run` started failed, 2 deny, 3 ask (unresolved),\n\
                  64 usage or configuration error\n\
                  (`guard` exits 2 instead, so a broken hook blocks rather than fails open).\n\n\
                  Run `moat` alone to see what is protected and answer anything that needs you:\n\
                  a changed policy to accept, or a command an agent asked to run."
)]
pub struct Cli {
    /// `None` is the home screen (`moat` alone).
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Install the kernel: default policy, audit log and host hooks. At a terminal it
    /// asks before changing each agent it finds.
    Init(InitArgs),
    /// Remove OpenMoat's hooks and sandbox settings from the agents, restoring the
    /// backups `moat init` took. Refused unless run from an interactive terminal.
    Uninstall(UninstallArgs),
    /// Decide one hook request from stdin (invoked by host hooks, not by people).
    Guard(GuardArgs),
    /// Show one audit event, a session, or the most recent events.
    Show(ShowArgs),
    /// Report installation health: policy, hooks, each agent's protection level, recent activity.
    Status(StatusArgs),
    /// Verify policy lock, hooks and binary; `--accept` re-pins edits made by a person.
    Doctor(DoctorArgs),
    /// Approve a shell command for one session, or permanently; or permanently allow
    /// a site (`--site`) or a directory (`--dir`). Refused unless run from an interactive terminal.
    Allow(AllowArgs),
    /// Edit ~/.moat/policy.yaml in $VISUAL or $EDITOR; lint it, show the diff and ask
    /// before applying and re-pinning. Refused unless run from an interactive terminal.
    Edit,
    /// Let a repository's .moat/policy.yaml allow, not only deny and ask, until the file changes.
    /// Refused unless run from an interactive terminal, and over a drifted lock.
    Trust(TrustArgs),
    /// Replay agent sessions as a timeline of decisions.
    Replay(ReplayArgs),
    /// Summarise decisions over a window: verdicts, hosts, top rules, asks per hour.
    Report(ReportArgs),
    /// Run the default-deny egress proxy, or install/uninstall it as a user service
    /// so it stays up without a person running it (macOS launchd, Linux systemd user unit).
    /// `moat proxy` alone runs the proxy; `install`, `uninstall` and `status` manage the service.
    Proxy(ProxyArgs),
    /// Export the audit log for review elsewhere, and verify an export.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Run an agent in a sandbox generated from the policy, its network only through
    /// OpenMoat's proxy (Lightweight tier, ADR-018; macOS, Linux; `--isolate`: Isolated
    /// tier, Linux). The agent's own sandbox must be off.
    Run(RunArgs),
    /// What `moat run --isolate` starts inside its sandbox (not for people).
    #[command(hide = true)]
    Isolated(IsolatedArgs),
    /// Inspect and test policy files.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Send the bundled `MoatBench` scenarios to OpenMoat, or to any hook (`--hook`), as each
    /// host's hook payloads in a throwaway home, and print the scorecard. The scenarios'
    /// commands never run; only the hook does.
    Bench(BenchArgs),
    /// The host sandboxes OpenMoat configures from the policy (Standard tier, ADR-018).
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SandboxCommand {
    /// Print the sandbox settings the policy compiles to and the translation losses; writes nothing.
    Show(SandboxShowArgs),
    /// Write the sandbox settings from the current policy and re-pin them.
    /// Refused unless run from an interactive terminal, and over a drifted lock.
    Sync,
}

#[derive(Debug, Args)]
pub struct SandboxShowArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Output format; `json` prints each agent's protection level only.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Hosts to install hooks for, without asking. Defaults to every supported host
    /// that is present, each confirmed at the terminal.
    #[arg(long, value_delimiter = ',', value_parser = parse_host)]
    pub hosts: Option<Vec<Host>>,

    /// Set up every agent found without asking (for scripts).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Print what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Hosts to remove OpenMoat from. Defaults to every supported host.
    #[arg(long, value_delimiter = ',', value_parser = parse_host)]
    pub hosts: Option<Vec<Host>>,

    /// Also delete OpenMoat's state directory (policy, lock, audit log). Not with
    /// --hosts: the agents left set up would deny every tool call without it.
    #[arg(long, conflicts_with = "hosts")]
    pub purge: bool,
}

#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "24h", conflicts_with = "session")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host, conflicts_with = "session")]
    pub host: Option<Host>,

    /// One session by id, regardless of window.
    #[arg(long)]
    pub session: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "7d")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct AllowArgs {
    /// The exact shell command to approve.
    #[arg(conflicts_with = "last")]
    pub command: Option<String>,

    /// Take host, session and command from the most recent `ask` in the audit log.
    #[arg(long)]
    pub last: bool,

    /// Host of the session to approve (with --session).
    #[arg(long, value_parser = parse_host, requires = "session")]
    pub host: Option<Host>,

    /// Approve for this session id only (exact command match).
    #[arg(long, conflicts_with = "always")]
    pub session: Option<String>,

    /// Add a permanent allow rule to ~/.moat/policy.d/approved.yaml instead.
    #[arg(long)]
    pub always: bool,

    /// Permanently allow network access to this host (`net`), web fetches included.
    #[arg(long, value_name = "HOST", conflicts_with_all = ["command", "last", "session", "dir", "remove"])]
    pub site: Option<String>,

    /// Permanently allow reading and writing in this directory and below it; deny
    /// rules (secrets, kernel files) still win.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["command", "last", "session", "remove"])]
    pub dir: Option<PathBuf>,

    /// Remove a rule from ~/.moat/policy.d/approved.yaml by id (`approved-3`).
    #[arg(long, value_name = "RULE_ID", conflicts_with_all = ["command", "last", "session"])]
    pub remove: Option<String>,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// A directory in the repository. Defaults to the current directory.
    pub repo: Option<PathBuf>,

    /// Withdraw the trust instead: the repository policy only tightens again.
    #[arg(long)]
    pub revoke: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Accept the current policy and hook files as trusted and re-pin the lock.
    /// Refused unless run from an interactive terminal.
    #[arg(long)]
    pub accept: bool,

    /// Print every place each host sandbox is stricter or wider than the policy.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// `install` / `uninstall` / `status` manage the user service that keeps the proxy
    /// running; without a subcommand the proxy runs in this terminal (ADR-020).
    #[command(subcommand)]
    pub command: Option<ProxyCommand>,

    /// Address to listen on. Must be a loopback address: the proxy serves this machine only.
    /// Default: 127.0.0.1 and the policy's `sandbox.proxy_port`, where the host sandboxes
    /// then send their commands' traffic; 127.0.0.1:18080 when it is not set.
    /// Ignored when a subcommand is given (`install`, `uninstall`, `status`).
    #[arg(long)]
    pub listen: Option<std::net::SocketAddr>,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Install `moat proxy` as a user service that starts at login and restarts on failure
    /// (macOS launchd user agent, Linux systemd user unit; refused on Windows for now, #272).
    /// Refused unless run from an interactive terminal.
    Install,
    /// Stop and remove the user service. Refused unless run from an interactive terminal.
    Uninstall,
    /// Report the user service's state: not installed / stopped / running / drift-blocked /
    /// crashlooping. Exits 64 for any state other than running or not installed.
    Status(ProxyStatusArgs),
}

#[derive(Debug, Args)]
pub struct ProxyStatusArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// A file or directory the agent and its commands may also read and write, such as
    /// the agent's own state (`~/.claude`); deny rules still win. Repeatable.
    #[arg(long = "write", value_name = "PATH")]
    pub writes: Vec<PathBuf>,

    /// Print every place the sandbox is stricter or wider than the policy.
    #[arg(long)]
    pub verbose: bool,

    /// Isolated tier (Linux, bubblewrap): the agent sees only the project without its
    /// denied paths, the policy's read roots and `--write` paths, and reaches only
    /// OpenMoat's proxy. Refused where bubblewrap cannot run.
    #[arg(long)]
    pub isolate: bool,

    /// The agent and its arguments, after `--`.
    #[arg(required = true, last = true, value_name = "AGENT")]
    pub command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub struct IsolatedArgs {
    /// The Unix socket that reaches OpenMoat's proxy outside.
    #[arg(long)]
    pub socket: PathBuf,
    /// The loopback port to serve the proxy on inside.
    #[arg(long)]
    pub port: u16,
    /// The Landlock rules, as JSON.
    #[arg(long)]
    pub rules: String,
    /// The agent and its arguments, after `--`.
    #[arg(required = true, last = true, value_name = "AGENT")]
    pub command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub struct BenchArgs {
    /// A hook command line to test instead of OpenMoat, run through the system shell
    /// with each payload on stdin, the way hosts run hooks. Needs --host.
    #[arg(long, requires = "host")]
    pub hook: Option<String>,

    /// The host whose payloads to send and whose hook protocol reads the replies.
    /// Defaults to every host when testing OpenMoat.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Print on stderr the environment the hook gets and every payload sent.
    #[arg(long)]
    pub verbose: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// Host whose hook payload is on stdin.
    #[arg(long, value_parser = parse_host)]
    pub host: Host,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Event id as printed by `guard` (hex).
    #[arg(conflicts_with = "session")]
    pub id: Option<String>,

    /// All events of one host session, oldest first.
    #[arg(long)]
    pub session: Option<String>,

    /// Events since a window start, oldest first: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, conflicts_with_all = ["id", "session"])]
    pub since: Option<String>,

    /// Most recent events (default when nothing else is given).
    #[arg(long, default_value_t = 10)]
    pub recent: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Write events to stdout as JSON Lines, oldest first, each with its chain hashes.
    Export(ExportArgs),
    /// Check an export's hash chain without the database and print its head hash.
    Verify(VerifyArgs),
    /// Report over exports from several machines: per host, per rule, top asks and
    /// denies, false-positive candidates. Every file must verify first.
    Report(TeamReportArgs),
}

#[derive(Debug, Args)]
pub struct TeamReportArgs {
    /// Files `moat audit export` wrote; events present in several are counted once.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The file `moat audit export` wrote.
    pub file: PathBuf,

    /// A head hash recorded earlier (`moat audit verify` or `moat doctor` printed it);
    /// fail unless a verified event carries it.
    #[arg(long)]
    pub anchor: Option<String>,

    /// Fail when no `--anchor` is given: without one, an export whose newest
    /// events were dropped still verifies.
    #[arg(long)]
    pub require_anchor: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "all")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Only this session id.
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

fn parse_host(value: &str) -> Result<Host, String> {
    value
        .parse()
        .map_err(|e: openmoat_hosts::HostError| e.to_string())
}
