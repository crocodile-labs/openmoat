//! Command-line grammar.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use openmoat_hosts::Host;

mod approvals;
mod audit;
mod credential;
mod mcp;
mod policy;
mod provenance;
mod serve;
mod snapshot;
mod team;

mod timeline;

pub use approvals::{
    ApprovalsCommand, ApprovalsStatusArgs, ApproverArgs, ConnectArgs, ListenArgs, WaitArgs,
};
pub use audit::{
    AnchorArgs, AuditCommand, CheckpointArgs, DeliverCommand, DeliverFlushArgs, DeliverStatusArgs,
    DeliverTestArgs, EvidenceArgs, ExportArgs, StatsArgs, TeamReportArgs, VerifyArgs,
};
pub use credential::CredentialCommand;
pub use mcp::{McpAcceptArgs, McpCommand, McpProxyArgs, McpUnwrapArgs, McpWrapArgs};
pub use policy::{
    ActionKind, CheckArgs, CheckDiffArgs, CompileArgs, DiffArgs, DiffFormat, InstallArgs, LintArgs,
    MigrateArgs, PolicyCommand, RemoveArgs, TrustKeyArgs, UpgradeArgs,
};
pub use provenance::{DiffProvenanceArgs, ProvenanceArgs, ProvenanceLevel};
pub use serve::ServeArgs;
pub use snapshot::{RestoreArgs, SnapshotArgs};
pub use team::{InventoryArgs, InventoryFormat, TeamCommand, TeamJoinArgs, TeamUpdateArgs};

pub use timeline::{Only, WatchArgs, WhyArgs};

#[derive(Debug, Parser)]
#[command(
    name = "openmoat",
    version = concat!(env!("CARGO_PKG_VERSION"), " (OpenMoat)"),
    about = "OpenMoat: decides what AI coding agents may do, and records every decision",
    long_about = "OpenMoat decides what AI coding agents may do on this machine and records\n\
                  every decision.\n\
                  The hook decides each call; the operating system also bounds commands inside the\n\
                  agents' sandboxes `openmoat init` configures and under `openmoat run`. Outside them an\n\
                  allowed command runs with your permissions (`openmoat status` shows each agent's level).\n\
                  Exit codes: 0 allow/ok, 1 the agent `run` started failed (or `inventory --check` found\n\
                  drift), 2 deny, 3 review (unresolved),\n\
                  64 usage or configuration error\n\
                  (`guard` exits 2 instead, so a broken hook blocks rather than fails open).\n\n\
                  Run `openmoat` alone to see what is protected and answer anything that needs you:\n\
                  a changed policy to accept, or a command an agent asked to run."
)]
pub struct Cli {
    /// `None` is the home screen (`openmoat` alone).
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Set up OpenMoat: the default policy, the audit log and the hooks in each agent it
    /// finds. At a terminal it shows each change and asks before making it.
    Init(InitArgs),
    /// Remove OpenMoat's hooks and sandbox settings from the agents, restoring the
    /// backups `openmoat init` took. Refused unless run from an interactive terminal.
    Uninstall(UninstallArgs),
    /// Make typing a hook-only agent's name start it in `openmoat run`'s sandbox, or
    /// with `--off` start it as before (ADR-108). Refused unless run by a person at a
    /// terminal.
    #[command(after_help = "\
Examples:
  openmoat confine <agent-id>          typing the agent's name now starts it under `openmoat run`
  openmoat confine --all               every hook-only agent `openmoat run` can start here
  openmoat confine --off <agent-id>    start it as before again
Agent ids are the ones `openmoat init --hosts` takes; `openmoat status` lists them.
`openmoat status` shows each agent's protection score. An agent `openmoat run` cannot
start on this machine is named with why. Guide: docs/USAGE.md, \"How each agent is protected\".")]
    Confine(ConfineArgs),
    /// Decide one hook request from stdin (invoked by host hooks, not by people).
    Guard(GuardArgs),
    /// Show one audit event, a session, or the most recent events.
    Show(ShowArgs),
    /// Follow the agents' calls as they happen, one line each, in a second terminal
    /// pane: what ran, what was denied and what waits for you. Reads the audit log
    /// only. Ctrl-C stops it.
    Watch(WatchArgs),
    /// Explain one decision in full: the call, the rules that decided it and where
    /// they are in your policy, the session's context, and how to change it.
    Why(WhyArgs),
    /// Report installation health: policy, hooks, each agent's protection level, recent activity.
    Status(StatusArgs),
    /// Verify policy lock, hooks and binary; `--accept` re-pins edits made by a person.
    Doctor(DoctorArgs),
    /// Approve a shell command for one session, or permanently; or permanently allow
    /// a site (`--site`) or a directory (`--dir`). Refused unless run from an interactive terminal.
    Allow(AllowArgs),
    /// List what you allowed: permanent rules from `openmoat allow`, active session
    /// grants, and trusted repositories, each with how to take it back.
    Allowed(AllowedArgs),
    /// Edit ~/.moat/policy.yaml in $VISUAL or $EDITOR; lint it, show the diff and ask
    /// before applying and re-pinning. Refused unless run from an interactive terminal.
    Edit,
    /// Keep a secret from the agent: OpenMoat adds it to the policy, shows the diff and
    /// asks, then syncs the sandbox. Refused unless run from an interactive terminal.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Answer reviews from another device: a chat channel you connect sends each held
    /// call to the people you allow, and an approval lets that exact call run once
    /// (ADR-078).
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Let a repository's .moat/policy.yaml allow, not only deny and review, until the file changes.
    /// Refused unless run from an interactive terminal, and over a drifted lock.
    Trust(TrustArgs),
    /// Replay agent sessions as a timeline of decisions.
    Replay(ReplayArgs),
    /// Summarise decisions over a window: verdicts, hosts, top rules, reviews per hour.
    Report(ReportArgs),
    /// Show what `status`, `show`, `report` and `why` show in a browser on this machine:
    /// listens on 127.0.0.1 only, prints a link with a token made for this run, and
    /// answers only requests that carry it. Read-only; Ctrl-C stops it. Refused unless
    /// run by a person at an interactive terminal.
    Serve(ServeArgs),
    /// Show which files and lines of commits agent sessions wrote, as this machine's audit
    /// log recorded them, and whether each session had read untrusted content first;
    /// `--write-notes` keeps it in git notes, `--verify` checks those notes.
    Provenance(ProvenanceArgs),
    /// Run the default-deny egress proxy, or install/uninstall it as a user service
    /// so it stays up without a person running it (macOS launchd, Linux systemd user unit).
    /// `openmoat proxy` alone runs the proxy; `install`, `uninstall` and `status` manage the service.
    Proxy(ProxyArgs),
    /// Export the audit log for review elsewhere, verify an export, report on it as
    /// evidence per framework control, and anchor the log's head outside it.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Run an agent and everything it starts in one sandbox made from the policy, with
    /// network only through OpenMoat's proxy (macOS, Linux; on Linux the Isolated tier
    /// where bubblewrap works). Turn the agent's own sandbox off. On Linux in the
    /// Lightweight tier (`--no-isolate`, or no bubblewrap), files inside the project
    /// (`.env`, `.git`, `.moat`) are not protected.
    Run(RunArgs),
    /// Take a snapshot of the project's files into OpenMoat's own store, list the
    /// snapshots (`--list`) or remove old ones (`--prune`). `openmoat run` takes one
    /// before the agent starts and one after it exits. Refused when an agent started it.
    Snapshot(SnapshotArgs),
    /// Put the project's files back as a snapshot holds them: shows what changes and
    /// asks first, and takes a snapshot of the files as they are so the restore can be
    /// undone. Refused unless run by a person at an interactive terminal.
    Restore(RestoreArgs),
    /// What `openmoat run` starts inside bubblewrap on Linux (not for people).
    #[command(hide = true)]
    Isolated(IsolatedArgs),
    /// The local credential helper `openmoat run` sets up for git and the AWS tools
    /// (ADR-118): asks the run's proxy for a minted secret (not for people).
    #[command(hide = true)]
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// Inspect and test policy files.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Send the bundled `MoatBench` scenarios to OpenMoat, or to any hook (`--hook`), as each
    /// host's hook payloads in a throwaway home, and print the scorecard. The scenarios'
    /// commands never run; only the hook does.
    Bench(BenchArgs),
    /// Show what the policy (the default one when none is installed) decides for a fixed
    /// list of example agent calls. Nothing runs; no hook or file is touched.
    Demo(DemoArgs),
    /// The agents' own sandboxes, which OpenMoat configures from the policy.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    /// The MCP servers the agents start: accept a changed definition, and run a server
    /// through OpenMoat to pin its tool descriptions.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// The hook commands, plugin hooks and git programs the agents load besides
    /// OpenMoat's hook (ADR-109): list them, and accept a new or changed one.
    Hooks {
        #[command(subcommand)]
        command: HooksCommand,
    },
    /// A team's signed policy bundle as a managed layer over your policy (ADR-119):
    /// join it, update it, leave it. Nothing is sent anywhere.
    Team {
        #[command(subcommand)]
        command: TeamCommand,
    },
    /// This machine's state for a team: agents and versions, hooks and whether they
    /// run, protection levels, MCP servers and their pins, policy and lock, latest
    /// checkpoint. Redacted; reads files only, sends nothing unless `--deliver`.
    #[command(after_help = "\
Examples:
  openmoat inventory                          JSON (openmoat-inventory-v1)
  openmoat inventory --format ocsf            OCSF 1.3.0 events, for a SIEM
  openmoat inventory --check ~/src/acme-openmoat; echo $?
                                              0: this machine has what the team's bundle requires; 1: it differs
Guide: docs/TEAM.md")]
    Inventory(InventoryArgs),
    /// A second factor on every command that loosens the protection (ADR-117): once
    /// set up, `allow`, `trust`, `edit`, `doctor --accept` and the other commands that
    /// widen or re-pin ask for a code from your authenticator app as well.
    #[command(after_help = "\
Try it, with any authenticator app on your phone:
  openmoat gate setup                       scan the link or type the key, then type the app's code
  openmoat allow --site example.com         now asks for a code first
  openmoat show --session policy-changes    every change, with whether a code was given
  openmoat gate remove                      asks for a code, then turns it off
Guide: docs/USAGE.md, \"Ask for a code before anything is loosened\".")]
    Gate {
        #[command(subcommand)]
        command: GateCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum GateCommand {
    /// Make a new secret, show it once for your authenticator app, and turn the gate on
    /// once you type a code the app gives. Refused unless run by a person at an
    /// interactive terminal.
    Setup,
    /// Whether the gate is on, and how many wrong codes count against its limit now.
    Status,
    /// Turn the gate off: asks for a code first. Refused unless run by a person at an
    /// interactive terminal.
    Remove,
}

#[derive(Debug, Subcommand)]
pub enum HooksCommand {
    /// List every hook command, plugin hook, program-running setting and git program
    /// the set-up agents load besides OpenMoat's hook, with the shell classifier's
    /// verdict on each new or changed one. Reads files only.
    List,
    /// Show each new or changed one with its verdict and ask before recording it.
    /// Until then the calls of the agent that loads it are held for review (denied
    /// when its command is one the policy denies). Refused unless run from an
    /// interactive terminal, by a person, and over a drifted lock.
    Accept,
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
pub struct DemoArgs {
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "four command-line flags, each of its own: clap reads them as bools"
)]
pub struct InitArgs {
    /// Hosts to install hooks for, without asking. Defaults to every supported host
    /// that is present, each confirmed at the terminal.
    #[arg(long, value_delimiter = ',', value_parser = parse_host())]
    pub hosts: Option<Vec<Host>>,

    /// Set up every agent found without asking (for scripts).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Print what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Install and pin the agents' hooks only: no agent sandbox, no MCP step
    /// (pinning or wrapping), no opt-in questions. Over a readable lock the
    /// other agents' pins stay as they are; without one, every installed hook
    /// is pinned, as a plain `init` does.
    #[arg(long, conflicts_with_all = ["mcp_proxy", "mcp_no_sandbox"])]
    pub hooks_only: bool,

    /// Output format: `text` (the default), or `json`: one document on stdout
    /// for scripts. `json` asks no question, so it needs `--hosts`, `--yes` or
    /// `--dry-run`.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Also print each file written and its hook entries, the backups and the
    /// files the lock pins.
    #[arg(long)]
    pub verbose: bool,

    #[command(flatten)]
    pub managed: InitManagedArgs,

    #[command(flatten)]
    pub mcp: InitMcpArgs,
}

/// `init`'s managed hook flag (ADR-098).
#[derive(Debug, Args)]
pub struct InitManagedArgs {
    /// Also write OpenMoat's hook where an administrator's hooks live, for each
    /// agent set up that has such a place (its managed settings, policy or
    /// enterprise hooks), so a repository's settings cannot turn it off. A
    /// person at a terminal only. Where the file needs root, OpenMoat prints
    /// the command that installs it instead.
    #[arg(long)]
    pub managed: bool,
}

/// `init`'s MCP proxy flags.
#[derive(Debug, Args)]
pub struct InitMcpArgs {
    /// Also run every stdio MCP server in the agents' user configuration through
    /// `openmoat mcp proxy` (`openmoat mcp wrap`), which starts only an accepted
    /// definition, pins its tool descriptions and, wherever `openmoat run` can sandbox,
    /// starts it in that sandbox.
    #[arg(long)]
    pub mcp_proxy: bool,

    /// With --mcp-proxy: start the servers without `openmoat run`'s sandbox
    /// (`openmoat mcp wrap --no-sandbox`).
    #[arg(long, requires = "mcp_proxy")]
    pub mcp_no_sandbox: bool,

    /// Do not offer to run the agents' stdio MCP servers through `openmoat mcp
    /// proxy`, and leave them as they are. At a terminal `init` offers it by default;
    /// `openmoat mcp wrap` does it later.
    #[arg(long, conflicts_with = "mcp_proxy")]
    pub no_mcp_proxy: bool,
}

impl InitMcpArgs {
    /// The sandbox choice for `--mcp-proxy`: `None` is the default.
    pub fn sandbox(&self) -> Option<bool> {
        self.mcp_no_sandbox.then_some(false)
    }
}

#[derive(Debug, Args)]
pub struct ConfineArgs {
    /// The agents, by id (`gemini-cli`, `openclaw`, …).
    #[arg(value_parser = parse_host(), required_unless_present = "all", conflicts_with = "all")]
    pub agents: Vec<Host>,
    /// Every agent set up here that `openmoat run` can start.
    #[arg(long)]
    pub all: bool,
    /// Remove the agents' shims instead, so typing their names starts them as before.
    #[arg(long)]
    pub off: bool,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Hosts to remove OpenMoat from. Defaults to every supported host.
    #[arg(long, value_delimiter = ',', value_parser = parse_host())]
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
    #[arg(long, value_parser = parse_host(), conflicts_with = "session")]
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
    #[arg(long, value_parser = parse_host())]
    pub host: Option<Host>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Broker a secret: the agent holds a placeholder, and OpenMoat puts the value in
    /// one header of requests to one host. `openmoat secret add gh` is the GitHub API token
    /// (`GITHUB_TOKEN`, `api.github.com`).
    Add(SecretAddArgs),
    /// List the brokered secrets: id, host, header and where the value is read from.
    /// Never the value.
    List(SecretListArgs),
}

#[derive(Debug, Args)]
pub struct SecretListArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct AllowedArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct SecretAddArgs {
    /// The secret's id: lowercase letters, digits and `-`. `gh` alone sets up GitHub.
    pub id: String,
    /// The one host whose requests get the value.
    #[arg(long)]
    pub host: Option<String>,
    /// The request header the value goes in.
    #[arg(long)]
    pub header: Option<String>,
    /// Read the value from this environment variable of `openmoat proxy` and the agent.
    #[arg(long, value_name = "NAME")]
    pub env: Option<String>,
    /// Read the value from this file (absolute or under `~/`).
    #[arg(long, value_name = "PATH")]
    pub file: Option<String>,
    /// Inside `openmoat run`, decrypt HTTPS to the host to put the value in
    /// (`tls: terminate`, ADR-043). Needs the proxy CA, which this offers to make.
    #[arg(long)]
    pub tls_terminate: bool,
    /// Only the requests this rule names get the value: `METHOD /path`, where `*` is one
    /// path segment and `**` any number (`--allow 'GET /repos/**'`). Repeatable; any other
    /// request to the host is refused. Needs `--tls-terminate`.
    #[arg(long = "allow", value_name = "RULE", requires = "tls_terminate")]
    pub allow: Vec<String>,
}

#[derive(Debug, Args)]
pub struct AllowArgs {
    /// The exact shell command to approve.
    #[arg(conflicts_with = "last")]
    pub command: Option<String>,

    /// Take host, session and command from the most recent `review` in the audit log.
    #[arg(long)]
    pub last: bool,

    /// Host of the session to approve (with --session).
    #[arg(long, value_parser = parse_host(), requires = "session")]
    pub host: Option<Host>,

    /// Approve for this session id only (exact command match).
    #[arg(long, conflicts_with = "always")]
    pub session: Option<String>,

    /// A directory of the project a session grant for a command applies in
    /// (its repository root, else the directory). Defaults to the current directory.
    #[arg(long, value_name = "DIR", requires = "session")]
    pub project: Option<PathBuf>,

    /// Add a permanent allow rule to ~/.moat/policy.d/approved.yaml instead.
    #[arg(long)]
    pub always: bool,

    /// Allow network access to this host (`net`), web fetches included, until removed
    /// or for --for.
    #[arg(long, value_name = "HOST", conflicts_with_all = ["command", "last", "session", "dir", "remove"])]
    pub site: Option<String>,

    /// Allow reading and writing in this directory and below it, until removed or for
    /// --for; deny rules (secrets, OpenMoat's own files) still win.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["command", "last", "session", "remove"])]
    pub dir: Option<PathBuf>,

    /// Remove a rule from ~/.moat/policy.d/approved.yaml by id (`approved-3`).
    #[arg(long, value_name = "RULE_ID", conflicts_with_all = ["command", "last", "session"])]
    pub remove: Option<String>,

    /// End the --always, --site or --dir grant after this long: 30m, 2h, 3d, 1w (at
    /// most 366 days). Without it the grant lasts until removed; granting the same
    /// thing again sets its end anew.
    #[arg(long = "for", value_name = "DURATION", value_parser = crate::approvals::parse_for,
          conflicts_with_all = ["session", "remove", "prune"])]
    pub for_ms: Option<i64>,

    /// Remove the grants in ~/.moat/policy.d/approved.yaml whose --for has ended.
    #[arg(long, conflicts_with_all = ["command", "last", "session", "always", "site", "dir", "remove"])]
    pub prune: bool,
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

    /// Also print every check with its paths, each agent's known gaps, and every
    /// place each host sandbox is stricter or wider than the policy.
    #[arg(long)]
    pub verbose: bool,

    /// Output format; `json` prints every check as one document, for tools that show them.
    #[arg(long, value_enum, default_value_t = Format::Text, conflicts_with_all = ["accept", "verbose"])]
    pub format: Format,

    /// Write a diagnostic file for a bug report instead of printing the checks:
    /// version, system, agents, policy findings, the checks and recent decisions
    /// (verdict, rule ids, host and tool name only). Nothing is sent; the file must
    /// not exist yet. Refused when an agent is among the parent processes.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["accept", "format"])]
    pub bundle: Option<PathBuf>,

    /// How many recent audit decisions the bundle lists.
    #[arg(long, value_name = "N", default_value_t = 20, requires = "bundle")]
    pub bundle_events: usize,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// `install` / `uninstall` / `status` manage the user service that keeps the proxy
    /// running; without a subcommand the proxy runs in this terminal.
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
    /// Install `openmoat proxy` as a user service that starts at login and restarts on failure
    /// (macOS launchd user agent, Linux systemd user unit; refused on Windows for now, #272).
    /// Refused unless run from an interactive terminal.
    Install,
    /// Stop and remove the user service. Refused unless run from an interactive terminal.
    Uninstall,
    /// Report the user service's state: not installed / stopped / running / drift-blocked /
    /// crashlooping. Exits 64 for any state other than running or not installed.
    Status(ProxyStatusArgs),
    /// The certificate authority `openmoat run`'s proxy reads HTTPS with, for the brokered
    /// secrets that say `tls: terminate` (ADR-043).
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Make a new CA for the hosts of the secrets that say `tls: terminate`, limited to them
    /// by name constraints, and pin it in the policy lock; again to rotate it or cover new
    /// hosts. Shows what it covers and asks first. Refused unless run by a person at an
    /// interactive terminal.
    Init,
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

    /// The one TCP port the agent may listen on, on loopback only: a local
    /// service the agent serves, such as OpenClaw's Gateway. It may bind no other
    /// port and no other address. On Linux the port is forwarded from this
    /// machine's loopback into the sandbox's network; refused where the sandbox
    /// has no network of its own (bubblewrap), on macOS (its sandbox would let a
    /// bind to every address through) and on Windows.
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1024..))]
    pub listen: Option<u16>,

    /// Print every place the sandbox is stricter or wider than the policy.
    #[arg(long)]
    pub verbose: bool,

    // `--isolate` or `--no-isolate`.
    #[command(flatten)]
    pub tier: TierArgs,

    /// Where the agent cannot get a network of its own (Linux, bubblewrap): `auto`
    /// restricts its connections by port only and says so; `require` refuses to start.
    #[arg(long, value_enum, default_value_t = Netns::Auto, value_name = "MODE")]
    pub netns: Netns,

    // `--env NAME`… and `--scrub-env`.
    #[command(flatten)]
    pub environment: RunEnvArgs,

    /// Take no snapshot of the project before the agent starts and after it exits
    /// (recorded in the audit log).
    #[arg(long)]
    pub no_snapshot: bool,

    /// Print the sandbox boundary this run would start with (tier, downgrades, network,
    /// Landlock ABI, each restriction) and exit without starting the agent.
    #[arg(long)]
    pub print_boundary: bool,

    /// Output format of `--print-boundary`.
    #[arg(long, value_enum, default_value_t = Format::Text, requires = "print_boundary")]
    pub format: Format,

    /// The agent and its arguments, after `--`.
    #[arg(required = true, last = true, value_name = "AGENT")]
    pub command: Vec<std::ffi::OsString>,
}

/// What `openmoat run` passes on of the environment it starts from (ADR-077, ADR-105).
#[derive(Debug, Args)]
pub struct RunEnvArgs {
    /// A variable of this environment to pass on for this run when the environment is
    /// scrubbed. A name, never `NAME=value` or a pattern. Repeatable.
    #[arg(long = "env", value_name = "NAME", value_parser = parse_env_name)]
    pub envs: Vec<String>,

    /// Pass on only the allowlist of this environment for this run (ADR-105): what every
    /// program needs, the agent's own variables, `sandbox.env_allow` and `--env` names.
    /// What `sandbox.env: scrubbed` in your policy does on every run.
    #[arg(long)]
    pub scrub_env: bool,
}

/// Which tier `openmoat run` starts, when the person names one.
#[derive(Debug, Args)]
pub struct TierArgs {
    /// The Isolated tier (Linux, bubblewrap), or nothing: the agent sees only the project
    /// without its denied paths, the policy's read roots and `--write` paths, and reaches
    /// only OpenMoat's proxy. Refused where bubblewrap cannot run. Without this flag or
    /// `--no-isolate`, Linux starts this tier where bubblewrap works and otherwise says
    /// why and starts the Lightweight tier.
    #[arg(long)]
    pub isolate: bool,

    /// The Lightweight tier on Linux instead of the default Isolated tier: commands see
    /// the rest of the machine the policy's read roots allow, and inside the project
    /// `openmoat run` says on start what stays open (ADR-090). Recorded in the
    /// audit log; refused when a policy has `require.run: full-boundary`. Changes
    /// nothing on macOS, which has no Isolated tier yet.
    #[arg(long, conflicts_with = "isolate")]
    pub no_isolate: bool,
}

/// `--env`: the one form the policy's `sandbox.env_allow` takes too.
fn parse_env_name(name: &str) -> Result<String, String> {
    match openmoat_core::env_name_problem(name) {
        Some(problem) => Err(problem.to_owned()),
        None => Ok(name.to_owned()),
    }
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
    /// The Unix socket the check of the agent's start is reported on (ADR-089).
    #[arg(long)]
    pub report: PathBuf,
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
    #[arg(long, value_parser = parse_host())]
    pub host: Option<Host>,

    /// Print on stderr the environment the hook gets and every payload sent.
    #[arg(long)]
    pub verbose: bool,

    /// Print the proof report instead of the scorecard: each security promise per
    /// layer (policy decision, host hook, OS sandbox, network boundary) as PASS,
    /// FAIL or NOT TESTED HERE with the reason. Runs attacks under `openmoat run` in
    /// the throwaway home. Exits 1 when an exercised layer fails.
    #[arg(long, conflicts_with = "hook")]
    pub report: bool,

    /// The directory to make the throwaway home in (default: the system temp
    /// directory). On Linux the OS sandbox rows need one outside /tmp, which the
    /// sandbox lets commands read.
    #[arg(long, value_name = "DIR")]
    pub scratch_dir: Option<PathBuf>,

    /// Output format; markdown only with --report.
    #[arg(long, value_enum, default_value_t = BenchFormat::Text)]
    pub format: BenchFormat,
}

/// `openmoat bench --format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BenchFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// Host whose hook payload is on stdin.
    #[arg(long, value_parser = parse_host())]
    pub host: Host,

    /// Set only by `openmoat run` for a call it relays from inside its sandbox
    /// (ADR-028): the command runs in that sandbox (ADR-039). Not for hooks.
    #[arg(long, hide = true)]
    pub relayed: bool,
    /// Record that the host loaded OpenMoat's plugin, and read no payload
    /// (run by the plugin as it loads; `openmoat status` reports it).
    #[arg(long)]
    pub heartbeat: bool,
    /// Run from an OpenMoat package installed through the agent's own plugin
    /// channel (ADR-099): decide the call, or give no decision where `openmoat
    /// init`'s own hook for the agent is installed and pinned, so each call is
    /// decided once. `openmoat doctor` reports what it did last.
    #[arg(long, conflicts_with = "home")]
    pub plugin: bool,
    /// The state directory to decide with, as `openmoat init` writes it into
    /// the hook (ADR-071). It wins over `MOAT_HOME`, and a `MOAT_HOME` that
    /// names another directory makes the guard deny.
    #[arg(long, value_name = "DIR")]
    pub home: Option<String>,
    /// The hook event the entry was installed for, as `openmoat init` writes
    /// it for an agent whose payloads name none (GitHub Copilot CLI): the
    /// payload is read as that event's, never as another's.
    #[arg(long, value_name = "EVENT")]
    pub event: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

/// `openmoat run --netns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Netns {
    Auto,
    Require,
}

/// A host id, with every one `--help` lists and the shell completes.
fn parse_host() -> impl clap::builder::TypedValueParser<Value = Host> {
    use clap::builder::TypedValueParser as _;
    clap::builder::PossibleValuesParser::new(Host::ALL.map(Host::id))
        .try_map(|id| id.parse::<Host>())
}
