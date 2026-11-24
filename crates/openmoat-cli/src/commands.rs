//! Command dispatch.

mod allow;
mod allowed;
mod approvals;
mod audit;
pub(crate) mod bench;
mod demo;
mod doctor;
mod edit;
mod gate;
pub(crate) mod guard;
mod hooks;
mod init;
mod inventory;
mod mcp;
mod miswired_hook;
mod overview;
mod policy;
mod provenance;
mod proxy;
mod replay;
mod report;
mod restore;
mod run;
mod sandbox;
mod secret;
mod serve;
mod service;
mod show;
mod snapshot;
mod status;
mod team;
mod team_mode;
mod trust;
mod uninstall;
mod watch;
mod why;

use anyhow::Result;

use crate::cli::{
    ApprovalsCommand, AuditCommand, CaCommand, Cli, Command, DeliverCommand, GateCommand,
    HooksCommand, McpCommand, PolicyCommand, ProxyCommand, SandboxCommand, SecretCommand,
    TeamCommand,
};
use crate::exit::Code;

pub use run::tool_shell_entry;

pub fn run(cli: Cli) -> Result<Code> {
    let Some(command) = cli.command else {
        if miswired_hook::detected() {
            eprintln!("openmoat was run as a hook without `guard --host <agent>`; denying");
            return Ok(Code::Deny);
        }
        return overview::run();
    };
    match command {
        Command::Init(args) => init::run(&args),
        Command::Uninstall(args) => uninstall::run(&args),
        Command::Guard(args) => Ok(guard::run(&args)),
        Command::Show(args) => show::run(&args),
        Command::Watch(args) => watch::run(&args),
        Command::Why(args) => why::run(&args),
        Command::Status(args) => status::run(&args),
        Command::Doctor(args) => doctor::run(&args),
        Command::Allow(args) => allow::run(&args),
        Command::Allowed(args) => allowed::run(&args),
        Command::Edit => edit::run(),
        Command::Secret { command } => match command {
            SecretCommand::Add(args) => secret::add(&args),
            SecretCommand::List(args) => secret::list(&args),
        },
        Command::Approvals { command } => match command {
            ApprovalsCommand::Connect(args) => approvals::connect(&args),
            ApprovalsCommand::Allow(args) => approvals::allow(&args),
            ApprovalsCommand::Remove(args) => approvals::remove(&args),
            ApprovalsCommand::Status(args) => approvals::status(&args),
            ApprovalsCommand::Test => approvals::test(),
            ApprovalsCommand::Listen(args) => approvals::listen(&args),
            ApprovalsCommand::Install => approvals::install(),
            ApprovalsCommand::Uninstall => approvals::uninstall(),
            ApprovalsCommand::Wait(args) => approvals::wait(&args),
            ApprovalsCommand::Disconnect => approvals::disconnect(),
        },
        Command::Trust(args) => trust::run(&args),
        Command::Replay(args) => replay::run(&args),
        Command::Report(args) => report::run(&args),
        Command::Serve(args) => serve::run(&args),
        Command::Provenance(args) => provenance::run(&args),
        Command::Proxy(args) => match args.command {
            None => proxy::run(&args),
            Some(ProxyCommand::Install) => proxy::install(),
            Some(ProxyCommand::Uninstall) => proxy::uninstall(),
            Some(ProxyCommand::Status(status_args)) => proxy::status(&status_args),
            Some(ProxyCommand::Ca {
                command: CaCommand::Init,
            }) => proxy::ca_init(),
        },
        Command::Audit { command } => match command {
            AuditCommand::Export(args) => audit::export(&args),
            AuditCommand::Verify(args) => audit::verify(&args),
            AuditCommand::Report(args) => team::run(&args),
            AuditCommand::Evidence(args) => audit::evidence(&args),
            AuditCommand::Stats(args) => audit::stats(&args),
            AuditCommand::Anchor(args) => audit::anchor(&args),
            AuditCommand::Checkpoint(args) => audit::checkpoint(&args),
            AuditCommand::Deliver { command } => match command {
                DeliverCommand::Status(args) => audit::deliver::status(&args),
                DeliverCommand::Test(args) => audit::deliver::test(&args),
                DeliverCommand::Flush(args) => audit::deliver::flush(&args),
            },
        },
        Command::Run(args) => run::run(&args),
        Command::Snapshot(args) => snapshot::run(&args),
        Command::Restore(args) => restore::run(&args),
        Command::Isolated(args) => run::inside(&args),
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy::lint(&args),
            PolicyCommand::Check(args) => policy::check(&args),
            PolicyCommand::CheckDiff(args) => policy::check_diff(&args),
            PolicyCommand::Diff(args) => policy::diff(&args),
            PolicyCommand::Compile(args) => policy::compile(&args),
            PolicyCommand::Upgrade(args) => policy::upgrade(&args),
            PolicyCommand::Migrate(args) => policy::migrate(&args),
            PolicyCommand::Install(args) => policy::install(&args),
            PolicyCommand::TrustKey(args) => policy::trust_key(&args),
            PolicyCommand::Remove(args) => policy::remove(&args),
        },
        Command::Bench(args) => bench::run(&args),
        Command::Demo(args) => demo::run(&args),
        Command::Sandbox { command } => match command {
            SandboxCommand::Show(args) => sandbox::show(&args),
            SandboxCommand::Sync => sandbox::sync(),
        },
        Command::Mcp { command } => match command {
            McpCommand::Accept(args) => mcp::accept(&args),
            McpCommand::Proxy(args) => mcp::proxy(&args),
            McpCommand::Wrap(args) => mcp::wrap(&args),
            McpCommand::Unwrap(args) => mcp::unwrap(&args),
        },
        Command::Hooks { command } => match command {
            HooksCommand::List => hooks::list(),
            HooksCommand::Accept => hooks::accept(),
        },
        Command::Gate { command } => match command {
            GateCommand::Setup => gate::setup(),
            GateCommand::Status => gate::status(),
            GateCommand::Remove => gate::remove(),
        },
        Command::Team { command } => match command {
            TeamCommand::Join(args) => team_mode::join(&args),
            TeamCommand::Update(args) => team_mode::update(&args),
            TeamCommand::Leave => team_mode::leave(),
        },
        Command::Inventory(args) => inventory::run(&args),
    }
}

/// The command that puts an agent without a sandbox of its own in one, as
/// `moat status`, `moat doctor` and `moat init` name it: `--isolate` on Linux,
/// where plain `moat run` leaves paths inside the project open ([`run::tier`]).
pub fn sandboxing_command() -> &'static str {
    run::tier::command(run::bubblewrap())
}

/// [`sandboxing_command`] as a person types it, without the backticks.
pub fn sandboxing_words() -> &'static str {
    run::tier::words(run::bubblewrap())
}

/// Why `moat run` here would have no network namespace (Linux without a
/// usable bubblewrap, where it refuses a `--write` path outside the project).
pub fn run_port_only_network() -> Option<String> {
    run::port_only_network()
}

/// Whether this process runs under a restricted token, as the Windows tier
/// of `openmoat run` starts the agent and its hooks (ADR-115).
#[cfg(windows)]
pub fn run_in_restricted_token() -> bool {
    run::windows::in_restricted_token()
}

/// Why `openmoat run` cannot sandbox on this machine; `None` when it can.
pub fn run_unavailable() -> Option<String> {
    run::unavailable()
}

/// Whether the system's bubblewrap creates a user namespace here, for the
/// agents' own sandboxes (`sandbox::linux_needs`); `None` without it or off
/// Linux.
pub fn run_bubblewrap_userns() -> Option<std::result::Result<(), String>> {
    run::bubblewrap_userns()
}

/// What `openmoat run` lacks here for its full boundary (ADR-077); `None` when
/// it has all of it.
pub fn run_full_boundary_gap() -> Option<String> {
    run::full_boundary_gap()
}
