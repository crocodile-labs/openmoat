//! Command dispatch.

mod allow;
mod allowed;
mod audit;
mod bench;
mod demo;
mod doctor;
mod edit;
mod guard;
mod init;
mod mcp;
mod miswired_hook;
mod overview;
mod policy;
mod proxy;
mod replay;
mod report;
mod run;
mod sandbox;
mod secret;
mod service;
mod show;
mod status;
mod team;
mod trust;
mod uninstall;

use anyhow::Result;

use crate::cli::{
    AuditCommand, CaCommand, Cli, Command, McpCommand, PolicyCommand, ProxyCommand, SandboxCommand,
    SecretCommand,
};
use crate::exit::Code;

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
        Command::Status(args) => status::run(&args),
        Command::Doctor(args) => doctor::run(&args),
        Command::Allow(args) => allow::run(&args),
        Command::Allowed(args) => allowed::run(&args),
        Command::Edit => edit::run(),
        Command::Secret { command } => match command {
            SecretCommand::Add(args) => secret::add(&args),
            SecretCommand::List(args) => secret::list(&args),
        },
        Command::Trust(args) => trust::run(&args),
        Command::Replay(args) => replay::run(&args),
        Command::Report(args) => report::run(&args),
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
            AuditCommand::Anchor(args) => audit::anchor(&args),
        },
        Command::Run(args) => run::run(&args),
        Command::Isolated(args) => run::inside(&args),
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy::lint(&args),
            PolicyCommand::Check(args) => policy::check(&args),
            PolicyCommand::Compile(args) => policy::compile(&args),
            PolicyCommand::Upgrade(args) => policy::upgrade(&args),
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
    }
}
