//! Command dispatch.

mod allow;
mod audit;
mod bench;
mod doctor;
mod edit;
mod guard;
mod init;
mod overview;
mod policy;
mod proxy;
mod replay;
mod report;
mod run;
mod sandbox;
mod service;
mod show;
mod status;
mod team;
mod trust;
mod uninstall;

use anyhow::Result;

use crate::cli::{AuditCommand, Cli, Command, PolicyCommand, ProxyCommand, SandboxCommand};
use crate::exit::Code;

pub fn run(cli: Cli) -> Result<Code> {
    let Some(command) = cli.command else {
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
        Command::Edit => edit::run(),
        Command::Trust(args) => trust::run(&args),
        Command::Replay(args) => replay::run(&args),
        Command::Report(args) => report::run(&args),
        Command::Proxy(args) => match args.command {
            None => proxy::run(&args),
            Some(ProxyCommand::Install) => proxy::install(),
            Some(ProxyCommand::Uninstall) => proxy::uninstall(),
            Some(ProxyCommand::Status(status_args)) => proxy::status(&status_args),
        },
        Command::Audit { command } => match command {
            AuditCommand::Export(args) => audit::export(&args),
            AuditCommand::Verify(args) => audit::verify(&args),
            AuditCommand::Report(args) => team::run(&args),
        },
        Command::Run(args) => run::run(&args),
        Command::Isolated(args) => run::inside(&args),
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy::lint(&args),
            PolicyCommand::Check(args) => policy::check(&args),
            PolicyCommand::Compile(args) => policy::compile(&args),
        },
        Command::Bench(args) => bench::run(&args),
        Command::Sandbox { command } => match command {
            SandboxCommand::Show(args) => sandbox::show(&args),
            SandboxCommand::Sync => sandbox::sync(),
        },
    }
}
