//! `moat`: command-line entry point for OpenMoat.
//!
//! The binary owns all I/O (files, environment, terminal); decisions are made
//! by `openmoat-core`. Exit codes are a stable contract used by host hooks:
//! see [`exit::Code`].

mod anchor;
mod approvals;
mod cli;
mod commands;
mod context;
mod environment;
mod exit;
mod guard_relay;
mod hangs;
mod home;
mod install;
mod integrity;
mod json5;
mod mcp;
mod os_version;
mod packs;
mod project;
mod project_settings;
mod protection;
mod push;
mod realpath;
mod render;
mod repo;
mod sandbox;
mod secrets;
mod session_code;
mod signing;
mod taint;
mod terminal;
mod time;
mod trust;
mod upgrade;

use std::process::ExitCode;

/// This build's version, as `openmoat --version` prints it.
const VERSION: &str = env!("CARGO_PKG_VERSION");

use clap::Parser;

fn main() -> ExitCode {
    // A host runs `moat guard` and blocks the tool call only on exit 2; any other
    // failure lets the call through. So a `guard` that cannot even parse its
    // arguments denies (ADR-015), and every other command reports usage errors
    // with the dedicated code, never 2.
    let failed = if invoked_as_hook() {
        exit::Code::Deny
    } else {
        exit::Code::Usage
    };
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = !error.use_stderr();
            let _ = error.print();
            return if informational {
                exit::Code::Ok
            } else {
                failed
            }
            .into();
        }
    };
    match commands::run(cli) {
        Ok(code) => code.into(),
        // Never for `guard`: a hook that cannot answer must not exit 0 (ADR-015).
        Err(error) if !invoked_as_hook() && broken_pipe(&error) => exit::Code::Ok.into(),
        Err(error) => {
            eprintln!("moat: {error:#}");
            failed.into()
        }
    }
}

/// True when the first argument is `guard`, the subcommand host hooks run.
fn invoked_as_hook() -> bool {
    std::env::args_os().nth(1).is_some_and(|arg| arg == "guard")
}

/// A reader that stops early (`moat show | head`) closes the pipe. Like other
/// command-line tools, stop quietly instead of reporting it as an error.
fn broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let kind = cause
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
            .or_else(|| cause.downcast_ref::<serde_json::Error>()?.io_error_kind());
        kind == Some(std::io::ErrorKind::BrokenPipe)
    })
}
