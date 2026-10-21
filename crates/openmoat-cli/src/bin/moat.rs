//! `moat`: the name OpenMoat's command had up to 0.7.0, kept for a few
//! releases so hooks, scripts and habits that call it keep working.
//!
//! It runs the `openmoat` in its own directory with the same arguments, the
//! same standard streams and the same exit code; on Unix it replaces itself
//! with it. Hooks written by an older `moat init` name this file until
//! `openmoat init` rewrites them, so every failure follows the hook contract:
//! `moat guard` that cannot start `openmoat` exits 2 (deny, ADR-015), any
//! other command 64.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Exit codes of `openmoat`'s contract (`exit.rs`).
const DENY: u8 = 2;
const USAGE: u8 = 64;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let failed = if args.first().is_some_and(|arg| arg == "guard") {
        DENY
    } else {
        USAGE
    };
    let Some(openmoat) = beside() else {
        eprintln!(
            "moat: cannot find openmoat next to this moat; reinstall OpenMoat, which installs both"
        );
        return ExitCode::from(failed);
    };
    let mut command = Command::new(&openmoat);
    command.args(&args);
    let error = run(command, failed);
    eprintln!("moat: cannot run {}: {error}", openmoat.display());
    ExitCode::from(failed)
}

/// `openmoat` in this executable's directory, when it is a file. The
/// directory is the one the executable really lives in: on macOS
/// `current_exe` is the path it was started by, so a `moat` linked from
/// another directory (`~/bin/moat → …/bin/moat`) would otherwise look beside
/// the link. The link's own directory is the fallback.
fn beside() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = format!("openmoat{}", std::env::consts::EXE_SUFFIX);
    std::fs::canonicalize(&exe)
        .ok()
        .into_iter()
        .chain([exe])
        .filter_map(|exe| exe.parent().map(|dir| dir.join(&name)))
        .find(|path| path.is_file())
}

/// Replace this process with `command`; returns only when that failed.
#[cfg(unix)]
fn run(mut command: Command, _failed: u8) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    command.exec()
}

/// Run `command` and exit with its code; returns only when it could not start.
#[cfg(not(unix))]
fn run(mut command: Command, failed: u8) -> std::io::Error {
    match command.status() {
        Ok(status) => {
            // A code that does not fit (Windows has 32-bit codes, a crash has
            // none) is a failure, so a crashed `guard` still denies.
            let code = status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(failed);
            std::process::exit(i32::from(code))
        }
        Err(error) => error,
    }
}
