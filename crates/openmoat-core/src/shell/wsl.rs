//! Commands that cross from Windows into the Windows Subsystem for Linux
//! (ADR-083).
//!
//! On native Windows OpenMoat's rules name Windows paths (`~/.ssh/**` is
//! `C:/Users/me/.ssh/**`). A command run inside a WSL distribution reads the
//! distribution's own files (its `~/.ssh`, its shell start-up files), which no
//! Windows path names, and a WSL distribution can reach the Windows drives
//! under `/mnt/c` as well. So a command that hands work to WSL gets an
//! `@wsl <how>` atom, which the `wsl-crossing` rule denies:
//!
//! - its program is a WSL launcher: `wsl`, `wslg`, `wslconfig` (also its 8.3
//!   short name `wslcon~1`), the legacy `bash.exe` in `System32`, `Sysnative`,
//!   `SysWOW64` or under `WinSxS`, or a listed distribution's own launcher
//!   (`ubuntu`, `ubuntu2204`, `debian`, `kali`, …), read as Windows reads a
//!   path ([`path`]: either slash, any letter case, trailing dots and spaces,
//!   an NTFS stream, `.` components): `@wsl <launcher>`;
//! - a `cmd`, PowerShell or launching program's line runs one ([`runner`]),
//!   where a bare `bash` counts too: Windows' search finds `System32\bash.exe`
//!   first;
//! - a word starting with `\\` or `//` names the distributions' share
//!   (`wsl$` or `wsl.localhost` as any of its components, so the `\\?\UNC\`,
//!   `\\.\UNC\` and `\\?\GLOBALROOT\Device\Mup\` forms too), alone, after
//!   `file:`, or as an option's value (`--dir=\\wsl$\x`): `@wsl share`.
//!   `net use Z: \\wsl$\Ubuntu` maps a drive to it, after which no path names
//!   WSL at all.
//!
//! A runner line built at run time (`^` escapes, `%var%` or `!var!` in the
//! program's place, joined strings, `iex`, `-EncodedCommand`) gets
//! `@opaque-code <runner>`, which the `opaque-code` rule holds for review: what
//! it runs cannot be read. A bare `bash` outside such a line is not a WSL
//! launcher: in Git Bash, where Claude Code runs its commands on Windows, it is
//! Git's own bash, and it is classified like any shell.

use super::{ClassifyError, ShellContext, Sink};
use crate::action::AtomicAction;

mod path;
mod runner;

#[cfg(test)]
mod tests;

/// Programs that run a command inside WSL wherever they are installed.
const LAUNCHERS: &[&str] = &["wsl", "wslg", "wslconfig"];

/// Distributions' own launchers (`ubuntu2204.exe run <command>`), from the
/// Microsoft Store packages of `wsl --list --online`. A distribution
/// installed another way is reached through `wsl -d`, which is denied anyway.
const DISTRIBUTION_LAUNCHERS: &[&str] = &["ubuntu", "debian", "kali", "fedoraremix"];

/// Distribution launchers named with a version after this prefix
/// (`opensuse-leap-15.6`, `oraclelinux_9_1`, `almalinux9`).
const VERSIONED_LAUNCHERS: &[&str] = &["opensuse-", "sles-", "oraclelinux", "almalinux"];

/// The Windows folders whose `bash.exe` is WSL's legacy launcher.
const SYSTEM_DIRS: &[&str] = &["system32", "sysnative", "syswow64"];

/// The components that name the WSL share (`\\wsl$`, `\\wsl.localhost`).
const SHARES: &[&str] = &["wsl$", "wsl.localhost"];

/// Names that make a runner line at least need review wherever they stand in
/// it, quoted or not (`runner::names_launcher`): exact parsing of `cmd` and
/// PowerShell keeps finding new ways to hide the program.
const BACKSTOP: &[&str] = &["wsl", "wslg", "wslconfig", "bash"];

/// Emit `@wsl <how>` for each way `argv` hands work to WSL, and
/// `@opaque-code <runner>` for a runner line built at run time or one that
/// names a launcher where its program cannot be told.
pub(super) fn note(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let Some(first) = argv.first() else {
        return Ok(());
    };
    if let Some(launcher) = launcher(first) {
        push(sink, "@wsl", &launcher)?;
    }
    relative(first, ctx, sink)?;
    // `fsutil hardlink create NEW EXISTING`: a launcher under another name
    if path::program(first) == "fsutil" && argv.iter().any(|a| a.eq_ignore_ascii_case("hardlink")) {
        for launcher in argv[1..].iter().filter_map(|a| launcher_path(a)) {
            push(sink, "@wsl", &launcher)?;
        }
    }
    let found = runner::scan(first, &argv[1..]);
    for launcher in &found.launchers {
        push(sink, "@wsl", launcher)?;
    }
    if found.opaque {
        push(sink, "@opaque-code", &path::program(first))?;
    }
    if found.share || argv.iter().any(|word| names_share(word)) {
        push(sink, "@wsl", "share")?;
    }
    Ok(())
}

/// `./bash.exe` runs the file of that name in the working directory: a
/// launcher when that directory is a system folder (after `cd
/// /c/Windows/System32`), and at least a review when it is not known.
fn relative(first: &str, ctx: &ShellContext<'_>, sink: &mut Sink) -> Result<(), ClassifyError> {
    let unified = first.replace('\\', "/");
    let explicit = unified.starts_with("./") || unified.starts_with("../");
    let name = path::program(first);
    if !explicit || !(BACKSTOP.contains(&name.as_str()) || launcher(&name).is_some()) {
        return Ok(());
    }
    match ctx.paths(first) {
        Ok(paths) => {
            for found in paths.iter().filter_map(|p| launcher(p)) {
                push(sink, "@wsl", &found)?;
            }
            Ok(())
        }
        Err(_) => push(sink, "@opaque-code", &name),
    }
}

/// The launcher a path names (`C:\Windows\System32\wsl.exe`), for a link
/// made to it; a bare name is not a path.
fn launcher_path(word: &str) -> Option<String> {
    word.contains(['/', '\\']).then(|| launcher(word)).flatten()
}

fn push(sink: &mut Sink, atom: &str, how: &str) -> Result<(), ClassifyError> {
    sink.push(AtomicAction::Shell {
        argv: vec![atom.to_owned(), how.to_owned()],
    })
}

/// The WSL launcher `word` runs, as its lower-case name without `.exe`;
/// `None` when it runs something else.
fn launcher(word: &str) -> Option<String> {
    let path = path::read(word);
    let name = path.program();
    let parent = path.parts.iter().rev().nth(1).map(String::as_str);
    let system_bash = name == "bash"
        && (parent.is_some_and(|d| SYSTEM_DIRS.contains(&d))
            || path.parts.iter().any(|part| part == "winsxs"));
    let is_launcher = LAUNCHERS.contains(&name.as_str())
        || is_short_name(&name, "wslcon")
        || system_bash
        || is_distribution(&name);
    is_launcher.then_some(name)
}

/// Whether `word` names the WSL share: a word starting with `\\` or `//`
/// (after `file:`, after an option's `=`, or after the `:` of an option such
/// as `-Path:\\wsl$\x`) with `wsl$` or `wsl.localhost` as one of its
/// components. A share name built when the line runs (`\\ws%x%l$`) is not
/// read here; in a runner line it makes the line opaque (`runner.rs`).
fn names_share(word: &str) -> bool {
    let value = word.split_once('=').map_or(word, |(_, value)| value);
    let option = (word.starts_with('-') || (word.starts_with('/') && !word.starts_with("//")))
        .then(|| word.split_once(':').map(|(_, value)| value))
        .flatten()
        .unwrap_or(word);
    [word, value, option].into_iter().any(|word| {
        let unified = word.replace('\\', "/");
        let after_scheme = unified
            .get(..5)
            .filter(|scheme| scheme.eq_ignore_ascii_case("file:"))
            .map_or(unified.as_str(), |_| &unified[5..]);
        after_scheme.starts_with("//")
            && path::read(after_scheme)
                .parts
                .iter()
                .any(|part| SHARES.contains(&part.as_str()))
    })
}

/// Whether `name` is the 8.3 short name Windows gives a long file name that
/// starts with `prefix` (`wslcon~1` for `wslconfig.exe`).
fn is_short_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('~'))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A distribution's own launcher: `ubuntu`, `ubuntu2204` (8.3: `ubuntu~1`),
/// `debian`, `opensuse-leap-15.6`, … Not `ubuntu-drivers` and the other
/// Ubuntu tools named `ubuntu-…`.
fn is_distribution(name: &str) -> bool {
    let versioned_ubuntu = name
        .strip_prefix("ubuntu")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
    DISTRIBUTION_LAUNCHERS.contains(&name)
        || versioned_ubuntu
        || is_short_name(name, "ubuntu")
        || VERSIONED_LAUNCHERS.iter().any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|rest| !rest.is_empty())
        })
}
