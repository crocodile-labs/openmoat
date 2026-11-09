//! The wrapper `openmoat run` puts in front of an agent's tool shell, so tool
//! commands do not receive the relay token (ADR-075).
//!
//! The run makes a directory of its own holding links named `bash` and `zsh`
//! to this binary, and points the variable the agent reads its tool shell from
//! at one of them. Started under one of those names with [`DIR_ENV`] set, this
//! binary drops the relay variables and starts the real shell. The agent's
//! hooks do not go through it: the hosts that use it start hooks by another
//! way ([`openmoat_hosts::ToolToken::Wrapper`]).
//!
//! The directory is outside everything the sandbox lets commands write, so a
//! command cannot replace the wrapper with one that keeps the token. A run
//! whose write grants hold the directory gets no wrapper ([`prepare`]).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use openmoat_hosts::{Host, ToolToken};

use super::platform;
use crate::context::path_string;
use crate::exit::Code;
use crate::guard_relay::{self, random_hex};
use crate::sandbox::ToolShellGrant;

/// Names the wrapper is linked under: the shells hosts ask for by name.
pub const NAMES: [&str; 2] = ["bash", "zsh"];

/// Set for the agent to the wrapper's directory: what makes a binary started
/// under one of [`NAMES`] the wrapper.
pub const DIR_ENV: &str = "MOAT_TOOL_SHELL_DIR";

/// The agent's own `SHELL`, which the wrapper puts back for the tool command.
pub const SHELL_ENV: &str = "MOAT_TOOL_SHELL_SHELL";

const SHELL: &str = "SHELL";

/// How the wrapper's directory's name starts.
const DIR_PREFIX: &str = "openmoat-tools-";

/// The wrapper directory of one run; removed when dropped.
#[derive(Debug)]
pub struct ToolShell {
    dir: PathBuf,
    moat: PathBuf,
    vars: &'static [&'static str],
    on_path: bool,
}

/// What to tell the person when `host` has a wrapper and this run has none:
/// its write grants hold the wrapper's directory ([`prepare`]).
pub fn off_notice(host: Option<Host>, tools: Option<&ToolShell>) -> Option<&'static str> {
    let wrapped = matches!(
        host.map(|h| h.spec().tool_token),
        Some(ToolToken::Wrapper { .. })
    );
    (wrapped && tools.is_none()).then_some(
        "moat run: tool commands keep the hook relay token in this run: \
         its write grants include the system temp directory, where the shell wrapper would be",
    )
}

/// The wrapper for `host`'s tool commands, when it has one. `write_roots` are
/// the trees (resolved) commands may write: a directory one of them holds
/// could be replaced by a command, so such a run gets none.
pub fn prepare(host: Option<Host>, write_roots: &[String]) -> Result<Option<ToolShell>> {
    let Some(ToolToken::Wrapper { vars, on_path }) = host.map(|h| h.spec().tool_token) else {
        return Ok(None);
    };
    let system =
        std::fs::canonicalize(std::env::temp_dir()).context("resolving the temp directory")?;
    let dir = system.join(format!("{DIR_PREFIX}{}", random_hex(8)?.as_str()));
    if write_roots.iter().any(|root| dir.starts_with(root)) {
        return Ok(None);
    }
    let moat = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("locating the openmoat binary")?;
    let tools = ToolShell {
        dir,
        moat,
        vars,
        on_path,
    };
    tools.create()?;
    Ok(Some(tools))
}

impl ToolShell {
    fn create(&self) -> Result<()> {
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            let mut builder = builder;
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
        };
        builder
            .create(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        for name in NAMES {
            platform::link_tool_shell(&self.moat, &self.dir.join(name))
                .with_context(|| format!("linking the tool shell {name}"))?;
        }
        Ok(())
    }

    /// What the sandbox must let the agent read and start.
    pub fn grant(&self) -> ToolShellGrant {
        ToolShellGrant {
            dir: path_string(&self.dir),
            moat: path_string(&self.moat),
        }
    }

    /// Point the agent at the wrapper. Named after the person's own shell
    /// when that is one of [`NAMES`], so a host that picks arguments by name
    /// picks the same ones, and `bash` otherwise.
    pub fn apply(&self, agent: &mut Command) {
        let own = std::env::var_os(SHELL);
        let name = own
            .as_deref()
            .map(Path::new)
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            .filter(|name| NAMES.contains(name))
            .unwrap_or(NAMES[0]);
        let wrapper = self.dir.join(name);
        for var in self.vars {
            agent.env(var, &wrapper);
        }
        agent.env(DIR_ENV, &self.dir);
        if let Some(own) = &own {
            agent.env(SHELL_ENV, own);
        }
        if self.on_path {
            let path = std::env::var_os("PATH").unwrap_or_default();
            let mut joined = OsString::from(&self.dir);
            joined.push(":");
            joined.push(path);
            agent.env("PATH", joined);
        }
    }
}

impl Drop for ToolShell {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// When this process was started as the wrapper: the code to exit with once
/// the real shell could not start. Replaces this process with the shell
/// otherwise, so it does not return.
pub fn entry() -> Option<Code> {
    let first = std::env::args_os().next()?;
    let name = Path::new(&first).file_name()?.to_str()?.to_owned();
    if !NAMES.contains(&name.as_str()) {
        return None;
    }
    // `DIR_ENV` is gone below the first wrapper, but the variable a host reads
    // its shell from is not: a program a tool command starts can use it too.
    let dir = std::env::var_os(DIR_ENV).map(PathBuf::from).or_else(|| {
        let parent = Path::new(&first).parent()?;
        let own = parent.file_name()?.to_str()?.starts_with(DIR_PREFIX);
        own.then(|| parent.to_path_buf())
    })?;
    Some(start(&name, &dir))
}

fn start(name: &str, dir: &Path) -> Code {
    // Only a process that held the token needs the extra sandbox layer, so
    // nested shells do not use up Landlock's sixteen.
    let held = std::env::var_os(guard_relay::TOKEN_ENV).is_some();
    if held && let Err(error) = platform::seal_tool_shell() {
        eprintln!("openmoat: refusing to start the tool command: {error:#}");
        return Code::Failed;
    }
    let Some(shell) = real_shell(name, dir) else {
        eprintln!("openmoat: no {name} found for the tool command");
        return Code::Failed;
    };
    let mut command = Command::new(&shell);
    command
        .args(std::env::args_os().skip(1))
        .env_remove(guard_relay::TOKEN_ENV)
        .env_remove(guard_relay::SOCKET_ENV)
        .env_remove(DIR_ENV)
        .env_remove(SHELL_ENV);
    match std::env::var_os(SHELL_ENV) {
        Some(own) => command.env(SHELL, own),
        None => command.env_remove(SHELL),
    };
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", without_dir(&path, dir));
    }
    let error = platform::exec_tool_shell(&mut command);
    eprintln!("openmoat: cannot start {}: {error}", shell.display());
    Code::Failed
}

/// The real shell for `name`: the first on `PATH` that is not in the wrapper's
/// directory, else the system's. Tool commands decide `PATH`, but by then the
/// token is gone: whatever this finds runs with no more than the command had.
fn real_shell(name: &str, dir: &Path) -> Option<PathBuf> {
    let dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    dirs.into_iter()
        .filter(|entry| entry != dir && entry.is_absolute())
        .map(|entry| entry.join(name))
        .chain(["/bin", "/usr/bin"].map(|d| Path::new(d).join(name)))
        .find(|candidate| candidate.is_file() && !candidate.starts_with(dir))
        .or_else(|| Some(PathBuf::from("/bin/sh")).filter(|p| p.is_file()))
}

/// `path` without the wrapper's directory, which [`ToolShell::apply`] puts
/// first for a host that finds its shell on `PATH`.
fn without_dir(path: &OsStr, dir: &Path) -> OsString {
    let kept = std::env::split_paths(path).filter(|entry| entry != dir);
    std::env::join_paths(kept).unwrap_or_else(|_| path.to_owned())
}

// `openmoat run` and its wrapper exist only on macOS and Linux.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn real_shell_skips_the_wrapper_directory() {
        let dir = Path::new("/tmp/openmoat-tools-x");
        let found = real_shell("sh", dir);
        assert!(found.is_some_and(|p| !p.starts_with(dir)));
    }

    #[test]
    fn the_wrapper_directory_leaves_the_path() {
        let path = OsString::from("/tmp/openmoat-tools-x:/usr/bin:/bin");
        let kept = without_dir(&path, Path::new("/tmp/openmoat-tools-x"));
        assert_eq!(kept, OsString::from("/usr/bin:/bin"));
    }

    #[test]
    fn a_host_without_a_wrapper_gets_no_directory() {
        let host = Host::EVERY
            .into_iter()
            .find(|host| !host.spec().tool_token.withheld());
        assert!(host.is_some());
        assert!(prepare(host, &[]).unwrap().is_none());
    }

    #[test]
    fn write_grants_over_the_directory_turn_the_wrapper_off() {
        let host = Host::EVERY
            .into_iter()
            .find(|host| matches!(host.spec().tool_token, ToolToken::Wrapper { .. }));
        assert!(host.is_some());
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let tools = prepare(host, &[crate::context::path_string(&root)]).unwrap();
        assert!(tools.is_none());
        assert!(off_notice(host, tools.as_ref()).is_some());
    }

    #[test]
    fn a_host_without_a_wrapper_gets_no_notice() {
        let host = Host::EVERY
            .into_iter()
            .find(|host| !host.spec().tool_token.withheld());
        assert!(host.is_some());
        assert_eq!(off_notice(host, None), None);
        assert_eq!(off_notice(None, None), None);
    }
}
