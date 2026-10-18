//! The processes that started this one, and whether an agent is among them.
//!
//! An agent can hand a command a terminal (a pty wrapper such as `script`),
//! but the command still descends from the agent's process. Walking parent
//! ids finds it. A process that detaches itself (a double fork, `setsid`, a
//! launchd or systemd job) is reparented to the init process and so escapes
//! this check; `docs/THREAT_MODEL.md` lists that limit.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as platform;

use std::io;

/// One process: its parent's id and its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Process {
    pub ppid: u32,
    pub argv: Vec<String>,
}

/// Executable names of the agent hosts, and `moat` itself: `moat run` is the
/// parent of the agent it starts.
const AGENTS: &[&str] = &["claude", "codex", "cursor-agent", "moat"];

/// Directories the agents install their code under, for an agent that runs
/// as `node <dir>/…/cli.js` or from a versioned file (`claude/versions/2.1.0`).
const AGENT_DIRS: &[&[&str]] = &[&["claude", "versions"], &["claude-code"], &["cursor-agent"]];

/// More ancestors than any real process tree has; a longer chain is a loop.
const MAX_DEPTH: usize = 256;

/// The agent among this process's ancestors, by the name it was found under.
pub(super) fn agent_ancestor() -> io::Result<Option<String>> {
    platform::agent_ancestor()
}

/// Walk from `pid` up the parent chain through `lookup` and return the first
/// agent found. The init process (pid 1) is checked too, for a container
/// whose entry point is the agent, but a failure to read it ends the walk
/// instead of failing it: some systems hide it from other users.
fn walk(
    mut pid: u32,
    mut lookup: impl FnMut(u32) -> io::Result<Process>,
) -> io::Result<Option<String>> {
    for _ in 0..MAX_DEPTH {
        if pid == 0 {
            return Ok(None);
        }
        let process = match lookup(pid) {
            Ok(process) => process,
            Err(_) if pid == 1 => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(name) = agent_name(&process.argv) {
            return Ok(Some(name));
        }
        if pid == 1 || process.ppid == pid {
            return Ok(None);
        }
        pid = process.ppid;
    }
    Err(io::Error::other(
        "the chain of parent processes does not end",
    ))
}

/// The agent a command line runs, judged by its first two words: the program,
/// and the script an interpreter (`node`) was given.
fn agent_name(argv: &[String]) -> Option<String> {
    argv.iter().take(2).find_map(|word| {
        let lower = word.trim_start_matches('-').to_ascii_lowercase();
        let segments: Vec<&str> = lower.split(['/', '\\']).filter(|s| !s.is_empty()).collect();
        let base = segments.last()?;
        let stem = [".exe", ".js", ".mjs", ".cjs"]
            .iter()
            .find_map(|ext| base.strip_suffix(ext))
            .unwrap_or(base);
        if let Some(name) = AGENTS.iter().find(|a| **a == stem) {
            return Some((*name).to_owned());
        }
        let dirs = &segments[..segments.len() - 1];
        AGENT_DIRS
            .iter()
            .find(|pattern| dirs.windows(pattern.len()).any(|w| w == **pattern))
            .map(|pattern| pattern[0].to_owned())
    })
}

#[cfg(test)]
mod tests;
