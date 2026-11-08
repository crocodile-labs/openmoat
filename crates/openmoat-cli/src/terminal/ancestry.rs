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

use openmoat_hosts::{Host, ProcessSpec};

/// One process: its parent's id and its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Process {
    pub ppid: u32,
    pub argv: Vec<String>,
}

/// `openmoat` itself under either name: `openmoat run` is the parent of the
/// agent it starts. The agent hosts' own names come from their specs
/// (`HostSpec::process`).
const OPENMOAT: &[&str] = &["openmoat", "moat"];

/// Each host's process facts, in the host list's order.
fn processes() -> impl Iterator<Item = &'static ProcessSpec> {
    Host::EVERY.iter().map(|host| &host.spec().process)
}

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

/// The agent a command line runs, judged by its first two words (the program,
/// and the script an interpreter was given) and, after an interpreter
/// ([`candidates`]), its other words; or a Cursor helper,
/// whose program path holds spaces (`ps` splits it into several words), so
/// it is read from the words before the first option.
fn agent_name(argv: &[String]) -> Option<String> {
    let program: Vec<&str> = argv
        .iter()
        .map(String::as_str)
        .take_while(|word| !word.starts_with('-'))
        .collect();
    let program = program.join(" ").to_ascii_lowercase();
    if let Some(helper) = processes()
        .filter_map(|process| process.helper.as_ref())
        .find(|helper| program.contains(helper.path))
    {
        return Some(helper.name.to_owned());
    }
    let (mut program_words, mut paths) = candidates(argv);
    program_words
        .find_map(|word| {
            // `openmoat` itself by its program name; the hosts as their specs say.
            let lower = word.trim_start_matches('-').to_ascii_lowercase();
            let base = lower.rsplit(['/', '\\']).find(|s| !s.is_empty())?;
            let stem = base.strip_suffix(".exe").unwrap_or(base);
            if let Some(name) = OPENMOAT.iter().find(|name| **name == stem) {
                return Some((*name).to_owned());
            }
            Host::by_program(word).map(|(_, name)| name.to_owned())
        })
        // Any other path after an interpreter names an agent only as an
        // agent's package does: a script handed OpenMoat's own binary as an
        // argument (`python3 check.py --bin target/debug/openmoat`) is not
        // OpenMoat running.
        .or_else(|| paths.find_map(|word| Host::by_program(word).map(|(_, name)| name.to_owned())))
}

/// Programs that run an agent's script given after their own options
/// (`node --no-warnings /…/@github/copilot/index.js`).
const INTERPRETERS: &[&str] = &["node", "nodejs", "bun", "deno", "tsx", "python", "python3"];

/// The words of `argv` that may name the agent: the program words (the first
/// two, and after an interpreter ([`INTERPRETERS`], also `python3.12`) the
/// first word that is no option), then every other word after an interpreter
/// that is a path. An option's value (`--require /x/hook.js`) cannot be told
/// from the script without knowing each interpreter's options, so every path
/// counts as an agent's package would: that only adds a refusal.
fn candidates(argv: &[String]) -> (impl Iterator<Item = &String>, impl Iterator<Item = &String>) {
    let interpreter = argv.first().is_some_and(|program| {
        let lower = program.to_ascii_lowercase();
        let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
        let stem = base.strip_suffix(".exe").unwrap_or(base);
        INTERPRETERS.contains(&stem)
            || stem
                .strip_prefix("python")
                .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
    });
    let rest = argv.iter().skip(1).filter(move |_| interpreter);
    let operand = rest.clone().find(|word| !word.starts_with('-'));
    let paths = rest.filter(|word| word.contains(['/', '\\']));
    (argv.iter().take(2).chain(operand), paths)
}

#[cfg(test)]
mod tests;
