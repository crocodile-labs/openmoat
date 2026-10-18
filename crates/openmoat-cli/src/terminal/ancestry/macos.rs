//! macOS: the process table from `/bin/ps`.
//!
//! Workspace lints forbid `unsafe`, so `proc_pidinfo` cannot be called
//! directly; `/bin/ps` is part of the system volume and runs by absolute path.
//! When it cannot run (an agent's sandbox may forbid it) the check fails, and
//! the command is refused.

use std::collections::HashMap;
use std::io;
use std::process::Command;

use super::Process;

const PS: &str = "/bin/ps";

pub(super) fn agent_ancestor() -> io::Result<Option<String>> {
    let out = Command::new(PS)
        .args(["-A", "-ww", "-o", "pid=,ppid=,args="])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{PS} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let table = parse(&String::from_utf8_lossy(&out.stdout));
    super::walk(std::os::unix::process::parent_id(), |pid| {
        table
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("process {pid} is not in the process table")))
    })
}

/// `ps -o pid=,ppid=,args=` lines: two numbers, then the command line, whose
/// words are split on spaces (`ps` joins the argument vector with them).
pub(super) fn parse(text: &str) -> HashMap<u32, Process> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let id = words.next()?.parse().ok()?;
            let ppid = words.next()?.parse().ok()?;
            let argv = words.map(str::to_owned).collect();
            Some((id, Process { ppid, argv }))
        })
        .collect()
}
