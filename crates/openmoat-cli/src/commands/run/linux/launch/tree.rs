//! Stop a process and everything it started (ADR-089). Killing only the
//! child would leave what it forked running, reparented; the agent cannot
//! go in a process group of its own, which would take it out of the
//! terminal's foreground group. So the tree is found in `/proc` by parent:
//! each process found is stopped (`SIGSTOP`) at once so it cannot fork past
//! the walk, the walk repeats until it finds no new one, then all are killed.

use std::process::Child;

use rustix::process::{Pid, Signal, kill_process};

/// Stop `child` and every process below it, then reap `child`.
pub fn stop(child: &mut Child) {
    let mut tree = vec![child.id()];
    signal(child.id(), Signal::STOP);
    loop {
        let found = children(&tree);
        if found.is_empty() {
            break;
        }
        for pid in found {
            signal(pid, Signal::STOP);
            tree.push(pid);
        }
    }
    for &pid in &tree {
        signal(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Send `signal` to `pid`; one that is gone already is no error.
fn signal(pid: u32, signal: Signal) {
    if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process(pid, signal);
    }
}

/// The processes whose parent is in `parents` and that are not in it.
fn children(parents: &[u32]) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| !parents.contains(pid))
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| parent(&stat))
                .is_some_and(|ppid| parents.contains(&ppid))
        })
        .collect()
}

/// The parent in a `/proc/<pid>/stat` line: the field after the state,
/// which follows the command name in parentheses (a name may hold spaces and
/// parentheses, so the last `)` ends it).
pub fn parent(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}
