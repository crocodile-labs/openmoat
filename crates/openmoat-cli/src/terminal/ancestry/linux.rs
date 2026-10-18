//! Linux: each process's parent and command line from `/proc`.

use std::io;

use super::Process;

pub(super) fn agent_ancestor() -> io::Result<Option<String>> {
    super::walk(std::os::unix::process::parent_id(), process)
}

fn process(pid: u32) -> io::Result<Process> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    parse(&stat, &cmdline)
}

/// `/proc/<pid>/stat` is `pid (comm) state ppid …`; `comm` may hold spaces and
/// parentheses, so the fields after it start at the last `)`. `cmdline` is the
/// argument vector, NUL-separated; it is empty for a zombie, and then `comm`
/// names the program.
pub(super) fn parse(stat: &str, cmdline: &[u8]) -> io::Result<Process> {
    let malformed = || io::Error::other("unreadable /proc stat line");
    let open = stat.find('(').ok_or_else(malformed)?;
    let close = stat.rfind(')').ok_or_else(malformed)?;
    let comm = stat.get(open + 1..close).ok_or_else(malformed)?;
    let ppid = stat
        .get(close + 1..)
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|field| field.parse().ok())
        .ok_or_else(malformed)?;
    let mut argv: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    if argv.is_empty() {
        argv.push(comm.to_owned());
    }
    Ok(Process { ppid, argv })
}
