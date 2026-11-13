use std::io::Read as _;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::*;

/// The status of a process with this run's two filters over one inherited.
const STATUS: &str = "Name:\tsh\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n";

fn applied(inherited: u32) -> LaunchCheck {
    LaunchCheck {
        landlock: Some(Enforcement::Partial),
        seccomp_filters: Some(2),
        inherited_seccomp_filters: Some(inherited),
        ..LaunchCheck::default()
    }
}

#[test]
fn the_status_lines_are_read_against_the_inherited_filters() {
    let mut check = applied(1);
    read_status(&mut check, STATUS);
    assert_eq!(check.proc_no_new_privs, Some(true));
    assert_eq!(check.proc_seccomp_filters, Some(3));
    assert_eq!(check.proc_seccomp_filter, Some(true));
    assert_eq!(check.linux_failure(), None);
    // `Seccomp: 2` from a parent's filter alone (a container runtime's) is
    // not this run's: the count shows the run's two are not there.
    let mut parent_only = applied(1);
    read_status(
        &mut parent_only,
        &STATUS.replace("filters:\t3", "filters:\t1"),
    );
    assert_eq!(parent_only.proc_seccomp_filter, Some(false));
    assert!(
        parent_only
            .linux_failure()
            .unwrap()
            .contains("Seccomp_filters")
    );
    let mut off = applied(0);
    read_status(
        &mut off,
        "NoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
    );
    assert_eq!(off.proc_no_new_privs, Some(false));
    assert_eq!(off.proc_seccomp_filter, Some(false));
    // Lines missing: unknown, which is a gap too.
    let mut unknown = applied(0);
    read_status(&mut unknown, "Name:\tsh\n");
    assert_eq!(unknown.proc_seccomp_filter, None);
    assert!(unknown.linux_failure().unwrap().contains("NoNewPrivs"));
}

#[test]
fn the_parent_is_read_past_a_name_with_spaces_and_parentheses() {
    assert_eq!(tree::parent("42 (a) b) c) S 7 42 42 0"), Some(7));
    assert_eq!(tree::parent("1 (init) S 0 1 1"), Some(0));
    assert_eq!(tree::parent("garbage"), None);
}

/// Whether `pid` is still a process that is not a zombie.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z')
    })
}

/// Wait up to two seconds for `pid` to be gone (its new parent reaps it).
fn gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while alive(pid) {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// The child and the grandchild it started in the background both go.
#[test]
fn stopping_a_tree_ends_what_the_child_started() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = [0u8; 16];
    let n = child.stdout.as_mut().unwrap().read(&mut line).unwrap();
    let grandchild: u32 = String::from_utf8_lossy(&line[..n]).trim().parse().unwrap();
    assert!(alive(grandchild));
    let pid = child.id();
    tree::stop(&mut child);
    assert!(gone(pid), "the child is still running");
    assert!(gone(grandchild), "what the child started is still running");
}

/// The real thing on this kernel: a child of a restricted thread shows
/// `no_new_privs` and this run's filters in `/proc`, and the check passes.
/// Below Landlock ABI 4 the ruleset cannot be built, as `openmoat run`
/// refuses there too.
#[test]
fn a_restricted_child_shows_no_new_privs_and_its_filters() {
    let Some(restrict) = restriction() else {
        return;
    };
    let mut command = Command::new("/bin/sleep");
    command.arg("0");
    let mut seen = None;
    let status = restricted(command, restrict, false, |check| {
        seen = check;
        Ok(())
    })
    .unwrap();
    assert!(status.success());
    let seen = seen.unwrap();
    assert_eq!(seen.proc_no_new_privs, Some(true), "{seen:?}");
    assert_eq!(seen.proc_seccomp_filter, Some(true), "{seen:?}");
    assert_eq!(seen.seccomp_filters, Some(2), "{seen:?}");
    let inherited = seen.inherited_seccomp_filters.unwrap();
    assert_eq!(seen.proc_seccomp_filters, Some(inherited + 2), "{seen:?}");
    assert!(seen.failure.is_none(), "{seen:?}");
    assert!(seen.landlock_abi.is_some_and(|abi| abi >= 4), "{seen:?}");
}

/// When the run cannot keep the start on record, the agent and what it
/// started are stopped and the run fails.
#[test]
fn an_error_on_record_stops_the_agent_and_its_children() {
    let Some(restrict) = restriction() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let pids = dir.path().join("pids");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "sleep 30 & echo $$ $! > \"$0\"; wait"])
        .arg(&pids);
    let refused = restricted(command, restrict, false, |_| {
        wait_for(&pids);
        bail!("the audit log is locked")
    })
    .unwrap_err();
    assert!(format!("{refused:#}").contains("locked"), "{refused:#}");
    let written = std::fs::read_to_string(&pids).unwrap();
    for pid in written.split_whitespace() {
        assert!(gone(pid.parse().unwrap()), "{pid} of {written} still runs");
    }
}

/// A gap the check finds stops the agent and what it started before the
/// start goes on record, the record names the gap, and the run fails.
#[test]
fn a_gap_stops_the_agent_before_it_goes_on_record() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = [0u8; 16];
    let n = child.stdout.as_mut().unwrap().read(&mut line).unwrap();
    let grandchild: u32 = String::from_utf8_lossy(&line[..n]).trim().parse().unwrap();
    let pid = child.id();
    let mut check = applied(0);
    read_status(
        &mut check,
        "NoNewPrivs:\t1\nSeccomp:\t0\nSeccomp_filters:\t0\n",
    );
    let mut recorded = None;
    let refused = finish(child, check, |check| {
        // Gone already when the record is written.
        assert!(!alive(pid));
        recorded = check;
        Ok(())
    })
    .unwrap_err();
    assert!(
        format!("{refused:#}").contains("stopped the agent"),
        "{refused:#}"
    );
    assert!(gone(grandchild), "what the agent started is still running");
    let failure = recorded.unwrap().failure.unwrap();
    assert!(failure.contains("Seccomp: 2"), "{failure}");
}

/// Up to two seconds for `path` to hold a line.
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !std::fs::read_to_string(path).is_ok_and(|s| s.ends_with('\n'))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The Lightweight tier's restriction with the whole root readable, or
/// `None`, saying so, where this kernel has no Landlock ABI 4.
fn restriction() -> Option<(RulesetCreated, Vec<BpfProgram>)> {
    let rules = crate::sandbox::landlock::Rules {
        read: vec!["/".to_owned()],
        write: vec![std::env::temp_dir().to_string_lossy().into_owned()],
        ..crate::sandbox::landlock::Rules::default()
    };
    let report = crate::sandbox::Report::default();
    let Ok(built) = super::super::restricted(&rules, report, Command::new("/bin/sh")) else {
        eprintln!("skipped: no Landlock ABI 4 here");
        return None;
    };
    built.restrict
}
