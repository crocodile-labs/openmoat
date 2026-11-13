//! The run's boundary record (ADR-089): `--print-boundary` reports the tier
//! a run would start and starts nothing; every run writes one `run-boundary`
//! row; on Linux the row carries the check of the agent's start, read from
//! its `/proc/<pid>/status` (`NoNewPrivs: 1`, `Seccomp: 2`), whichever
//! process started it (this one, or `openmoat isolated` inside bubblewrap).

use std::path::Path;
use std::process::Output;

use serde_json::Value;

use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags};
use crate::common::{OK, Sandbox, output, stderr, text};

/// The records of the run's `run-boundary` rows, in order.
pub(super) fn boundary_rows(sb: &Sandbox) -> Vec<Value> {
    let store = openmoat_audit::Store::open_read_only(&sb.home.join(".moat/audit.db")).unwrap();
    store
        .since(0, Some("moat-run"))
        .unwrap()
        .into_iter()
        .filter(|event| event.tool == "boundary")
        .map(|event| {
            assert_eq!(event.rules, ["run-boundary"]);
            serde_json::from_str(&event.reasons[0]).unwrap()
        })
        .collect()
}

/// `openmoat run <flags> --print-boundary --format json -- /bin/sh -c <script>`.
pub(super) fn print_boundary(sb: &Sandbox, project: &Path, flags: &[&str]) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .arg("run")
            .args(flags)
            .args(["--print-boundary", "--format", "json"])
            .args(["--", "/bin/sh", "-c", "touch started"]),
        None,
    )
}

/// The restriction `name` of `record`.
pub(super) fn restriction<'a>(record: &'a Value, name: &str) -> &'a Value {
    record["restrictions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("no {name}: {record}"))
}

/// The plan names the tier asked for and the one that would start, and
/// nothing starts: no file, no row.
#[test]
fn print_boundary_reports_the_tier_and_starts_nothing() {
    let (sb, project) = installed_with_secret();
    let out = print_boundary(&sb, &project, &[LIGHTWEIGHT]);
    if stderr(&out).contains("needs macOS 13") {
        eprintln!("skipped: `openmoat run` refuses on this macOS");
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let record: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(record["version"], 1, "{record}");
    assert_eq!(record["requested"], "lightweight", "{record}");
    assert_eq!(record["tier"], "lightweight", "{record}");
    assert!(record["launch"].is_null(), "{record}");
    assert!(!project.join("started").exists(), "the agent started");
    assert_eq!(boundary_rows(&sb), Vec::<Value>::new());
    if cfg!(target_os = "linux") {
        // `--no-isolate` gives up the Isolated tier on purpose.
        assert_eq!(record["downgrades"][0]["what"], "tier", "{record}");
        assert_eq!(record["downgrades"][0]["chosen"], true, "{record}");
        assert_eq!(restriction(&record, "seccomp")["configured"], true);
    } else {
        assert_eq!(record["downgrades"], Value::Array(Vec::new()), "{record}");
        assert_eq!(record["network"]["mode"], "profile", "{record}");
        assert_eq!(restriction(&record, "seatbelt")["configured"], true);
    }
    // The text form, for a person.
    let out = output(
        sb.command().current_dir(&project).args([
            "run",
            LIGHTWEIGHT,
            "--print-boundary",
            "--",
            "/bin/sh",
        ]),
        None,
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("boundary: Lightweight tier"),
        "{}",
        text(&out)
    );
}

/// `--format` belongs to `--print-boundary` alone.
#[test]
fn format_without_print_boundary_is_a_usage_error() {
    let (sb, project) = installed_with_secret();
    let out = output(
        sb.command()
            .current_dir(&project)
            .args(["run", "--format", "json", "--", "/bin/sh"]),
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(crate::common::USAGE),
        "{}",
        text(&out)
    );
}

/// One row per run, written once the agent started. On Linux the
/// Lightweight tier's own thread started the agent and read its
/// `/proc/<pid>/status`: both restrictions are tested there, the ruleset
/// is enforced, and the ABI is `restrict_self`'s. macOS has no `/proc`: its
/// row names Seatbelt, configured, with no check.
#[test]
fn every_run_writes_one_boundary_row_with_the_launch_check() {
    let (sb, project) = installed_with_secret();
    let out = run_sh_flags(&sb, &project, &[LIGHTWEIGHT], "echo started", &[]);
    if !ran(&out) || stderr(&out).contains("needs macOS 13") {
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let rows = boundary_rows(&sb);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let record = &rows[0];
    assert_eq!(record["tier"], "lightweight", "{record}");
    assert!(record["network"]["proxy_port"].is_u64(), "{record}");
    if cfg!(target_os = "linux") {
        assert_proc_checked(record);
    } else {
        assert!(record["launch"].is_null(), "{record}");
        assert_eq!(restriction(record, "seatbelt")["tested"], Value::Null);
    }
}

/// What the check after the start must show on Linux.
pub(super) fn assert_proc_checked(record: &Value) {
    let launch = &record["launch"];
    assert_eq!(launch["proc_no_new_privs"], true, "{record}");
    assert_eq!(launch["proc_seccomp_filter"], true, "{record}");
    assert_eq!(launch["seccomp_filters"], 2, "{record}");
    assert!(launch["failure"].is_null(), "{record}");
    assert_ne!(record["landlock"]["enforcement"], "none", "{record}");
    assert!(record["landlock"]["abi"].as_u64().unwrap() >= 4, "{record}");
    for name in ["seccomp", "no_new_privs"] {
        assert_eq!(restriction(record, name)["applied"], true, "{record}");
        assert_eq!(restriction(record, name)["tested"], true, "{record}");
    }
    assert_eq!(restriction(record, "landlock_filesystem")["applied"], true);
}

/// Under the default on Linux (the Isolated tier where bubblewrap works),
/// `openmoat isolated` checks the agent inside bubblewrap and reports it.
#[cfg(target_os = "linux")]
#[test]
fn the_isolated_tier_reports_its_check_from_inside() {
    if super::stock_linux() {
        eprintln!("skipped: a stock-Linux run has no bubblewrap (stock_linux.rs)");
        return;
    }
    let (sb, project) = installed_with_secret();
    let out = run_sh_flags(&sb, &project, &["--isolate"], "echo started", &[]);
    if !ran(&out) || !super::confined::isolated(&out) {
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let rows = boundary_rows(&sb);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let record = &rows[0];
    assert_eq!(record["tier"], "isolated", "{record}");
    assert_eq!(record["downgrades"], Value::Array(Vec::new()), "{record}");
    assert_eq!(record["launch"]["in_bubblewrap"], true, "{record}");
    assert_proc_checked(record);
    assert_eq!(restriction(record, "isolated_view")["applied"], true);
    let printed = print_boundary(&sb, &project, &[]);
    let plan: Value = serde_json::from_slice(&printed.stdout).unwrap();
    assert_eq!(plan["tier"], "isolated", "{plan}");
}

/// A run that cannot put its start on record stops the agent and what it
/// started, in every Lightweight path (the network namespace, where there is
/// no PID namespace to end it with bubblewrap, and the port-only one): exit
/// 64, and both processes are gone. The debug-only switch fails the row
/// write after the script had time to start its background process.
#[cfg(target_os = "linux")]
#[test]
fn a_run_that_cannot_record_its_start_stops_the_agent() {
    let (sb, project) = installed_with_secret();
    // A folder of its own: without a namespace nothing is created at the
    // project's top (ADR-090).
    std::fs::create_dir_all(project.join("work")).unwrap();
    let pids = project.join("work/pids");
    let script = "sleep 30 & echo $$ $! > work/pids; wait";
    let out = run_sh_flags(
        &sb,
        &project,
        &[LIGHTWEIGHT],
        script,
        &[("MOAT_TEST_FAIL_BOUNDARY_ROW_MS", "1500")],
    );
    if !ran(&out) {
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(crate::common::USAGE),
        "{}",
        text(&out)
    );
    assert!(
        stderr(&out).contains("boundary row failed"),
        "{}",
        text(&out)
    );
    let written = std::fs::read_to_string(&pids).unwrap_or_default();
    let started: Vec<&str> = written.split_whitespace().collect();
    assert_eq!(started.len(), 2, "the script did not start: {}", text(&out));
    for pid in started {
        let proc = std::path::PathBuf::from(format!("/proc/{pid}/stat"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let running = || {
            std::fs::read_to_string(&proc).is_ok_and(|stat| {
                !stat
                    .rsplit(')')
                    .next()
                    .unwrap_or("")
                    .trim_start()
                    .starts_with('Z')
            })
        };
        while running() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!running(), "process {pid} still runs: {}", text(&out));
    }
}
