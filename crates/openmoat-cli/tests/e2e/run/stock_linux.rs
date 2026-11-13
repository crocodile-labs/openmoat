//! `openmoat run` on a stock Linux: Landlock and seccomp, no bubblewrap, so no
//! network namespace and no masks inside the grants. This is what a person
//! gets out of the box on Ubuntu, whose AppArmor restricts the unprivileged
//! user namespaces bubblewrap needs. A stock-Linux run sets
//! [`super::STOCK_LINUX`] on a machine without bubblewrap; elsewhere they
//! say so and stop, since the other Linux jobs install it.

use std::path::Path;
use std::process::Output;

use super::confined::ran;
use super::{installed_with_secret, run_sh};
use crate::common::{OK, Sandbox, USAGE, output, stderr, text};

/// False, saying so, outside a stock-Linux run.
fn stock() -> bool {
    let stock = super::stock_linux();
    if !stock {
        eprintln!("skipped: only a stock-Linux run runs the port-only path on purpose");
    }
    stock
}

/// `openmoat run <flags> -- /bin/sh -c true` in `project`.
fn run_with(sb: &Sandbox, project: &Path, flags: &[&str]) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .arg("run")
            .args(flags)
            .args(["--", "/bin/sh", "-c", "true"]),
        None,
    )
}

/// The command runs, sandboxed, and `openmoat run --no-isolate` says before
/// it starts that the network is restricted by port only.
#[test]
fn the_lightweight_tier_starts_and_says_the_network_is_restricted_by_port_only() {
    if !stock() {
        return;
    }
    let (sb, project) = installed_with_secret();
    let out = run_sh(&sb, &project, "echo started");
    assert!(ran(&out), "{}", text(&out));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stderr(&out).contains("restricted by port only"),
        "{}",
        text(&out)
    );
    // The key stays out of reach: Landlock grants the project, not the home.
    let out = run_sh(&sb, &project, "cat \"$HOME/.ssh/id_rsa\"");
    assert!(!text(&out).contains("FAKE-SSH-KEY"), "{}", text(&out));
    assert!(text(&out).contains("Permission denied"), "{}", text(&out));
    // `openmoat doctor` names the gap.
    let doctor = sb.moat(&["doctor"]);
    assert!(
        text(&doctor).contains("network restricted by port only"),
        "{}",
        text(&doctor)
    );
}

/// Without bubblewrap the default (the Isolated tier, ADR-080) cannot start:
/// `openmoat run` says why, writes that it started the Lightweight tier to
/// the audit log, and starts it, as it did before the default changed.
/// `doctor` says the same before any run.
#[test]
fn the_default_warns_records_and_starts_the_lightweight_tier() {
    if !stock() {
        return;
    }
    let (sb, project) = installed_with_secret();
    let out = run_with(&sb, &project, &[]);
    assert!(ran(&out), "{}", text(&out));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = stderr(&out);
    for expected in [
        "the Isolated tier, `openmoat run`'s default on Linux, cannot start here",
        "bubblewrap is not installed",
        "restricted by port only",
        "granted entry by entry",
    ] {
        assert!(shown.contains(expected), "{expected}: {}", text(&out));
    }
    assert_eq!(
        super::default_tier::tier_rows(&sb),
        ["run-isolation-unavailable"]
    );
    // The boundary row names both downgrades, forced, with bubblewrap's
    // absence as the reason, and the check of the agent's start (ADR-089);
    // `--print-boundary` says the same before any start.
    let rows = super::boundary::boundary_rows(&sb);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let printed = super::boundary::print_boundary(&sb, &project, &[]);
    assert_eq!(printed.status.code(), Some(OK), "{}", text(&printed));
    let plan: serde_json::Value = serde_json::from_slice(&printed.stdout).unwrap();
    for record in [&rows[0], &plan] {
        assert_eq!(record["requested"], "default", "{record}");
        assert_eq!(record["tier"], "lightweight", "{record}");
        assert_eq!(record["network"]["mode"], "port_only", "{record}");
        let downgrades = record["downgrades"].as_array().unwrap();
        assert_eq!(downgrades.len(), 2, "{record}");
        for (downgrade, what) in downgrades.iter().zip(["tier", "network"]) {
            assert_eq!(downgrade["what"], what, "{record}");
            assert_eq!(downgrade["chosen"], false, "{record}");
            let why = downgrade["why"].as_str().unwrap();
            assert!(why.contains("bubblewrap is not installed"), "{record}");
        }
    }
    super::boundary::assert_proc_checked(&rows[0]);
    let doctor = sb.moat(&["doctor"]);
    assert!(
        text(&doctor).contains("cannot start the Isolated tier here"),
        "{}",
        text(&doctor)
    );
}

/// What needs a network namespace or masks refuses to start instead of
/// starting with less: `--netns=require` exits 64, `--isolate` names
/// bubblewrap, and a `--write` grant outside the project, which Landlock
/// cannot keep the hook settings in, is refused.
#[test]
fn what_needs_a_namespace_is_refused_not_weakened() {
    if !stock() {
        return;
    }
    let (sb, project) = installed_with_secret();
    let out = run_with(&sb, &project, &["--netns=require"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("--netns=require"), "{}", text(&out));

    let out = run_with(&sb, &project, &["--isolate"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(stderr(&out).contains("bubblewrap"), "{}", text(&out));

    let outside = sb.home.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let outside = outside.to_string_lossy().into_owned();
    let out = run_with(&sb, &project, &["--write", &outside]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        stderr(&out).contains("Install bubblewrap"),
        "{}",
        text(&out)
    );
}
