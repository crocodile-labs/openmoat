//! `openmoat run` on a stock Linux: Landlock and seccomp, no bubblewrap, so no
//! network namespace and no masks inside the grants. This is what a person
//! gets out of the box on Ubuntu, whose AppArmor restricts the unprivileged
//! user namespaces bubblewrap needs. CI's `stock linux` job runs these with
//! [`super::STOCK_LINUX`] set on a runner without bubblewrap; elsewhere they
//! say so and stop, since the other Linux jobs install it.

use std::path::Path;
use std::process::Output;

use super::confined::ran;
use super::{installed_with_secret, run_sh};
use crate::common::{OK, Sandbox, USAGE, output, stderr, text};

/// False, saying so, outside CI's `stock linux` job.
fn stock() -> bool {
    let stock = super::stock_linux();
    if !stock {
        eprintln!("skipped: only CI's `stock linux` job runs the port-only path on purpose");
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

/// The command runs, sandboxed, and `openmoat run` says before it starts
/// that the network is restricted by port only.
#[test]
fn a_plain_run_starts_and_says_the_network_is_restricted_by_port_only() {
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
