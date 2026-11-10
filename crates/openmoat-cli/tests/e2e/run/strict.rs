//! `require.run: full-boundary` (ADR-077): `openmoat run` starts only with its
//! whole boundary, and no flag lowers that. CI's `stock linux` job has no
//! network namespace, so there it refuses; every other job starts.

use std::path::Path;
use std::process::Output;

use serde_json::Value;

use super::confined::ran;
use super::{installed_with_secret, run_sh, stock_linux};
use crate::common::{OK, Sandbox, USAGE, json as parse, output, stderr, text};

pub(super) const STRICT: &str = "require:\n  run: full-boundary\n";

/// `sb` with `section` added to the user policy and re-pinned as a person would.
pub(super) fn require(sb: &Sandbox, section: &str) {
    let path = sb.home.join(".moat/policy.yaml");
    let mut policy = std::fs::read_to_string(&path).unwrap();
    policy.push('\n');
    policy.push_str(section);
    std::fs::write(&path, policy).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

/// `openmoat run <flags> -- /bin/sh -c 'echo started'` in `project`.
fn run_with(sb: &Sandbox, project: &Path, flags: &[&str]) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .arg("run")
            .args(flags)
            .args(["--", "/bin/sh", "-c", "echo started"]),
        None,
    )
}

fn boundary(sb: &Sandbox) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    parse(&out)["run_boundary"].clone()
}

#[test]
fn it_starts_with_the_full_boundary_and_refuses_without_one() {
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    let out = run_sh(&sb, &project, "echo started");
    if !ran(&out) {
        return;
    }
    if stock_linux() {
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(stderr(&out).contains("your policy"), "{}", text(&out));
        assert!(stderr(&out).contains("bubblewrap"), "{}", text(&out));
        assert!(!text(&out).contains("started\n"), "{}", text(&out));
    } else {
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(text(&out).contains("started\n"), "{}", text(&out));
    }
}

/// The default and an explicit `--netns=auto` both mean "take what you can
/// get", which a policy's requirement overrides.
#[test]
fn no_flag_lowers_it() {
    if !stock_linux() {
        eprintln!("skipped: only CI's `stock linux` job has no network namespace");
        return;
    }
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    let out = run_with(&sb, &project, &["--netns=auto"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("full boundary"), "{}", text(&out));
    assert!(!text(&out).contains("started\n"), "{}", text(&out));
}

/// A repository can ask for it without being trusted, since it only tightens.
#[test]
fn a_repository_policy_can_require_it() {
    let (sb, project) = installed_with_secret();
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(
        project.join(".moat/policy.yaml"),
        format!("version: 1\n{STRICT}"),
    )
    .unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .args(["status", "--format", "json"]),
        None,
    );
    assert_eq!(parse(&out)["run_boundary"]["by"], "the repository policy");
}

#[test]
fn status_reports_it_only_when_a_policy_asks() {
    let (sb, _project) = installed_with_secret();
    assert_eq!(boundary(&sb), Value::Null);
    require(&sb, STRICT);
    let state = boundary(&sb);
    assert_eq!(state["by"], "your policy");
    assert_eq!(state["met"], Value::Bool(!stock_linux()), "{state}");
}
