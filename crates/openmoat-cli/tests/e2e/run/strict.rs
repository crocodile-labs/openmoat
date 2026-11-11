//! `require.run: full-boundary` (ADR-077): `openmoat run` starts only with its
//! whole boundary, and no flag lowers that. CI's `stock linux` job has no
//! network namespace, so there it refuses; every other job starts.

use std::path::Path;
use std::process::Output;

use serde_json::Value;

use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags, stock_linux};
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

/// `sb` with `name` in the `sandbox:` section the default policy already has,
/// re-pinned as a person would.
fn allow_env(sb: &Sandbox, name: &str) {
    let path = sb.home.join(".moat/policy.yaml");
    let policy = std::fs::read_to_string(&path).unwrap();
    let edited = policy.replacen(
        "\nsandbox:\n",
        &format!("\nsandbox:\n  env_allow: [{name}]\n"),
        1,
    );
    assert_ne!(
        policy, edited,
        "the default policy has a `sandbox:` section"
    );
    std::fs::write(&path, edited).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

fn boundary(sb: &Sandbox) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    parse(&out)["run_boundary"].clone()
}

#[test]
fn it_starts_with_the_full_boundary_and_refuses_without_one() {
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    // The default tier: on Linux the Isolated one, which the requirement asks for.
    let out = run_with(&sb, &project, &[]);
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

/// On Linux the full boundary is the Isolated tier (ADR-080), so the flag
/// that starts the Lightweight one is refused, before anything starts and
/// whether or not bubblewrap works. macOS has no Isolated tier yet, so there
/// the flag changes nothing and the run starts.
#[test]
fn no_isolate_does_not_lower_it() {
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    let out = run_with(&sb, &project, &[LIGHTWEIGHT]);
    if cfg!(target_os = "linux") {
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(stderr(&out).contains("your policy"), "{}", text(&out));
        assert!(stderr(&out).contains("--no-isolate"), "{}", text(&out));
        assert!(!text(&out).contains("started\n"), "{}", text(&out));
        assert_eq!(super::default_tier::tier_rows(&sb), [] as [String; 0]);
    } else if ran(&out) {
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(text(&out).contains("started\n"), "{}", text(&out));
    }
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

/// The attack: a cloud credential in the environment `openmoat run` was
/// started from. Under the requirement the command does not get it; a
/// variable the person added does, and the run names what it withheld.
#[test]
fn a_planted_credential_does_not_reach_a_command_and_an_added_variable_does() {
    if stock_linux() {
        return;
    }
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    let out = output(
        sb.command()
            .current_dir(&project)
            .env("AWS_SECRET_ACCESS_KEY", "fake-planted-value")
            .env("MY_BENIGN_VAR", "benign-value")
            .args([
                "run",
                "--verbose",
                "--env",
                "MY_BENIGN_VAR",
                "--",
                "/bin/sh",
                "-c",
                "echo \"secret=[$AWS_SECRET_ACCESS_KEY]\"; echo \"benign=[$MY_BENIGN_VAR]\"",
            ]),
        None,
    );
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(shown.contains("secret=[]"), "{shown}");
    assert!(shown.contains("benign=[benign-value]"), "{shown}");
    assert!(stderr(&out).contains("AWS_SECRET_ACCESS_KEY"), "{shown}");
    assert!(!shown.contains("fake-planted-value"), "{shown}");
}

/// A name in the person's policy reaches the command without a flag.
#[test]
fn a_name_in_the_policy_is_passed_on() {
    if stock_linux() {
        return;
    }
    let (sb, project) = installed_with_secret();
    require(&sb, STRICT);
    allow_env(&sb, "MY_POLICY_VAR");
    let out = run_sh_flags(
        &sb,
        &project,
        &[],
        "echo \"var=[$MY_POLICY_VAR]\"",
        &[("MY_POLICY_VAR", "from-policy")],
    );
    if !ran(&out) {
        return;
    }
    assert!(text(&out).contains("var=[from-policy]"), "{}", text(&out));
}

/// Without the requirement everything still reaches the command, as before,
/// and one line names what looks like a credential, never its value.
#[test]
fn without_the_requirement_nothing_is_withheld_and_one_line_warns() {
    let (sb, project) = installed_with_secret();
    let out = super::run_sh_with(
        &sb,
        &project,
        "echo \"secret=[$AWS_SECRET_ACCESS_KEY]\"",
        &[("AWS_SECRET_ACCESS_KEY", "fake-planted-value")],
    );
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(shown.contains("secret=[fake-planted-value]"), "{shown}");
    assert!(stderr(&out).contains("AWS_SECRET_ACCESS_KEY"), "{shown}");
    assert!(stderr(&out).contains("look like credentials"), "{shown}");
    assert!(!stderr(&out).contains("fake-planted-value"), "{shown}");
}

/// `doctor` names what is withheld and no value.
#[test]
fn doctor_names_what_is_withheld() {
    let (sb, _project) = installed_with_secret();
    require(&sb, STRICT);
    let out = output(
        sb.command()
            .env("AWS_SECRET_ACCESS_KEY", "fake-planted-value")
            .args(["doctor"]),
        None,
    );
    assert!(
        text(&out).contains("AWS_SECRET_ACCESS_KEY"),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("fake-planted-value"), "{}", text(&out));
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
