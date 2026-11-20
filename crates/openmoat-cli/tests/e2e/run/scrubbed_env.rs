//! The scrubbed environment (ADR-105): with `sandbox.env: scrubbed` or
//! `--scrub-env`, what `openmoat run` starts gets only the allowlist of the
//! environment it was started from, so a credential planted there is not in
//! the program's environment, nor in that of any process it starts. A
//! brokered secret's variable holds its placeholder, never the value.
//! `--print-boundary` names what passes, names only.

use super::boundary::print_boundary;
use super::confined::ran;
use super::strict::require;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags};
use crate::common::{OK, Sandbox, json as parse, stderr, text};

/// A made-up cloud credential, built at run time so it never looks real.
fn planted() -> String {
    format!("fake-planted-{}", "4d1c9e")
}

/// Prints the credential from the program, from a child shell and from the
/// child's whole environment, and a toolchain location that must pass.
const SCRIPT: &str = "echo \"secret=[$AWS_SECRET_ACCESS_KEY]\"; \
     /bin/sh -c 'echo \"child=[$AWS_SECRET_ACCESS_KEY]\"; env' ; \
     echo \"java=[$JAVA_HOME]\"";

/// `sb` with `sandbox.env: scrubbed` in the user policy, re-pinned as a
/// person would.
fn scrubbed(sb: &Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let policy = std::fs::read_to_string(&path).unwrap();
    let edited = policy.replacen("\nsandbox:\n", "\nsandbox:\n  env: scrubbed\n", 1);
    assert_ne!(
        policy, edited,
        "the default policy has a `sandbox:` section"
    );
    std::fs::write(&path, edited).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

/// The value is nowhere in what the program or its child printed, and the
/// toolchain location reached both.
fn assert_withheld(shown: &str, value: &str) {
    assert!(shown.contains("secret=[]"), "{shown}");
    assert!(shown.contains("child=[]"), "{shown}");
    assert!(shown.contains("java=[/opt/jdk]"), "{shown}");
    assert!(!shown.contains(value), "{shown}");
}

/// The attack: a cloud credential in the shell `openmoat run` starts from, and
/// a program that reads its environment, or starts one that prints all of it.
// protection: credentials every linux,macos
#[test]
fn a_scrubbed_policy_keeps_a_planted_credential_from_the_program_and_its_children() {
    let (sb, project) = installed_with_secret();
    scrubbed(&sb);
    let value = planted();
    let out = run_sh_flags(
        &sb,
        &project,
        &[LIGHTWEIGHT],
        SCRIPT,
        &[("AWS_SECRET_ACCESS_KEY", &value), ("JAVA_HOME", "/opt/jdk")],
    );
    if !ran(&out) {
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_withheld(&text(&out), &value);
    assert!(
        stderr(&out).contains("withheld from the agent"),
        "{}",
        text(&out)
    );
}

/// `--scrub-env` does the same for one run, with no policy setting.
#[test]
fn the_flag_scrubs_one_run() {
    let (sb, project) = installed_with_secret();
    let value = planted();
    let out = run_sh_flags(
        &sb,
        &project,
        &[LIGHTWEIGHT, "--scrub-env"],
        SCRIPT,
        &[("AWS_SECRET_ACCESS_KEY", &value), ("JAVA_HOME", "/opt/jdk")],
    );
    if !ran(&out) {
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_withheld(&text(&out), &value);
}

/// On Linux the program's own `/proc/self/environ` does not hold it either:
/// the variable is gone from the process, not hidden from one way of asking.
#[cfg(target_os = "linux")]
#[test]
fn the_process_environment_itself_does_not_hold_it() {
    let (sb, project) = installed_with_secret();
    let value = planted();
    let out = run_sh_flags(
        &sb,
        &project,
        &[LIGHTWEIGHT, "--scrub-env"],
        "tr '\\0' '\\n' < /proc/self/environ 2>&1; echo done",
        &[("AWS_SECRET_ACCESS_KEY", &value)],
    );
    if !ran(&out) {
        return;
    }
    assert!(text(&out).contains("done"), "{}", text(&out));
    assert!(!text(&out).contains(&value), "{}", text(&out));
}

/// A brokered secret's variable holds the placeholder, scrubbed or not, and
/// the value never reaches the program.
#[test]
fn a_brokered_variable_holds_its_placeholder() {
    let (sb, project) = installed_with_secret();
    require(
        &sb,
        "secrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: { env: MOAT_E2E_BROKERED }\n",
    );
    let value = planted();
    for flags in [&[LIGHTWEIGHT][..], &[LIGHTWEIGHT, "--scrub-env"][..]] {
        let out = run_sh_flags(
            &sb,
            &project,
            flags,
            "echo \"held=[$MOAT_E2E_BROKERED]\"",
            &[("MOAT_E2E_BROKERED", &value)],
        );
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        assert!(
            shown.contains("held=[moat-secret:gh:placeholder]"),
            "{shown}"
        );
        assert!(!shown.contains(&value), "{shown}");
    }
}

/// `--print-boundary` says the environment is scrubbed and why, names what
/// passes and what is withheld, never a value, and starts nothing.
#[test]
fn print_boundary_names_what_passes() {
    let (sb, project) = installed_with_secret();
    let plain = print_boundary(&sb, &project, &[LIGHTWEIGHT]);
    if !plain.status.success() {
        eprintln!("skipped: {}", text(&plain));
        return;
    }
    let environment = parse(&plain)["environment"].clone();
    assert_eq!(environment["scrubbed"], false, "{environment}");
    assert!(environment["why"].as_str().unwrap().contains("default"));
    scrubbed(&sb);
    let value = planted();
    let out = crate::common::output(
        sb.command()
            .current_dir(&project)
            .env("AWS_SECRET_ACCESS_KEY", &value)
            .args(["run", LIGHTWEIGHT, "--print-boundary", "--format", "json"])
            .args(["--", "/bin/sh", "-c", "touch started"]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let environment = parse(&out)["environment"].clone();
    assert_eq!(environment["scrubbed"], true, "{environment}");
    assert!(
        environment["why"]
            .as_str()
            .unwrap()
            .contains("sandbox.env: scrubbed")
    );
    let has = |list: &str, name: &str| {
        environment[list]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == name)
    };
    assert!(has("withheld", "AWS_SECRET_ACCESS_KEY"), "{environment}");
    assert!(has("passed", "PATH"), "{environment}");
    assert!(!text(&out).contains(&value), "{}", text(&out));
    assert!(!project.join("started").exists(), "the agent started");
    let shown = crate::common::output(
        sb.command()
            .current_dir(&project)
            .args(["run", LIGHTWEIGHT, "--print-boundary"])
            .args(["--", "/bin/sh", "-c", "true"]),
        None,
    );
    assert!(
        text(&shown).contains("environment: scrubbed"),
        "{}",
        text(&shown)
    );
}
