//! `openmoat proxy ca init` and `openmoat secret add --tls-terminate`, end to end
//! (ADR-043): person-only, the question before anything is written, the CA's
//! files and their pins, and the CA key kept from the agent.

use std::fs;

use crate::common::{OK, Sandbox, USAGE, output, text, verdict_and_reason};

fn as_person(sb: &Sandbox, args: &[&str], answers: &str) -> std::process::Output {
    let mut cmd = sb.command();
    cmd.args(args).env("MOAT_ASSUME_TTY", "1");
    output(&mut cmd, Some(answers))
}

fn ca_files(sb: &Sandbox) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = sb.home.join(".moat/proxy-ca");
    (dir.join("ca.pem"), dir.join("key.pem"))
}

/// A CA file as the lock and `doctor` spell it: under `proxy-ca/` with the OS
/// separator.
fn ca_file(name: &str) -> String {
    format!("proxy-ca{}{name}", std::path::MAIN_SEPARATOR)
}

#[test]
fn ca_init_is_for_a_person_with_a_terminated_secret() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["proxy", "ca", "init"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("must be run by a person in a terminal"),
        "{}",
        text(&out)
    );
    let out = as_person(&sb, &["proxy", "ca", "init"], "y\n");
    assert_ne!(out.status.code(), Some(OK));
    assert!(
        text(&out).contains("nothing for a CA to cover"),
        "{}",
        text(&out)
    );
    assert!(!ca_files(&sb).0.exists());
}

#[test]
fn allow_rules_need_tls_termination_on_the_command_line() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = as_person(
        &sb,
        &["secret", "add", "gh", "--allow", "GET /repos/**"],
        "y\n",
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
}

#[test]
fn a_terminated_secret_gets_a_pinned_ca_that_covers_its_host() {
    let sb = Sandbox::installed(&[".claude"]);
    let args = [
        "secret",
        "add",
        "gh",
        "--tls-terminate",
        "--allow",
        "GET /repos/**",
    ];
    // Yes to the secret, no to the CA: the policy changes, no CA is made.
    let out = as_person(&sb, &args, "y\nn\n");
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(
        shown.contains("+    tls: terminate") && shown.contains("GET /repos/**"),
        "{shown}"
    );
    assert!(
        shown.contains("decrypts HTTPS to api.github.com"),
        "{shown}"
    );
    assert!(shown.contains("Only these requests get it"), "{shown}");
    assert!(shown.contains("It can sign for those hosts"), "{shown}");
    assert!(shown.contains("no CA was made"), "{shown}");
    let (cert, key) = ca_files(&sb);
    assert!(!cert.exists() && !key.exists());

    let out = as_person(&sb, &["proxy", "ca", "init"], "y\n");
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(
        shown.contains("proxy CA made for api.github.com"),
        "{shown}"
    );
    let pem = fs::read_to_string(&cert).unwrap();
    assert!(
        pem.contains("only for: api.github.com") && pem.contains("BEGIN CERTIFICATE"),
        "{pem}"
    );
    let first_key = fs::read_to_string(&key).unwrap();
    assert!(first_key.contains("BEGIN PRIVATE KEY"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let lock = fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap();
    // The lock is JSON, where a Windows separator is written escaped.
    assert!(
        lock.contains("proxy-ca") && lock.contains("ca.pem") && lock.contains("key.pem"),
        "{lock}"
    );
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));

    // A changed key is drift, which only a person accepts.
    fs::write(&key, "-----BEGIN PRIVATE KEY-----\nplanted\n").unwrap();
    let doctor = sb.moat(&["doctor"]);
    assert!(
        text(&doctor).contains(&ca_file("key.pem")),
        "{}",
        text(&doctor)
    );
    fs::write(&key, &first_key).unwrap();

    // Again: asks, says what it replaces, and rotates the key.
    let out = as_person(&sb, &["proxy", "ca", "init"], "n\n");
    assert!(
        text(&out).contains("It replaces the CA valid until"),
        "{}",
        text(&out)
    );
    assert_eq!(
        fs::read_to_string(&key).unwrap(),
        first_key,
        "nothing written on no"
    );
    let out = as_person(&sb, &["proxy", "ca", "init"], "y\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_ne!(fs::read_to_string(&key).unwrap(), first_key, "a new key");
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
}

#[test]
fn the_agent_cannot_read_the_ca() {
    let sb = Sandbox::installed(&[".claude"]);
    for file in ["key.pem", "ca.pem"] {
        let path = sb.home.join(".moat/proxy-ca").join(file);
        let read = serde_json::json!({
            "session_id": "s-ca", "cwd": sb.project().to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": path.to_string_lossy()},
            "tool_use_id": "t1"
        })
        .to_string();
        let (verdict, reason) = verdict_and_reason(&sb.guard("claude-code", &read));
        assert_eq!(verdict, "deny", "{file}: {reason}");
        assert!(reason.contains("kernel-self"), "{reason}");
        // On Windows the shell behind `Bash` may be PowerShell or `cmd`, and a
        // `C:\…` path is not a POSIX word: OpenMoat leaves that to the host.
        if !cfg!(windows) {
            let (verdict, _) = sb.guard_bash(
                "s-ca",
                &sb.project(),
                &format!("cat {}", path.to_string_lossy()),
            );
            assert_eq!(verdict, "deny", "{file}");
        }
    }
}

/// Without a pinned CA that covers the host, `openmoat run` stops before the
/// agent starts, and says what to do.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn run_refuses_a_terminated_secret_without_a_ca() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = as_person(&sb, &["secret", "add", "gh", "--tls-terminate"], "y\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let mut cmd = sb.command();
    cmd.current_dir(sb.project())
        .env("GITHUB_TOKEN", "fake-run-token-1d2c")
        .args(["run", "--", "/bin/sh", "-c", "echo ran"]);
    let out = output(&mut cmd, None);
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(USAGE), "{shown}");
    assert!(
        shown.contains("no pinned proxy CA yet") && shown.contains("openmoat proxy ca init"),
        "{shown}"
    );
    assert!(!shown.contains("ran\n"), "the agent never started: {shown}");
}
