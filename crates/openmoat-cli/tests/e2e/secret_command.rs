//! `command` secret sources (ADR-087), end to end: the proxy runs no program
//! the agent could change, and none from a folder any user can write.

use std::fs;
use std::path::Path;

use crate::common::{OK, Sandbox, USAGE, stderr, text};

/// An installed home outside `/tmp` (no command source may be there).
fn home() -> Sandbox {
    Sandbox::installed_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[])
}

/// `sb`'s policy with secret `cloud` from `run`.
fn broker_from(sb: &Sandbox, run: &str) {
    let policy = sb.home.join(".moat/policy.yaml");
    let text = fs::read_to_string(&policy).unwrap();
    fs::write(
        &policy,
        format!(
            "{text}\nsecrets:\n  - id: cloud\n    host: api.github.com\n    header: \
             Authorization\n    source:\n      command: {{ run: [{run}], lifetime: 15m }}\n"
        ),
    )
    .unwrap();
}

/// Attack: the policy names a program in the person's home that no deny rule
/// keeps from the agent, which could replace it and so run as the person
/// outside every sandbox. The proxy refuses to start and never runs it; the
/// lint says why.
#[test]
fn a_program_the_agent_could_change_is_never_run() {
    let sb = home();
    let program = sb.home.join("bin/token");
    let marker = sb.home.join("ran");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        format!(
            "#!/bin/sh\ntouch '{}'\necho fake-token-0f9e\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    }
    broker_from(&sb, &format!("'{}', token", program.display()));
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));

    let out = sb.moat(&["proxy", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let err = stderr(&out);
    assert!(err.contains("reading secret `cloud`"), "{err}");
    assert!(err.contains("could be changed by the agent"), "{err}");
    assert!(!err.contains("fake-token"), "{err}");
    assert!(!marker.exists(), "the program ran");

    let lint = sb.moat(&["policy", "lint"]);
    assert!(
        text(&lint).contains("no deny fs.write rule covers"),
        "{}",
        text(&lint)
    );
}

/// Attack: a program under `/tmp`, where any user can put a file, does not
/// load, whatever rule covers it.
#[test]
fn a_program_under_tmp_does_not_load() {
    let sb = home();
    broker_from(&sb, "/tmp/token");
    let out = sb.moat(&["policy", "lint"]);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    let all = text(&out);
    assert!(
        all.contains("secrets.cloud") && all.contains("under /tmp/"),
        "{all}"
    );
}
