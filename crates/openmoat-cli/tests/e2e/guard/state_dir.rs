//! The state directory a hook's command line names (ADR-071): `init` writes
//! `--home`, the guard decides with it, and a `MOAT_HOME` naming another
//! directory is refused.

use serde_json::Value;

use crate::common::{Sandbox, hook_output as decision, host_fixture, stderr, stdout};
use crate::hosts::{dir_of, hook_file};
use openmoat_hosts::Host;

/// The parsed `~/.claude/settings.json`.
fn settings(sb: &Sandbox) -> Value {
    let text = std::fs::read_to_string(hook_file(sb, Host::ClaudeCode)).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The hook's command line names the state directory (ADR-071): the guard
/// decides with it whatever the environment says, and refuses a `MOAT_HOME`
/// that names another one rather than reading that directory's policy.
#[test]
fn the_hooks_state_directory_wins_and_another_moat_home_is_refused() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let payload = host_fixture(Host::ClaudeCode, "read.json");
    let homed = sb.guard_homed(Host::ClaudeCode.id(), &payload);
    assert_eq!(homed.status.code(), Some(0), "{}", stderr(&homed));

    // The same directory in the variable is fine.
    let word = sb.home_word();
    let args = [
        "guard",
        "--host",
        Host::ClaudeCode.id(),
        "--home",
        word.as_str(),
    ];
    let same = crate::common::output(
        sb.command()
            .args(args)
            .env("MOAT_HOME", sb.home.join(".moat")),
        Some(&payload),
    );
    assert_eq!(same.status.code(), Some(0), "{}", stderr(&same));

    // Another state directory, with a policy that allows everything, is not
    // where the guard looks: it denies, and says which variable it refused.
    let other = sb.home.join("elsewhere");
    std::fs::create_dir_all(&other).unwrap();
    let refused = crate::common::output(
        sb.command().args(args).env("MOAT_HOME", &other),
        Some(&payload),
    );
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert_eq!(decision(&refused)["permissionDecision"], "deny");
    assert!(
        stderr(&refused).contains("MOAT_HOME"),
        "{}",
        stderr(&refused)
    );
    assert!(
        std::fs::read_dir(&other).unwrap().next().is_none(),
        "nothing is written to the other directory"
    );

    // A word `init` never writes is refused too.
    let bad = sb.moat_stdin(
        &[
            "guard",
            "--host",
            Host::ClaudeCode.id(),
            "--home",
            "relative/.moat",
        ],
        &payload,
    );
    assert_eq!(bad.status.code(), Some(2), "{}", stderr(&bad));
}

/// A hook in the form of releases before ADR-071 still decides, and `status`
/// and `doctor` say it is out of date until `init` rewrites it.
#[test]
fn a_hook_without_the_state_directory_is_flagged_until_init() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let path = hook_file(&sb, Host::ClaudeCode);
    let mut root = settings(&sb);
    for entries in root["hooks"].as_object_mut().unwrap().values_mut() {
        for entry in entries.as_array_mut().unwrap() {
            let args = entry["hooks"][0]["args"].as_array_mut().unwrap();
            assert_eq!(args.len(), 5, "{args:?}");
            args.truncate(3);
        }
    }
    std::fs::write(&path, root.to_string()).unwrap();
    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        stdout(&accepted).contains("re-pinned"),
        "{}",
        stdout(&accepted)
    );
    let decided = sb.guard_fixture(Host::ClaudeCode, "read.json");
    assert_eq!(decided.status.code(), Some(0), "{}", stderr(&decided));
    for command in ["status", "doctor"] {
        let out = sb.moat(&[command]);
        assert!(stdout(&out).contains("out of date"), "{}", stdout(&out));
    }
    let init = sb.moat(&["init", "--yes"]);
    assert_eq!(init.status.code(), Some(0), "{}", stderr(&init));
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("\"--home\"")
    );
}
