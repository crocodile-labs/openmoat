//! `moat policy upgrade`: a policy from an older release gains what the new
//! default added, keeps every line its owner changed, and can be put back.

use serde_json::json;

use crate::common::{ASK, OK, Sandbox, USAGE, output, text, verdict};

/// What `moat init` wrote from 0.1.1 to 0.3.0, before it recorded a base.
const V0_3_0: &str = include_str!("../../src/upgrade/default-v0.3.0.yaml");
const DEFAULT: &str = include_str!("../../../openmoat-core/policies/default-v1.yaml");

/// The shipped default with the policy's LF line ends, whatever a Windows checkout made of it.
fn default_lf() -> String {
    DEFAULT.replace("\r\n", "\n")
}

fn policy(sb: &Sandbox) -> String {
    std::fs::read_to_string(sb.home.join(".moat/policy.yaml")).unwrap()
}

/// A home set up by a release before this one: `policy`, no recorded base,
/// re-pinned and the sandbox synced by a person.
fn older_home(policy: &str) -> Sandbox {
    let sb = Sandbox::installed(&[".claude"]);
    std::fs::write(sb.home.join(".moat/policy.yaml"), policy).unwrap();
    std::fs::remove_file(sb.home.join(".moat/policy.base.yaml")).unwrap();
    sb.moat_as_person(&["doctor", "--accept"]);
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    intact(&sb);
    sb
}

fn intact(sb: &Sandbox) {
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
}

fn web_search(sb: &Sandbox) -> String {
    let proj = sb.project();
    let payload = json!({
        "session_id": "s1", "cwd": proj.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch", "tool_input": {"query": "serde rename_all"}, "tool_use_id": "t1"
    });
    verdict(&sb.guard("claude-code", &payload.to_string()))
}

/// Exit code of `moat policy check` for writing a `.git` below the project root.
fn nested_git_write(sb: &Sandbox) -> Option<i32> {
    let proj = sb.project();
    let target = proj.join("vendor/lib/.git/config");
    let (proj, target) = (proj.to_string_lossy(), target.to_string_lossy());
    let args = [
        "policy",
        "check",
        &target,
        "--kind",
        "fs-write",
        "--project",
        &proj,
    ];
    sb.moat(&args).status.code()
}

#[test]
fn a_new_policy_records_its_base_and_has_nothing_to_upgrade() {
    let sb = Sandbox::installed(&[".claude"]);
    let base = std::fs::read_to_string(sb.home.join(".moat/policy.base.yaml")).unwrap();
    assert_eq!(base, DEFAULT);
    let out = sb.moat(&["policy", "upgrade", "--dry-run"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("has every change"), "{}", text(&out));
}

#[test]
fn a_0_3_0_policy_gains_the_new_defaults_and_undo_restores_it() {
    let sb = older_home(V0_3_0);
    assert_eq!(web_search(&sb), "ask");
    assert_eq!(nested_git_write(&sb), Some(OK));

    let out = sb.moat(&["policy", "upgrade", "--dry-run"]);
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(
        shown.contains("Policy update available: 2 changes"),
        "{shown}"
    );
    assert!(shown.contains("+  web.search: allow"), "{shown}");
    assert!(shown.contains(r#""!${project}/**/.git/**""#), "{shown}");
    assert!(shown.contains("OpenMoat 0.3.0 default"), "{shown}");
    assert_eq!(policy(&sb), V0_3_0);

    // No terminal: nothing changes, `--yes` or not.
    let out = sb.moat(&["policy", "upgrade", "--yes"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("must be run by a person"),
        "{}",
        text(&out)
    );
    assert_eq!(policy(&sb), V0_3_0);
    let out = sb.moat_as_person(&["policy", "upgrade"]);
    assert!(
        text(&out).contains("the policy was not changed"),
        "{}",
        text(&out)
    );
    assert_eq!(policy(&sb), V0_3_0);

    let out = sb.moat_as_person(&["policy", "upgrade", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("moat policy upgrade --undo"),
        "{}",
        text(&out)
    );
    assert_eq!(policy(&sb), default_lf());
    intact(&sb);
    assert_eq!(web_search(&sb), "allow");
    assert_eq!(nested_git_write(&sb), Some(ASK));

    let out = sb.moat(&["policy", "upgrade", "--undo", "--yes"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let out = sb.moat_as_person(&["policy", "upgrade", "--undo", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(policy(&sb).as_bytes(), V0_3_0.as_bytes());
    assert!(!sb.home.join(".moat/policy.base.yaml").exists());
    intact(&sb);
    let out = sb.moat_as_person(&["policy", "upgrade", "--undo", "--yes"]);
    assert!(text(&out).contains("no upgrade to undo"), "{}", text(&out));
}

#[test]
fn the_owners_changes_are_kept_and_a_conflicting_change_is_listed() {
    let fs_write = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**"]"#;
    let mine = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**", "!${project}/keys/**"]"#;
    let rule = "  - id: my-rule\n    shell: [\"make deploy\"]\n";
    let edited = V0_3_0
        .replace(fs_write, mine)
        .replace("ask:\n", &format!("ask:\n{rule}"));
    assert_ne!(edited, V0_3_0);
    let sb = older_home(&edited);

    let out = sb.moat(&["policy", "upgrade", "--dry-run"]);
    let shown = text(&out);
    assert!(
        shown.contains("Policy update available: 1 change "),
        "{shown}"
    );
    assert!(
        shown.contains("Not applied: you changed the policy at line"),
        "{shown}"
    );

    let out = sb.moat_as_person(&["policy", "upgrade", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let upgraded = policy(&sb);
    assert!(
        upgraded.contains(mine) && upgraded.contains(rule),
        "{upgraded}"
    );
    assert!(upgraded.contains("web.search: allow"), "{upgraded}");
    intact(&sb);

    // The change left out is listed again, and nothing else is offered.
    let out = sb.moat(&["policy", "upgrade", "--dry-run"]);
    let shown = text(&out);
    assert!(!shown.contains("Policy update available"), "{shown}");
    assert!(shown.contains("Not applied"), "{shown}");
}

#[test]
fn a_policy_not_made_from_the_default_is_left_alone() {
    let own = "version: 1\ndefaults:\n  \"*\": ask\n";
    let sb = older_home(own);
    let out = sb.moat_as_person(&["policy", "upgrade", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("not made from OpenMoat's default"),
        "{}",
        text(&out)
    );
    assert_eq!(policy(&sb), own);
}

#[test]
fn init_doctor_and_the_home_screen_offer_an_available_update() {
    let sb = older_home(V0_3_0);
    let update = "2 changes from the OpenMoat";
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains(&format!("! policy update    {update}")),
        "{}",
        text(&out)
    );
    let out = sb.moat(&["init", "--yes"]);
    assert!(
        text(&out).contains(&format!("! policy update    {update}")),
        "{}",
        text(&out)
    );

    let out = sb.moat(&[]);
    let shown = text(&out);
    assert!(
        shown.contains(&format!("Policy update available: {update}")),
        "{shown}"
    );
    assert!(shown.contains("`moat policy upgrade`") && !shown.contains("Nothing needs you"));
    assert_eq!(policy(&sb), V0_3_0);

    let out = output(sb.command().env("MOAT_ASSUME_TTY", "1"), Some("y\ny\n"));
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(shown.contains("See the changes? [y/N]") && shown.contains("Apply 2 changes? [y/N]"));
    assert_eq!(policy(&sb), default_lf());
    assert!(text(&sb.moat(&[])).contains("Nothing needs you."));
}
