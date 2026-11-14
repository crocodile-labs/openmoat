//! `openmoat guard --plugin` (ADR-099), end to end with Claude Code: the
//! guard of the package from Claude Code's own plugin channel gives no
//! decision where `openmoat init`'s hook is installed and pinned, so each call
//! is decided once; decides the call where that hook is missing; denies and
//! names `openmoat init` without a lock; never stands aside over drift; and
//! `openmoat doctor` reports what it did last.

use std::fs;

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, bash_payload, json, stdout, text};

const DIR: &str = ".claude";
const HOST: &str = "claude-code";

/// A call the default policy denies: reading an SSH key.
fn secret_read(sb: &Sandbox) -> String {
    bash_payload("s1", &sb.project(), "cat ~/.ssh/id_rsa")
}

fn plugin_guard(sb: &Sandbox, payload: &str) -> std::process::Output {
    sb.moat_stdin(&["guard", "--host", HOST, "--plugin"], payload)
}

fn record(sb: &Sandbox) -> Value {
    let path = sb.home.join(format!(".moat/plugins/{HOST}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// `doctor --format json`'s rows whose detail starts with the package's line.
fn doctor_rows(sb: &Sandbox) -> Vec<Value> {
    let doc = json(&sb.moat(&["doctor", "--format", "json"]));
    doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["detail"]
                .as_str()
                .is_some_and(|d| d.contains("OpenMoat plugin installed through"))
        })
        .cloned()
        .collect()
}

#[test]
fn beside_inits_hook_the_package_gives_no_decision() {
    let sb = Sandbox::installed(&[DIR]);
    let out = plugin_guard(&sb, &secret_read(&sb));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "", "no decision is no output");
    assert_eq!(record(&sb)["stood_aside"], true);
    // `init`'s hook still decides the same call.
    let out = sb.guard_homed(HOST, &secret_read(&sb));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    let rows = doctor_rows(&sb);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0]["detail"]
            .as_str()
            .unwrap()
            .contains("gives no decision"),
        "{rows:?}"
    );
}

#[test]
fn without_inits_hook_the_package_decides() {
    let sb = Sandbox::installed(&[DIR]);
    // The person took OpenMoat's entries out of Claude Code's settings and
    // re-pinned (`init` answering no for Claude Code would leave the same).
    let settings = sb.home.join(DIR).join("settings.json");
    fs::write(&settings, "{}\n").unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));

    let out = plugin_guard(&sb, &secret_read(&sb));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(record(&sb)["stood_aside"], false);
    let rows = doctor_rows(&sb);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0]["detail"]
            .as_str()
            .unwrap()
            .contains("decided the calls itself"),
        "{rows:?}"
    );
}

#[test]
fn without_a_lock_the_package_denies_and_names_init() {
    let sb = Sandbox::bare(&[DIR]);
    let out = plugin_guard(&sb, &bash_payload("s1", &sb.project(), "ls"));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(text(&out).contains("openmoat init"), "{}", text(&out));
    // No state directory: nothing recorded.
    assert!(!sb.home.join(".moat").exists());
}

#[test]
fn over_drift_the_package_decides_and_denies() {
    let sb = Sandbox::installed(&[DIR]);
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text_now = fs::read_to_string(&policy).unwrap();
    text_now.push_str("\n# changed\n");
    fs::write(&policy, text_now).unwrap();
    let out = plugin_guard(&sb, &bash_payload("s1", &sb.project(), "ls"));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));
}

#[test]
fn a_heartbeat_from_the_package_records_it_and_reads_nothing() {
    let sb = Sandbox::installed(&[DIR]);
    let out = sb.moat(&["guard", "--heartbeat", "--host", HOST, "--plugin"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(record(&sb)["host"], HOST);
    // Never a report that `init`'s plugin loaded.
    assert!(!sb.home.join(".moat/loaded").exists());
}

/// `init` ran for another copy of Claude Code (`CLAUDE_CONFIG_DIR`), which
/// `hosts.json` records; this agent reads the default `~/.claude`, where no
/// hook of `init`'s is: the package decides, whatever the record says.
#[test]
fn a_hook_init_wrote_for_another_config_dir_is_not_stood_aside_for() {
    let sb = Sandbox::bare(&[".claude-work", DIR]);
    let work = sb.home.join(".claude-work");
    let mut init = sb.command();
    init.args(["init", "--yes"]).env("CLAUDE_CONFIG_DIR", &work);
    let out = crate::common::output(&mut init, None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(work.join("settings.json").is_file());

    let out = plugin_guard(&sb, &secret_read(&sb));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(record(&sb)["stood_aside"], false);
}

/// A repository can set an agent's environment; a package decides only with
/// the default state directory.
#[test]
fn a_moved_state_directory_is_refused() {
    let sb = Sandbox::installed(&[DIR]);
    let elsewhere = sb.home.join("elsewhere");
    let mut guard = sb.command();
    guard
        .args(["guard", "--host", HOST, "--plugin"])
        .env("MOAT_HOME", &elsewhere);
    let out = crate::common::output(&mut guard, Some(&bash_payload("s1", &sb.project(), "ls")));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(text(&out).contains("MOAT_HOME"), "{}", text(&out));
    // The default one, named, is fine.
    let mut guard = sb.command();
    guard
        .args(["guard", "--host", HOST, "--plugin"])
        .env("MOAT_HOME", sb.home.join(".moat"));
    let out = crate::common::output(&mut guard, Some(&secret_read(&sb)));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "", "stood aside");
}

/// A project's settings that turn hooks off leave `init`'s hook unrun: the
/// package does not stand aside for it there.
#[test]
fn a_project_that_turns_inits_hook_off_is_not_stood_aside_for() {
    let sb = Sandbox::installed(&[DIR]);
    let settings = sb.project().join(".claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{\"disableAllHooks\": true}\n").unwrap();
    let out = plugin_guard(&sb, &secret_read(&sb));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(record(&sb)["stood_aside"], false);
}

#[test]
fn plugin_and_home_together_are_a_usage_error() {
    let sb = Sandbox::installed(&[DIR]);
    let word = sb.home_word();
    let out = sb.moat_stdin(
        &["guard", "--host", HOST, "--plugin", "--home", &word],
        "{}",
    );
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
}
