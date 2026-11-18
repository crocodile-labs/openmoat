//! `moat init` asks before changing an agent, and `moat uninstall` undoes it.

use std::fs;
use std::path::Path;

use crate::common::{DENY, OK, Sandbox, USAGE, output, squash, stdout, text};
use crate::hosts::{dir_of, hook_file, hook_file_name, mcp_user_file};
use openmoat_hosts::Host;

/// `moat init` as a person at a terminal answering `answers`.
fn init_answering(sb: &Sandbox, answers: &str) -> std::process::Output {
    init_with(sb, &[], answers)
}

/// `openmoat init` with `args`, as a person answering `answers`.
fn init_with(sb: &Sandbox, args: &[&str], answers: &str) -> std::process::Output {
    output(
        sb.command()
            .arg("init")
            .args(args)
            .env("MOAT_ASSUME_TTY", "1"),
        Some(answers),
    )
}

fn pinned(sb: &Sandbox) -> String {
    fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap()
}

fn backups_in(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.contains(".moat-"))
        .collect()
}

#[test]
fn init_without_a_terminal_changes_no_agent() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = sb.moat(&["init"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stdout(&out).contains("openmoat init --yes"),
        "{}",
        text(&out)
    );
    assert!(sb.home.join(".moat/policy.yaml").is_file());
    assert!(!hook_file(&sb, Host::ClaudeCode).exists());
    assert!(!hook_file(&sb, Host::Codex).exists());
    assert!(!mcp_user_file(&sb, Host::Codex).exists());
}

#[test]
fn init_asks_per_agent_and_changes_only_the_accepted_ones() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = init_answering(&sb, "\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = squash(&stdout(&out));
    // The answers are not echoed here as a terminal echoes them, so one
    // question follows the other on the same line.
    let main = std::path::MAIN_SEPARATOR;
    assert!(
        shown.contains(&format!(" Claude Code ~{main}.claude adds hook")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!(" Codex ~{main}.codex adds hook")),
        "{shown}"
    );
    assert_eq!(shown.matches("Protect? [Y/n/d]").count(), 2, "{shown}");
    assert!(shown.contains("✔ 1 agent protected"), "{shown}");
    assert!(
        shown.contains("undo everything: openmoat uninstall"),
        "{shown}"
    );
    assert!(hook_file(&sb, Host::ClaudeCode).is_file());
    assert!(!hook_file(&sb, Host::Codex).exists());
    assert!(!mcp_user_file(&sb, Host::Codex).exists());

    let declined = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let out = init_answering(&declined, "");
    assert!(stdout(&out).contains("No agent accepted"), "{}", text(&out));
    assert!(!hook_file(&declined, Host::ClaudeCode).exists());
}

/// An agent whose files need no change is not asked again: a yes would
/// change nothing. One that does need a change still is.
#[test]
fn init_asks_only_about_agents_that_would_change() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = init_answering(&sb, "\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    // Claude Code is set up now; Codex was declined.
    let out = init_answering(&sb, "n\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = squash(&stdout(&out));
    let main = std::path::MAIN_SEPARATOR;
    assert!(
        shown.contains(&format!(" Claude Code ~{main}.claude already set up ✔\n")),
        "{shown}"
    );
    assert_eq!(shown.matches("Protect? [Y/n/d]").count(), 1, "{shown}");
    assert!(
        shown.contains(&format!(" Codex ~{main}.codex adds hook")),
        "{shown}"
    );
    assert!(!hook_file(&sb, Host::Codex).exists());
    assert!(shown.contains("✔ 1 agent protected"), "{shown}");
    // Nothing changed for Claude Code: no restart, no trust step.
    assert!(!shown.contains("Restart your agents"), "{shown}");
}

/// Before asking about an agent, `init` says in a few words what it would
/// write there and, with `--verbose`, sums up every file it would change (new
/// or edited, lines, the settings it sets), not the whole diff.
#[test]
fn init_sums_up_each_agents_changes_before_asking() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = init_answering(&sb, "\nn\n");
    let shown = stdout(&out);
    // native Windows has no OS sandbox for Claude Code
    let claude = if cfg!(windows) {
        "adds hook "
    } else {
        "adds hook + sandbox settings"
    };
    let first = shown.find("Protect? [Y/n/d]").expect(&shown);
    assert!(shown[..first].contains(claude), "{shown}");
    assert!(!shown.contains("settings.json: new file"), "{shown}");

    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = init_with(&sb, &["--verbose"], "\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = stdout(&out);
    let claude = shown
        .lines()
        .find(|l| l.contains("settings.json: new file, +"))
        .expect(&shown);
    assert!(
        claude.contains("sets ") && claude.contains("hooks"),
        "{shown}"
    );
    // native Windows has no OS sandbox for Claude Code, so no `sandbox` key there
    assert_eq!(claude.contains("sandbox"), !cfg!(windows), "{shown}");
    assert!(
        shown.find(claude).unwrap() < shown.find("Protect? [Y/n/d]").unwrap(),
        "{shown}"
    );
    assert!(shown.contains("hooks.json: new file, +"), "{shown}");
    assert!(shown.contains("config.toml: new file, +"), "{shown}");
    assert!(!shown.contains("(after openmoat init)"), "{shown}");
    assert!(hook_file(&sb, Host::ClaudeCode).is_file());
    assert!(!hook_file(&sb, Host::Codex).exists());
}

/// Answering `d` shows the full diff of every file the agent would get, hooks
/// and sandbox settings alike, then asks again; a declined agent's files stay
/// as they were.
#[test]
fn init_shows_the_full_diff_on_d_and_asks_again() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = init_answering(&sb, "d\n\nd\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = stdout(&out);
    // Claude Code's question twice, then Codex's twice.
    let asked: Vec<usize> = shown
        .match_indices("Protect? [Y/n/d]")
        .map(|(at, _)| at)
        .collect();
    assert_eq!(asked.len(), 4, "{shown}");
    // The agent a question is about: the first column of its line. A piped
    // answer is not echoed, so the line may follow the question before it.
    let agent_before = |at: usize| {
        let line = shown[..at].rsplit('\n').next().unwrap_or_default();
        let line = line.rsplit("[Y/n/d] ").next().unwrap_or_default();
        line.trim_start()
            .split("  ")
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(agent_before(asked[0]), "Claude Code", "{shown}");
    assert_eq!(agent_before(asked[2]), "Codex", "{shown}");
    let claude = shown
        .find("settings.json (after openmoat init)")
        .expect(&shown);
    let codex = shown
        .find("hooks.json (after openmoat init)")
        .expect(&shown);
    // each diff comes after the first question and before the question again
    assert!(asked[0] < claude && claude < asked[1], "{shown}");
    assert!(asked[2] < codex && codex < asked[3], "{shown}");
    assert!(
        shown.contains("config.toml (after openmoat init)"),
        "{shown}"
    );
    assert!(
        shown
            .lines()
            .any(|l| l.starts_with('+') && l.contains("\"--host\"")),
        "{shown}"
    );
    assert!(
        shown
            .lines()
            .any(|l| l.starts_with('+') && l.contains("\"onFailure\": \"block\"")),
        "{shown}"
    );
    assert!(hook_file(&sb, Host::ClaudeCode).is_file());
    assert!(!hook_file(&sb, Host::Codex).exists());
}

#[test]
fn init_hosts_leaves_other_agents_untouched() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode), &dir_of(Host::Codex)]);
    let out = sb.moat(&["init", "--hosts", Host::ClaudeCode.id()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(hook_file(&sb, Host::ClaudeCode).is_file());
    assert!(
        fs::read_dir(sb.home.join(dir_of(Host::Codex)))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn uninstall_restores_the_original_files_byte_for_byte() {
    let sb = Sandbox::bare(&[
        &dir_of(Host::ClaudeCode),
        &dir_of(Host::Codex),
        &dir_of(Host::Cursor),
    ]);
    let settings = hook_file(&sb, Host::ClaudeCode);
    let codex_config = mcp_user_file(&sb, Host::Codex);
    let claude_original = "{ \"theme\" : \"dark\",\n  \"hooks\": {\"Stop\": []} }\n";
    let codex_original = "# mine\nmodel = \"o3\"\n";
    fs::write(&settings, claude_original).unwrap();
    fs::write(&codex_config, codex_original).unwrap();
    let out = sb.moat(&["init", "--yes", "--verbose"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("Backups saved"), "{}", text(&out));
    assert!(
        stdout(&out).contains("settings.json.moat-backup"),
        "{}",
        text(&out)
    );
    assert!(pinned(&sb).contains(hook_file_name(Host::ClaudeCode)));

    let refused = sb.moat(&["uninstall"]);
    assert_eq!(refused.status.code(), Some(USAGE), "{}", text(&refused));
    assert_ne!(fs::read_to_string(&settings).unwrap(), claude_original);

    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("restored from"), "{}", text(&out));
    assert_eq!(fs::read_to_string(&settings).unwrap(), claude_original);
    assert_eq!(fs::read_to_string(&codex_config).unwrap(), codex_original);
    assert!(!hook_file(&sb, Host::Codex).exists(), "init created it");
    assert!(!hook_file(&sb, Host::Cursor).exists(), "init created it");
    for dir in [".claude", ".codex", ".cursor"] {
        assert!(backups_in(&sb.home.join(dir)).is_empty(), "{dir}");
    }
    assert!(
        !pinned(&sb).contains(hook_file_name(Host::ClaudeCode)),
        "{}",
        pinned(&sb)
    );
    assert!(!pinned(&sb).contains("config.toml"), "{}", pinned(&sb));
    assert!(sb.home.join(".moat/policy.yaml").is_file(), "state is kept");

    let again = sb.moat_as_person(&["uninstall"]);
    assert!(stdout(&again).contains("not set up"), "{}", text(&again));
}

#[test]
fn uninstall_keeps_changes_made_since_init() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let settings = hook_file(&sb, Host::ClaudeCode);
    fs::write(&settings, "{\"theme\": \"dark\"}").unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    doc["model"] = "opus".into();
    fs::write(&settings, doc.to_string()).unwrap();

    let out = sb.moat_as_person(&["uninstall", "--hosts", Host::ClaudeCode.id()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("backup kept"), "{}", text(&out));
    let left: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(left, serde_json::json!({"theme": "dark", "model": "opus"}));
}

/// A file of the user's at a backup's name is not OpenMoat's backup: `init`
/// neither replaces nor lists it, and `uninstall` neither restores nor deletes it.
#[test]
fn a_users_file_at_a_backup_name_is_never_taken_or_deleted() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let settings = hook_file(&sb, Host::ClaudeCode);
    let mine = sb.home.join(".claude/settings.json.moat-backup");
    fs::write(&settings, "{\"theme\": \"dark\"}\n").unwrap();
    fs::write(&mine, "my own notes\n").unwrap();
    let out = sb.moat(&[
        "init",
        "--yes",
        "--hosts",
        Host::ClaudeCode.id(),
        "--verbose",
    ]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        !stdout(&out).contains("settings.json.moat-backup"),
        "{}",
        text(&out)
    );

    let out = sb.moat_as_person(&["uninstall", "--hosts", Host::ClaudeCode.id()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(fs::read_to_string(&mine).unwrap(), "my own notes\n");
    let left: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(left, serde_json::json!({"theme": "dark"}));
    assert!(
        !stdout(&out).contains("settings.json.moat-backup"),
        "not listed as a backup: {}",
        text(&out)
    );
}

#[test]
fn uninstall_purge_deletes_the_state_directory() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    let out = sb.moat_as_person(&["uninstall", "--purge"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists());
    assert!(!hook_file(&sb, Host::ClaudeCode).exists());
}

/// #298: `init` records a moved config directory; later commands use it without
/// the variable, and uninstall forgets it.
#[test]
fn commands_follow_the_recorded_config_dir() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let custom = sb.home.join("custom-claude");
    fs::create_dir_all(&custom).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--hosts", Host::ClaudeCode.id()])
            .env("CLAUDE_CONFIG_DIR", &custom),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(custom.join(hook_file_name(Host::ClaudeCode)).is_file());
    let recorded = fs::read_to_string(sb.home.join(".moat/hosts.json")).unwrap();
    assert!(recorded.contains("custom-claude"), "{recorded}");

    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(OK), "{}", text(&status));
    let doctor = sb.moat(&["doctor", "--verbose"]);
    assert!(
        stdout(&doctor).contains("custom-claude"),
        "{}",
        text(&doctor)
    );
    assert!(!hook_file(&sb, Host::ClaudeCode).exists());

    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        !custom.join(hook_file_name(Host::ClaudeCode)).exists(),
        "{}",
        text(&out)
    );
    let recorded = fs::read_to_string(sb.home.join(".moat/hosts.json")).unwrap();
    assert!(!recorded.contains("custom-claude"), "{recorded}");
    let doctor = sb.moat(&["doctor"]);
    assert!(!text(&doctor).contains("was modified"), "{}", text(&doctor));
}

/// #298: `kernel-self` protects both the recorded directory and the one an
/// agent's variable names when they differ; an agent may run with either.
#[test]
fn kernel_self_covers_the_recorded_and_the_env_config_dir() {
    let sb = Sandbox::bare(&[]);
    let recorded = sb.home.join("recorded-claude");
    let other = sb.home.join("other-claude");
    fs::create_dir_all(&recorded).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--hosts", Host::ClaudeCode.id()])
            .env("CLAUDE_CONFIG_DIR", &recorded),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    for dir in [&recorded, &other] {
        let target = dir.join(hook_file_name(Host::ClaudeCode));
        let out = output(
            sb.command().env("CLAUDE_CONFIG_DIR", &other).args([
                "policy",
                "check",
                target.to_str().unwrap(),
                "--kind",
                "fs-write",
            ]),
            None,
        );
        assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
        assert!(stdout(&out).contains("kernel-self"), "{}", text(&out));
    }
}

/// The deny rules `init` adds to Claude Code's settings on every OS hold when
/// the hook does not run; uninstall takes exactly those, and a user's rule
/// spelled like one of them stays.
#[test]
fn uninstall_takes_only_the_deny_rules_init_added() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let settings = hook_file(&sb, Host::ClaudeCode);
    let user = serde_json::json!(["Read(//**/.env)", "Edit(//tmp/x)"]);
    let original = serde_json::json!({ "permissions": { "deny": user } });
    fs::write(&settings, original.to_string()).unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let deny = doc["permissions"]["deny"].as_array().unwrap().clone();
    for rule in [
        "Edit(//**/bin/moat)",
        "Edit(//**/.moat/**)",
        "Read(//**/.envrc)",
    ] {
        assert!(deny.contains(&rule.into()), "{rule}: {deny:?}");
    }
    let env = deny.iter().filter(|r| *r == "Read(//**/.env)").count();
    assert_eq!(env, 1, "the user's rule is not doubled: {deny:?}");

    // A change since init keeps the file from being restored: the rules are stripped.
    doc["model"] = "opus".into();
    fs::write(&settings, doc.to_string()).unwrap();
    let out = sb.moat_as_person(&["uninstall", "--hosts", Host::ClaudeCode.id()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let left: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(
        left,
        serde_json::json!({ "permissions": { "deny": user }, "model": "opus" })
    );
    let hosts = fs::read_to_string(sb.home.join(".moat/hosts.json")).unwrap();
    assert!(!hosts.contains("claude_rules"), "{hosts}");
}
