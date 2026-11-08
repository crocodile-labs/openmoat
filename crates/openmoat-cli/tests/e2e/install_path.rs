//! Hooks name the stable install path, so a package-manager upgrade keeps them
//! working (#90). A Homebrew layout is simulated: `<prefix>/bin/moat` is a link
//! into `<prefix>/Cellar/moat/<version>/bin/moat`, a copy of the built binary,
//! in a home outside the temp directory.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, fixture, hook_output, output, text};

/// Install `version` into the Cellar and point `<prefix>/bin/moat` at it.
fn brew_install(prefix: &Path, version: &str) {
    let bin = prefix.join(format!("Cellar/moat/{version}/bin"));
    fs::create_dir_all(&bin).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_openmoat"), bin.join("moat")).unwrap();
    let link = prefix.join("bin/moat");
    fs::create_dir_all(prefix.join("bin")).unwrap();
    let _ = fs::remove_file(&link);
    let target = format!("../Cellar/moat/{version}/bin/moat");
    std::os::unix::fs::symlink(target, &link).unwrap();
}

/// A home outside the temp directory: `init` refuses a binary inside one.
fn outside_temp() -> Sandbox {
    Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[".claude"])
}

fn hook_command(sb: &Sandbox) -> String {
    let settings = fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap();
    let settings: Value = serde_json::from_str(&settings).unwrap();
    settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn hooks_survive_a_package_manager_upgrade() {
    let sb = outside_temp();
    let prefix = sb.home.join("homebrew");
    brew_install(&prefix, "0.1.0");
    let moat = prefix.join("bin/moat");
    let run = |program: &Path, args: &[&str], stdin: Option<&str>| {
        output(sb.command_at(program).args(args), stdin)
    };

    // Started through the link, Linux reports the Cellar file as `current_exe()`
    // (macOS reports the link); starting the Cellar file directly gives the same
    // facts on both.
    let versioned = prefix.join("Cellar/moat/0.1.0/bin/moat");
    let out = run(&versioned, &["init", "--yes"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let command = hook_command(&sb);
    assert!(command.ends_with("homebrew/bin/moat"), "{command}");
    assert!(
        !command.contains("Cellar"),
        "versioned path in hook: {command}"
    );

    // `brew upgrade` re-points the link; `brew cleanup` deletes the old version.
    brew_install(&prefix, "0.2.0");
    fs::remove_dir_all(prefix.join("Cellar/moat/0.1.0")).unwrap();

    let hook = PathBuf::from(&command);
    let out = run(
        &hook,
        &["guard", "--host", "claude-code"],
        Some(&fixture("claude-code/read.json")),
    );
    assert_eq!(
        hook_output(&out)["permissionDecision"],
        "allow",
        "{}",
        text(&out)
    );
    let out = run(&moat, &["doctor"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        !text(&out).contains("re-installs and re-pins"),
        "no problem: {}",
        text(&out)
    );
}

#[test]
fn doctor_and_status_name_a_missing_or_different_hook_binary() {
    let sb = outside_temp();
    let prefix = sb.home.join("homebrew");
    brew_install(&prefix, "0.1.0");
    let moat = prefix.join("bin/moat");

    // Hooks installed by another moat (here the build output) are not this one.
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    for args in [["doctor"], ["status"]] {
        let out = output(sb.command_at(&moat).args(args), None);
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(
            text(&out).contains("a different OpenMoat binary than this one"),
            "{}",
            text(&out)
        );
    }

    // A hook left pointing at a version the package manager removed.
    let settings = sb.home.join(".claude/settings.json");
    let gone = prefix.join("Cellar/moat/0.0.9/bin/moat");
    let edited = fs::read_to_string(&settings)
        .unwrap()
        .replace(env!("CARGO_BIN_EXE_openmoat"), &gone.to_string_lossy());
    fs::write(&settings, edited).unwrap();
    let out = output(sb.command_at(&moat).args(["doctor"]), None);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(
        text(&out).contains("which does not exist → openmoat init"),
        "{}",
        text(&out)
    );

    // The edited hook file drifted from the lock: a person repairs it.
    let out = output(
        sb.command_at(&moat)
            .args(["init", "--yes"])
            .env("MOAT_ASSUME_TTY", "1"),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let out = output(sb.command_at(&moat).args(["doctor"]), None);
    assert_eq!(
        out.status.code(),
        Some(OK),
        "init repairs it: {}",
        text(&out)
    );
}

/// Programs a repository could plant for OpenMoat to find through a relative
/// `PATH` entry: each host's program (asked `--version` by `init`, `status`
/// and `doctor`) and programs OpenMoat runs or pins.
const PLANTED: &[&str] = &[
    "claude",
    "cn",
    "codex",
    "copilot",
    "gemini",
    "goose",
    "hermes",
    "openclaw",
    "opencode",
    "pi",
    "git",
    "ssh-keygen",
    "sh",
    "bash",
    "openmoat",
    "moat",
];

/// A repository with `.` first on `PATH` cannot make OpenMoat run, pin or
/// record a program of its own: every lookup outside the snapshot's
/// command resolution skips relative entries. OpenMoat Bar runs `status`
/// and `doctor` every minute, wherever its shell was started.
#[test]
fn a_relative_path_entry_never_runs_or_pins_a_planted_program() {
    use std::os::unix::fs::PermissionsExt as _;
    let sb = outside_temp();
    let repo = sb.home.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let marker = sb.home.join("ran.txt");
    for name in PLANTED {
        let script = repo.join(name);
        fs::write(
            &script,
            format!("#!/bin/sh\necho {name} >> '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!(".:{}", std::env::var("PATH").unwrap_or_default());
    let run = |args: &[&str]| {
        let mut cmd = sb.command();
        cmd.current_dir(&repo)
            .env("PATH", &path)
            .env_remove("MOAT_CLAUDE_CODE_VERSION")
            .env_remove("MOAT_OPENCODE_VERSION")
            .args(args);
        output(&mut cmd, None)
    };
    let out = run(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    run(&["status"]);
    run(&["doctor"]);
    assert!(
        !marker.exists(),
        "a planted program ran: {}",
        fs::read_to_string(&marker).unwrap_or_default()
    );
    let snapshot: Value =
        serde_json::from_str(&fs::read_to_string(sb.home.join(".moat/environment.json")).unwrap())
            .unwrap();
    for (name, pinned) in snapshot["programs"].as_object().unwrap() {
        let pinned = pinned.as_str().unwrap();
        assert!(Path::new(pinned).is_absolute(), "{name} pinned as {pinned}");
        assert!(
            !pinned.starts_with(&*repo.to_string_lossy()),
            "{name}: {pinned}"
        );
    }
    let hook = hook_command(&sb);
    assert!(
        !hook.starts_with('.'),
        "the hook names a relative path: {hook}"
    );
}

/// `init` from a shell whose `PATH` finds none of the programs it pins
/// refuses and writes nothing; over a recorded snapshot it keeps that one.
#[test]
fn init_with_an_empty_path_refuses_or_keeps_the_recorded_search_path() {
    let sb = outside_temp();
    let empty = |args: &[&str]| output(sb.command().env("PATH", "").args(args), None);
    let out = empty(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("run `openmoat init` from a normal shell"),
        "{}",
        text(&out)
    );
    assert!(!sb.home.join(".moat").exists(), "nothing was written");

    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    let environment = sb.home.join(".moat/environment.json");
    let recorded = fs::read_to_string(&environment).unwrap();
    let out = output(
        sb.command()
            .env("PATH", "")
            .env("MOAT_ASSUME_TTY", "1")
            .args(["init", "--yes"]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("kept: this shell's PATH finds none"),
        "{}",
        text(&out)
    );
    assert_eq!(fs::read_to_string(&environment).unwrap(), recorded);
}
