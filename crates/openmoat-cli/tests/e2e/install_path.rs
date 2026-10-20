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
    assert!(text(&out).contains("healthy"), "{}", text(&out));
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
        text(&out).contains("which does not exist; run `openmoat init`"),
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
