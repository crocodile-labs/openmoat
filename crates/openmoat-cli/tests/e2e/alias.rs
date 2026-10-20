//! `moat`, the command's name up to 0.7.0, runs the `openmoat` beside it, and
//! `openmoat init` moves hooks written under the old name to `openmoat`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, USAGE, fixture, hook_output, output, stdout, text};

/// `name` with this platform's executable suffix.
fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// A home outside the temp directory (`init` refuses a binary inside one)
/// with `bin/` holding nothing yet.
fn home_with_bin() -> (Sandbox, PathBuf) {
    let sb = Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[".claude"]);
    let bin = sb.home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    (sb, bin)
}

fn run(sb: &Sandbox, program: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    output(sb.command_at(program).args(args), stdin)
}

fn person(sb: &Sandbox, program: &Path, args: &[&str]) -> Output {
    output(
        sb.command_at(program)
            .args(args)
            .env("MOAT_ASSUME_TTY", "1"),
        None,
    )
}

/// The output on one line, so a CI annotation of the panic shows all of it.
fn one_line(out: &Output) -> String {
    text(out).replace(['\r', '\n'], " | ")
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
fn moat_runs_the_same_command_as_openmoat() {
    let (sb, bin) = home_with_bin();
    let (openmoat, moat) = (bin.join(exe("openmoat")), bin.join(exe("moat")));
    fs::copy(env!("CARGO_BIN_EXE_openmoat"), &openmoat).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_moat"), &moat).unwrap();

    let version = run(&sb, &openmoat, &["--version"], None);
    let alias = run(&sb, &moat, &["--version"], None);
    assert_eq!(alias.status.code(), Some(OK), "{}", text(&alias));
    assert_eq!(stdout(&alias), stdout(&version));
    assert!(stdout(&alias).contains("(OpenMoat)"), "{}", text(&alias));

    // The same arguments, streams and exit code: an unknown command is usage,
    // and the hook gets the same answer under either name.
    assert_eq!(
        run(&sb, &moat, &["no-such"], None).status.code(),
        Some(USAGE)
    );
    let init = person(&sb, &openmoat, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", one_line(&init));
    let payload = fixture("claude-code/read.json");
    let args = ["guard", "--host", "claude-code"];
    let direct = run(&sb, &openmoat, &args, Some(&payload));
    let through = run(&sb, &moat, &args, Some(&payload));
    assert_eq!(
        through.status.code(),
        direct.status.code(),
        "{}",
        text(&through)
    );
    assert_eq!(hook_output(&through), hook_output(&direct));

    // Started as `moat`, `init` still records `openmoat` in the hooks.
    assert_eq!(
        person(&sb, &moat, &["init", "--yes"]).status.code(),
        Some(OK)
    );
    assert_eq!(Path::new(&hook_command(&sb)), openmoat);
}

#[test]
fn moat_without_openmoat_beside_it_fails_closed() {
    let (sb, bin) = home_with_bin();
    let moat = bin.join(exe("moat"));
    fs::copy(env!("CARGO_BIN_EXE_moat"), &moat).unwrap();
    let out = run(
        &sb,
        &moat,
        &["guard", "--host", "claude-code"],
        Some(&fixture("claude-code/read.json")),
    );
    assert_eq!(
        out.status.code(),
        Some(DENY),
        "a hook blocks: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("cannot find openmoat"),
        "{}",
        text(&out)
    );
    let out = run(&sb, &moat, &["status"], None);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
}

#[test]
fn init_moves_hooks_written_as_moat_to_openmoat() {
    let (sb, bin) = home_with_bin();
    let (openmoat, moat) = (bin.join(exe("openmoat")), bin.join(exe("moat")));
    // Before the rename the whole program was `bin/moat`, and its hooks name it.
    fs::copy(env!("CARGO_BIN_EXE_openmoat"), &moat).unwrap();
    let init = person(&sb, &moat, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", one_line(&init));
    assert_eq!(Path::new(&hook_command(&sb)), moat);
    let before = fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap();

    // The upgrade installs `openmoat` and turns `moat` into the alias.
    fs::copy(env!("CARGO_BIN_EXE_openmoat"), &openmoat).unwrap();
    fs::remove_file(&moat).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_moat"), &moat).unwrap();

    // Nothing breaks before `init`: the hook still decides, and doctor counts
    // it as installed and says how to switch. (The sandbox settings now also
    // name `openmoat`, so doctor asks for a sync, which `init` does too.)
    let payload = fixture("claude-code/read.json");
    let hook = run(
        &sb,
        &moat,
        &["guard", "--host", "claude-code"],
        Some(&payload),
    );
    assert_eq!(
        hook_output(&hook)["permissionDecision"],
        "allow",
        "{}",
        text(&hook)
    );
    let doctor = run(&sb, &openmoat, &["doctor"], None);
    for said in [
        "hook installed",
        "hook runs the old `moat` name",
        "the lock records",
        "will be removed in a later release",
    ] {
        assert!(text(&doctor).contains(said), "{said}: {}", text(&doctor));
    }
    for unsaid in ["a different OpenMoat binary", "lock expects"] {
        assert!(
            !text(&doctor).contains(unsaid),
            "{unsaid}: {}",
            text(&doctor)
        );
    }

    // `openmoat init` rewrites the hook and the lock to `openmoat`, backing up first.
    let init = person(&sb, &openmoat, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert_eq!(Path::new(&hook_command(&sb)), openmoat);
    let backup = sb.home.join(".claude/settings.json.moat-backup");
    assert_eq!(fs::read_to_string(backup).unwrap(), before);
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    assert_eq!(
        lock["binary"].as_str().map(Path::new),
        Some(openmoat.as_path())
    );
    let hook = run(
        &sb,
        &openmoat,
        &["guard", "--host", "claude-code"],
        Some(&payload),
    );
    assert_eq!(
        hook_output(&hook)["permissionDecision"],
        "allow",
        "{}",
        text(&hook)
    );
    let doctor = run(&sb, &openmoat, &["doctor"], None);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
    assert!(
        !text(&doctor).contains("old `moat` name"),
        "{}",
        text(&doctor)
    );
}
