//! Cursor's sandbox (#324): `init` and `sandbox sync` write `sandbox.json` in
//! the directory `CURSOR_CONFIG_DIR` names, the lock pins it, `status` and
//! `doctor` check it, and `uninstall` gives the user's file back.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::Value;

#[cfg(not(windows))]
use crate::common::DENY;
use crate::common::{OK, Sandbox, output, stdout, text};

const USER_FILE: &str = "{\"enableSharedBuildCache\": true}\n";

/// A home with Cursor's directory moved by `CURSOR_CONFIG_DIR`, holding a
/// `sandbox.json` of the user's own.
fn moved_cursor() -> (Sandbox, PathBuf) {
    let sb = Sandbox::bare(&[]);
    let dir = sb.home.join("cfg/cursor");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("sandbox.json"), USER_FILE).unwrap();
    (sb, dir)
}

fn moat(sb: &Sandbox, dir: &Path, args: &[&str]) -> Output {
    output(sb.command().args(args).env("CURSOR_CONFIG_DIR", dir), None)
}

fn sandbox_json(dir: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join("sandbox.json")).unwrap()).unwrap()
}

#[cfg(not(windows))]
#[test]
fn init_writes_and_pins_sandbox_json_and_uninstall_gives_it_back() {
    let (sb, dir) = moved_cursor();
    let init = moat(&sb, &dir, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert!(
        stdout(&init).contains("sandbox.json (sandbox updated;"),
        "{}",
        text(&init)
    );
    let file = sandbox_json(&dir);
    assert_eq!(file["type"], "workspace_readwrite");
    assert_eq!(file["readBoundary"], "workspace");
    assert_eq!(file["networkPolicy"]["default"], "deny");
    assert_eq!(file["enableSharedBuildCache"], true, "the user's key stays");
    let reads = file["additionalReadPaths"].to_string();
    assert!(
        !reads.contains(".ssh") && !reads.contains(".aws"),
        "{reads}"
    );
    assert!(dir.join("sandbox.json.moat-sandbox-backup").is_file());
    let lock = fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap();
    assert!(lock.contains("sandbox.json"), "pinned: {lock}");

    // Later commands find the directory through the record, without the variable.
    let status = stdout(&sb.moat(&["status"]));
    for line in [
        "Cursor           ✔ sandbox matches the policy",
        "Cursor           ✔ protection: hook + OS sandbox",
        "Cursor           · known gaps: commands Cursor runs outside its sandbox",
    ] {
        assert!(status.contains(line), "{line:?} in {status}");
    }
    let doctor = sb.moat(&["doctor", "--verbose"]);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
    for line in [
        "Cursor           sandbox matches the policy",
        "wider:    shell `cursor.unsandboxed`",
        "stricter: fs.read `sandbox.read_roots`: `",
    ] {
        assert!(
            stdout(&doctor).contains(line),
            "{line:?} in {}",
            text(&doctor)
        );
    }
    let show = stdout(&sb.moat(&["sandbox", "show"]));
    assert!(show.contains("\"readBoundary\": \"workspace\""), "{show}");

    let before = fs::read(dir.join("sandbox.json")).unwrap();
    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    assert!(
        stdout(&sync).contains("sandbox.json (sandbox unchanged)"),
        "{}",
        text(&sync)
    );
    assert_eq!(fs::read(dir.join("sandbox.json")).unwrap(), before);

    let uninstall = sb.moat_as_person(&["uninstall"]);
    assert_eq!(uninstall.status.code(), Some(OK), "{}", text(&uninstall));
    assert_eq!(
        fs::read_to_string(dir.join("sandbox.json")).unwrap(),
        USER_FILE
    );
    assert!(!dir.join("sandbox.json.moat-sandbox-backup").exists());
}

#[cfg(not(windows))]
#[test]
fn a_weakened_sandbox_json_denies_every_call_and_drops_to_hook_only() {
    let (sb, dir) = moved_cursor();
    fs::remove_file(dir.join("sandbox.json")).unwrap();
    let init = moat(&sb, &dir, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    let mut file = sandbox_json(&dir);
    file["readBoundary"] = "system".into();
    fs::write(dir.join("sandbox.json"), file.to_string()).unwrap();

    let read = sb.guard(
        "cursor",
        &crate::common::fixture("cursor/beforeReadFile.json"),
    );
    assert_eq!(read.status.code(), Some(DENY), "{}", text(&read));
    assert!(text(&read).contains("kernel-integrity"), "{}", text(&read));
    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains(
            "Cursor           ! protection: hook only: sandbox: readBoundary is not workspace"
        ),
        "{status}"
    );

    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        stdout(&accepted).contains("lock re-pinned"),
        "{}",
        text(&accepted)
    );
    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    assert_eq!(sandbox_json(&dir)["readBoundary"], "workspace");
    assert_eq!(sb.moat(&["doctor"]).status.code(), Some(OK));

    let uninstall = sb.moat_as_person(&["uninstall"]);
    assert_eq!(uninstall.status.code(), Some(OK), "{}", text(&uninstall));
    assert!(
        !dir.join("sandbox.json").exists(),
        "openmoat init created it"
    );
}

/// Cursor documents its sandbox for macOS and Linux only, so on native
/// Windows `init` leaves `sandbox.json` alone and every command says why.
#[cfg(windows)]
#[test]
fn native_windows_leaves_cursor_sandbox_json_alone() {
    let (sb, dir) = moved_cursor();
    let init = moat(&sb, &dir, &["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert_eq!(
        sandbox_json(&dir),
        serde_json::json!({"enableSharedBuildCache": true})
    );
    for out in [sb.moat(&["status"]), sb.moat(&["doctor"])] {
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(
            stdout(&out).contains("Cursor's sandbox runs on macOS and Linux only"),
            "{}",
            text(&out)
        );
    }
}
