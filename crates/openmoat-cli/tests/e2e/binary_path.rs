//! The `moat` binary the hooks run is protected by its recorded path, not only
//! by the `**/bin/moat` name glob: a binary installed under another name, its
//! link target and the directory holding it are `kernel-self` too, and `init`
//! refuses a binary an agent could replace (in the project or a temp directory).

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::common::{OK, Sandbox, USAGE, output, text, verdict_and_reason};

/// A copy of the built binary at `path`.
fn install_copy(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_moat"), path).unwrap();
}

/// A Claude Code `Write` payload for `path`.
fn write_payload(cwd: &Path, path: &Path) -> String {
    json!({
        "session_id": "s1", "cwd": cwd.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "Write", "tool_input": {"file_path": path.to_string_lossy(), "content": "x"},
        "tool_use_id": "t1"
    })
    .to_string()
}

#[test]
fn a_binary_under_another_name_is_protected_by_its_recorded_path() {
    let sb = Sandbox::bare_in(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        &[".claude", ".codex"],
    );
    let root = sb.home.parent().unwrap().to_path_buf();
    let target = root.join("build/release/moat-dev");
    install_copy(&target);
    let link = root.join("links/kernel");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = output(sb.command_at(&link).args(["init", "--yes"]), None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let project = sb.project();
    let real = |p: &Path| fs::canonicalize(p).unwrap();
    let dir: PathBuf = real(target.parent().unwrap());
    for path in [link.clone(), real(&target), dir.clone()] {
        let out = sb.guard("claude-code", &write_payload(&project, &path));
        let (verdict, reason) = verdict_and_reason(&out);
        assert!(
            verdict == "deny" && reason.contains("kernel-self"),
            "{path:?}: {reason}"
        );
    }
    // Every host sandbox names the recorded path and its directory literally;
    // the link's target, which an upgrade moves, is left to the hook. Codex
    // gets only the directory: its deny covers the file, and on Linux a file
    // entry inside a denied directory makes bubblewrap fail every command.
    let settings = fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&settings).unwrap();
    let codex = fs::read_to_string(sb.home.join(".codex/config.toml")).unwrap();
    let link_dir = real(link.parent().unwrap()).to_string_lossy().into_owned();
    for path in [link.to_string_lossy().into_owned(), link_dir.clone()] {
        let deny = &settings["sandbox"]["filesystem"]["denyWrite"];
        assert!(deny.as_array().unwrap().contains(&json!(path)), "{path}");
    }
    assert!(
        codex.contains(&format!("\"{link_dir}\" = \"deny\"")),
        "Codex: {link_dir}\n{codex}"
    );
    assert!(
        !codex.contains(&format!("\"{}\" =", link.display())),
        "Codex lists the file inside its denied directory:\n{codex}"
    );
    let target = real(&target);
    let (link, target, dir) = (link.display(), target.display(), dir.display());
    for command in [
        format!("cp /bin/sh {target}"),
        format!("ln -sf /bin/sh {link}"),
        format!("mv {dir} {dir}.old"),
        format!("rm -rf {dir}"),
    ] {
        let (verdict, reason) = sb.guard_bash("s1", &project, &command);
        assert_eq!(verdict, "deny", "{command}: {reason}");
        assert!(reason.contains("kernel-self"), "{command}: {reason}");
    }
}

#[test]
fn init_refuses_a_binary_inside_the_project() {
    let sb = Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[".claude"]);
    let project = sb.project();
    let binary = project.join("target/release/moat");
    install_copy(&binary);
    let out = output(
        sb.command_at(&binary)
            .current_dir(&project)
            .args(["init", "--yes"]),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("inside the project"), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists(), "nothing written");
    assert!(!sb.home.join(".claude/settings.json").exists());
}

#[test]
fn init_refuses_a_binary_in_a_temp_directory() {
    let sb = Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[".claude"]);
    let tmp = tempfile::tempdir().unwrap();
    let binary = tmp.path().join("moat");
    install_copy(&binary);
    let out = output(
        sb.command_at(&binary)
            .env("TMPDIR", std::env::temp_dir())
            .args(["init", "--yes"]),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("temp directory"), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists(), "nothing written");
}
