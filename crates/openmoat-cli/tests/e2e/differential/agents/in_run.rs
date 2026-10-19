//! Hooks inside `moat run` (ADR-028) with the real Codex binary, as far as this
//! suite can take it. Driving a Codex session needs a model API, and inside
//! `moat run` the only network is the run's proxy, which refuses loopback, so
//! no local fake API is reachable from there (`run::confined`). What runs here:
//! the pinned `codex` starts inside the run's sandbox with the `CODEX_HOME`
//! `moat init` set up, and a Codex `PreToolUse` payload piped into the guard in
//! the same run is decided by the `moat run` process and recorded as Codex's.
//! `scripts/smoke-real-agents.sh` covers a whole Codex session in `moat run`.

use serde_json::json;

use crate::common::{DENY, OK, Sandbox, json as json_of, skip_without_host_binary, stdout, text};
use crate::run::confined::ran;
use crate::run::run_sh_with;

#[test]
fn real_codex_starts_inside_moat_run_and_its_hook_is_decided_outside() {
    let Some(codex) = std::env::var_os("MOAT_CODEX_BIN").filter(|v| !v.is_empty()) else {
        skip_without_host_binary("codex inside moat run (set MOAT_CODEX_BIN)");
        return;
    };
    // Landlock cannot deny inside a granted tree and `/tmp` is a read root, so
    // on Linux the home lives elsewhere for its key to be out of reach.
    let parent = if cfg!(target_os = "linux") {
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
    } else {
        std::env::temp_dir()
    };
    let sb = Sandbox::bare_in(&parent, &[".codex"]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "moat init: {}", text(&out));
    assert!(
        sb.home.join(".codex/hooks.json").exists(),
        "init installed no Codex hook: {}",
        text(&out)
    );
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "FAKE-SSH-KEY").unwrap();
    let project = sb.project();
    // Both binaries in the project: the sandbox reads the project, not the
    // CI download directory or the build tree.
    std::fs::copy(&codex, project.join("codex-bin")).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_moat"), project.join("moat-bin")).unwrap();

    let key = sb.home.join(".ssh/id_rsa");
    let payload = json!({
        "session_id": "codex-in-run", "turn_id": "t1", "hook_event_name": "PreToolUse",
        "cwd": project.to_string_lossy(), "tool_name": "Bash", "tool_use_id": "call_1",
        "tool_input": {"command": format!("cat {}", key.display())}
    })
    .to_string();
    let script = "./codex-bin --version && \
                  printf '%s' \"$PAYLOAD\" | ./moat-bin guard --host codex > hook.out; \
                  echo \"hook=$?\"; cat hook.out";
    let out = run_sh_with(&sb, &project, script, &[("PAYLOAD", &payload)]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(
        stdout(&out).contains("codex-cli "),
        "codex did not start: {shown}"
    );
    assert!(stdout(&out).contains(&format!("hook={DENY}")), "{shown}");
    assert!(shown.contains("secrets-paths"), "{shown}");
    assert!(!shown.contains("kernel-error"), "{shown}");
    let rows = sb.moat(&["show", "--session", "codex-in-run", "--format", "json"]);
    let rows = json_of(&rows);
    let row = &rows[0];
    assert_eq!(row["host"], "codex", "{rows}");
    assert_eq!(row["verdict"], "deny", "{rows}");
}
