//! The Cline CLI end to end: `init` writes OpenMoat's `PreToolUse` script to
//! `~/.cline/hooks`; run as Cline runs it (`sh <file>`, the call on stdin), the
//! script prints Cline's `cancel` for a deny, `{}` for an allow, and a `cancel`
//! of its own when `openmoat` cannot answer, since Cline runs the call when a
//! hook fails.
//!
//! The payloads follow the source of `cline/cline` `cli-v3.0.74`
//! (`crates/openmoat-hosts/src/host/cline/fixtures/README.md`); none is
//! captured from a signed-in session.

use serde_json::{Value, json};

use crate::common::Sandbox;

/// A `tool_call` payload for `tool` with `input`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    json!({
        "hookName": "tool_call", "clineVersion": "3.0.74",
        "timestamp": "2026-11-03T10:15:00.000Z", "taskId": "cline-1",
        "sessionContext": { "rootSessionId": "cline-1" },
        "workspaceRoots": [sb.project().to_string_lossy()], "userId": "me",
        "agent_id": "agent-1", "parent_agent_id": null, "iteration": 1,
        "tool_call": { "id": "call-1", "name": tool, "input": input },
    })
    .to_string()
}

#[cfg(unix)]
mod script {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use openmoat_hosts::Host;
    use serde_json::{Value, json};

    use super::payload;
    use crate::common::{OK, Sandbox, output, stdout, text};

    fn hook(sb: &Sandbox) -> PathBuf {
        sb.home
            .join(crate::hosts::dir_of(Host::Cline))
            .join("hooks")
            .join("PreToolUse")
    }

    /// `script` run as Cline runs a hook file whose `#!` line names `sh`, in the
    /// project, with `input` on stdin.
    fn run(sb: &Sandbox, script: &Path, input: &str) -> Output {
        let mut cmd = sb.configure(Command::new("sh"));
        cmd.arg(script).current_dir(sb.project());
        output(&mut cmd, Some(input))
    }

    /// The reply as JSON; `Value::Null` for none.
    fn reply(out: &Output) -> Value {
        serde_json::from_str(stdout(out).trim()).unwrap_or(Value::Null)
    }

    #[test]
    fn the_installed_script_answers_as_cline_reads_it() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(Host::Cline)]);
        let script = hook(&sb);
        let text_of = fs::read_to_string(&script).unwrap();
        assert!(text_of.starts_with("#!/bin/sh\n# OpenMoat for Cline."));

        let secret = sb.home.join(".ssh").join("id_rsa");
        let deny = run(
            &sb,
            &script,
            &payload(
                &sb,
                "run_commands",
                &json!({ "commands": [format!("cat {}", secret.display())] }),
            ),
        );
        assert_eq!(deny.status.code(), Some(OK), "{}", text(&deny));
        let doc = reply(&deny);
        assert_eq!(doc["cancel"], true, "{}", text(&deny));
        assert!(
            doc["errorMessage"]
                .as_str()
                .unwrap()
                .contains("secrets-paths")
        );

        let allow = run(
            &sb,
            &script,
            &payload(&sb, "run_commands", &json!({ "commands": ["git status"] })),
        );
        assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
        assert_eq!(reply(&allow), json!({}), "{}", text(&allow));

        // A tool OpenMoat does not govern is left to Cline: nothing on stdout.
        let ungoverned = run(
            &sb,
            &script,
            &payload(
                &sb,
                "ask_question",
                &json!({ "question": "?", "options": ["a", "b"] }),
            ),
        );
        assert_eq!(stdout(&ungoverned).trim(), "", "{}", text(&ungoverned));
    }

    /// A script whose `openmoat` is gone (a moved or uninstalled binary) still
    /// blocks the call: Cline would run it.
    #[test]
    fn the_script_blocks_when_openmoat_cannot_answer() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(Host::Cline)]);
        let installed = fs::read_to_string(hook(&sb)).unwrap();
        let line = installed
            .lines()
            .find(|l| l.starts_with("MOAT="))
            .unwrap()
            .to_owned();
        let moved = sb.home.join("moved-hook");
        fs::write(
            &moved,
            installed.replace(&line, "MOAT='/nonexistent/openmoat'"),
        )
        .unwrap();
        let out = run(
            &sb,
            &moved,
            &payload(&sb, "run_commands", &json!({ "commands": ["git status"] })),
        );
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        let doc = reply(&out);
        assert_eq!(doc["cancel"], true, "{}", text(&out));
        assert!(
            doc["errorMessage"]
                .as_str()
                .unwrap()
                .contains("hook-failure")
        );
    }

    /// Audit 2026-11-05 H10 and H12: `init` says it moves a person's own
    /// `PreToolUse` aside, keeps the file's mode, and `uninstall` gives the
    /// file back with its mode.
    #[test]
    fn init_says_it_moves_a_persons_hook_and_modes_survive() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = crate::hosts::dir_of(Host::Cline);
        let sb = Sandbox::bare(&[&dir]);
        let mine = hook(&sb);
        fs::create_dir_all(mine.parent().unwrap()).unwrap();
        fs::write(&mine, "#!/bin/sh\necho mine\n").unwrap();
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o755)).unwrap();
        let init = sb.moat(&["init", "--yes"]);
        assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
        assert!(
            stdout(&init).contains("moved your own hook"),
            "{}",
            text(&init)
        );
        assert_eq!(mode(&mine), 0o755, "the hook file keeps its mode");
        let again = sb.moat_as_person(&["init", "--yes"]);
        assert!(
            !stdout(&again).contains("moved your own hook"),
            "{}",
            text(&again)
        );
        let out = sb.moat_as_person(&["uninstall"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert_eq!(fs::read_to_string(&mine).unwrap(), "#!/bin/sh\necho mine\n");
        assert_eq!(mode(&mine), 0o755, "given back with its mode");
    }
}

/// Audit H9: Cline sends a call's arguments twice, so the limit is counted
/// once per copy: a file other agents may write in one call is checked, and
/// one past the limit is refused with how to go on.
#[test]
fn clines_two_copies_of_a_call_count_once_against_the_limit() {
    use crate::common::{DENY, OK, stdout};
    let sb = Sandbox::installed(&[&crate::hosts::dir_of(openmoat_hosts::Host::Cline)]);
    let with_copies = |size: usize| {
        let input =
            json!({ "command": "create", "path": "data.txt", "file_text": "a".repeat(size) });
        let mut doc: Value = serde_json::from_str(&payload(&sb, "editor", &input)).unwrap();
        doc["preToolUse"] = json!({ "toolName": "editor", "parameters": input });
        doc.to_string()
    };
    let out = sb.guard("cline", &with_copies(600_000));
    assert_eq!(out.status.code(), Some(OK), "{}", stdout(&out));
    let out = sb.guard("cline", &with_copies(1_100_000));
    assert_eq!(out.status.code(), Some(DENY));
    assert!(stdout(&out).contains("smaller parts"), "{}", stdout(&out));
}
