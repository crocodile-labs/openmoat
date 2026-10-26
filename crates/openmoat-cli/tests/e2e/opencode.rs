//! OpenCode integration end to end: `init` writes OpenMoat's plugin into
//! OpenCode's configuration directory and pins it, `guard --host opencode`
//! answers in the plugin's format, OpenCode 2 is not set up, and a project's
//! plugins and configuration are warned about. What every host shares
//! (uninstall, the lock, MCP pins, asks) is the suite in `hosts/`.
//!
//! The payloads follow the hook and tool arguments of the OpenCode 1.19.4
//! source (`crates/openmoat-hosts/src/host/opencode/fixtures/README.md`); none is
//! captured from OpenCode.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, output, stdout, text};

const CONFIG_DIR: &str = ".config/opencode";

fn sandbox() -> Sandbox {
    Sandbox::installed(&[CONFIG_DIR])
}

/// A `tool.execute.before` payload for `tool` with `args`, in the project,
/// with one configured MCP server, from the platform the test runs on, as
/// the plugin sends `process.platform`.
pub(crate) fn payload(sb: &Sandbox, tool: &str, args: &Value) -> String {
    let project = sb.project().to_string_lossy().into_owned();
    let platform = if cfg!(windows) { "win32" } else { "linux" };
    json!({
        "hook_event_name": "tool.execute.before",
        "tool": tool, "args": args, "sessionID": "ses_1", "callID": "call-1",
        "directory": project, "worktree": project,
        "mcpServers": ["internal-tools"], "platform": platform,
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("opencode", payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

fn reason(reply: &Value) -> String {
    reply["reason"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn init_writes_the_plugin_once() {
    let sb = sandbox();
    let plugin = sb.home.join(CONFIG_DIR).join("plugins/openmoat.js");
    let source = fs::read_to_string(&plugin).unwrap();
    assert!(source.starts_with("// OpenMoat for OpenCode."), "{source}");
    let binary = serde_json::to_string(env!("CARGO_BIN_EXE_openmoat")).unwrap();
    assert!(
        source.contains(&format!("const MOAT = {binary};")),
        "{source}"
    );
    // OpenCode's own configuration is not edited.
    assert!(!sb.home.join(CONFIG_DIR).join("opencode.json").exists());
}

#[test]
fn writes_to_opencodes_own_files_are_denied() {
    let sb = sandbox();
    let dir = sb.home.join(CONFIG_DIR);
    for (tool, args) in [
        (
            "edit",
            json!({"filePath": dir.join("plugins/openmoat.js"),
                "oldString": "throw error", "newString": "return"}),
        ),
        (
            "write",
            json!({"filePath": dir.join("opencode.json"),
                "content": "{\"plugin\":[\"./evil.js\"]}"}),
        ),
        (
            "bash",
            json!({"command": "rm -rf ~/.config/opencode/plugins"}),
        ),
        (
            "bash",
            json!({"command": "opencode run --pure 'list files'"}),
        ),
        ("bash", json!({"command": "OPENCODE_PURE=1 opencode run x"})),
    ] {
        // On Windows OpenCode's shell may be PowerShell or `cmd`, which
        // OpenMoat leaves to OpenCode (`unparseable`, documented there).
        if tool == "bash" && cfg!(windows) {
            continue;
        }
        let (code, reply) = guard(&sb, &payload(&sb, tool, &args));
        assert_eq!(code, Some(DENY), "{tool} {args}: {reply}");
        assert!(reason(&reply).contains("kernel-self"), "{tool}: {reply}");
    }
}

/// OpenCode 1 cannot ask: a project plugin write asks, which reaches OpenCode
/// as a deny that says how to approve it.
#[test]
fn a_project_plugin_write_is_a_deny_that_says_how_to_approve() {
    let sb = sandbox();
    let plugin = sb.project().join(".opencode/plugins/helper.ts");
    let (code, reply) = guard(
        &sb,
        &payload(&sb, "write", &json!({"filePath": plugin, "content": "x"})),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    let why = reason(&reply);
    assert!(why.contains("runs-later"), "{why}");
    assert!(why.contains("openmoat allow --last"), "{why}");
}

/// `XDG_CONFIG_HOME` moves the directory: `init` follows it, and later
/// commands follow the record without the variable.
#[test]
fn a_moved_config_directory_is_followed_and_protected() {
    let sb = Sandbox::bare(&[]);
    let xdg = sb.home.join("xdg");
    fs::create_dir_all(xdg.join("opencode")).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--yes", "--hosts", "opencode"])
            .env("XDG_CONFIG_HOME", &xdg),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let plugin = xdg.join("opencode/plugins/openmoat.js");
    assert!(plugin.is_file(), "{}", text(&out));
    assert!(!sb.home.join(CONFIG_DIR).exists());

    let write = json!({"filePath": plugin, "content": "export default async () => ({})"});
    let (code, reply) = guard(&sb, &payload(&sb, "write", &write));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reason(&reply).contains("kernel-self"), "{reply}");
}

/// A shell's `XDG_CONFIG_HOME` says nothing about OpenCode: with no OpenCode
/// directory under it, `init` says nothing about OpenCode.
#[test]
fn a_shared_xdg_config_home_alone_does_not_name_opencode() {
    let sb = Sandbox::bare(&[]);
    let xdg = sb.home.join("xdg");
    fs::create_dir_all(&xdg).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--yes"])
            .env("XDG_CONFIG_HOME", &xdg),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!text(&out).contains("OpenCode"), "{}", text(&out));
}

/// OpenCode 2 loads plugins through another API: `init` does not write a
/// plugin it would not run, and `status` reports the agent as not protected.
#[test]
fn opencode_2_is_not_set_up_and_is_reported() {
    let sb = Sandbox::bare(&[CONFIG_DIR]);
    let out = output(
        sb.command()
            .args(["init", "--yes"])
            .env("MOAT_OPENCODE_VERSION", "2.1.4"),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("OpenCode 2"), "{}", text(&out));
    assert!(
        !sb.home
            .join(CONFIG_DIR)
            .join("plugins/openmoat.js")
            .exists(),
        "{}",
        text(&out)
    );
    let mut status = sb.command();
    status
        .args(["status", "--format", "json"])
        .env("MOAT_OPENCODE_VERSION", "2.1.4");
    let doc = parse(&output(&mut status, None));
    let agent = doc["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["host"] == "opencode")
        .unwrap()
        .clone();
    assert_eq!(agent["level"], "not-protected", "{agent}");
    assert!(
        agent["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("2.1.4"),
        "{agent}"
    );
}

/// A project's configuration and plugins load at start with no prompt, so
/// `status` names them; comments in the file are read as OpenCode reads them.
#[test]
fn a_projects_plugins_and_configuration_are_reported() {
    let sb = sandbox();
    let project = sb.project();
    fs::create_dir_all(project.join(".opencode/plugins")).unwrap();
    fs::write(
        project.join("opencode.json"),
        "{\n  // added by the repository\n  \"plugin\": [\"opencode-helper\"],\n}\n",
    )
    .unwrap();
    fs::write(
        project.join(".opencode/plugins/helper.ts"),
        "export default async () => ({})",
    )
    .unwrap();
    let mut cmd = sb.command();
    cmd.current_dir(&project)
        .args(["status", "--format", "json"]);
    let doc = parse(&output(&mut cmd, None));
    let warnings = doc["project_settings"].to_string();
    assert!(warnings.contains("`plugin` loads plugins"), "{warnings}");
    assert!(
        warnings.contains("helper.ts: is a plugin OpenCode loads"),
        "{warnings}"
    );
    assert!(!warnings.contains("cannot be checked"), "{warnings}");
}

/// `OPENCODE_CONFIG_DIR` names a further configuration directory: `init`
/// records it, and its configuration file is protected like the default one's.
#[test]
fn opencode_config_dir_is_protected_like_the_configuration_directory() {
    let sb = Sandbox::bare(&[CONFIG_DIR]);
    let extra = sb.home.join("occ");
    fs::create_dir_all(extra.join("plugins")).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--yes", "--hosts", "opencode"])
            .env("OPENCODE_CONFIG_DIR", &extra),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    // Without the variable, from the record.
    let write = json!({"filePath": extra.join("opencode.json"),
        "content": "{\"plugin\":[\"./evil.js\"]}"});
    let (code, reply) = guard(&sb, &payload(&sb, "write", &write));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reason(&reply).contains("kernel-self"), "{reply}");
}

/// OpenCode's stored provider keys are the agent's to use, not to read.
#[test]
fn reading_opencodes_stored_keys_is_denied() {
    let sb = sandbox();
    let auth = sb.home.join(".local/share/opencode/auth.json");
    let (code, reply) = guard(&sb, &payload(&sb, "read", &json!({"filePath": auth})));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reason(&reply).contains("agent-credentials"), "{reply}");
}

/// A version with a published advisory is named in one warning line; the
/// exit code stays what it was.
#[test]
fn status_warns_about_a_version_with_an_advisory() {
    let sb = sandbox();
    let mut status = sb.command();
    status
        .args(["status"])
        .env("MOAT_OPENCODE_VERSION", "1.0.100");
    let out = output(&mut status, None);
    let printed = stdout(&out);
    let warned: Vec<&str> = printed
        .lines()
        .filter(|l| l.contains("has a known security advisory"))
        .collect();
    assert_eq!(warned.len(), 1, "{}", text(&out));
    assert!(warned[0].contains("OpenCode 1.0.100"), "{}", warned[0]);
    assert!(warned[0].contains("upgrade to"), "{}", warned[0]);
    let mut current = sb.command();
    current
        .args(["status"])
        .env("MOAT_OPENCODE_VERSION", "1.19.4");
    let quiet = output(&mut current, None);
    assert!(
        !stdout(&quiet).contains("security advisory"),
        "{}",
        text(&quiet)
    );
    assert_eq!(quiet.status.code(), out.status.code());
}
