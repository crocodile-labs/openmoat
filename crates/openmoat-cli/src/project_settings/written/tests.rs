//! Each write that leaves a project settings file turning its host's hook off
//! is denied, whichever tool makes it; every other change to those files, and
//! a write whose outcome is not known, keeps the policy's verdict.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::{Decision, EvalContext, Verdict};
use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::tightened;

struct Project {
    _dir: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
}

impl Project {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = home.join("proj");
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::create_dir_all(root.join(".pi")).unwrap();
        fs::create_dir_all(root.join(".opencode")).unwrap();
        Self {
            _dir: dir,
            home,
            root,
        }
    }

    fn file(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }

    fn ctx(&self) -> EvalContext {
        let s = |p: &Path| p.to_string_lossy().replace('\\', "/");
        EvalContext {
            home: s(&self.home),
            project: Some(s(&self.root)),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: s(&self.root),
            case_insensitive_paths: false,
        }
    }

    /// OpenMoat's hook file of `host` under this home, as `moat init` puts it.
    fn hook_file(&self, host: Host) -> PathBuf {
        match host {
            Host::Pi => self.home.join(".pi/agent/extensions/openmoat.js"),
            Host::OpenCode => self.home.join(".config/opencode/plugins/openmoat.js"),
            _ => self.home.join(format!(".{}/hooks.json", host.id())),
        }
    }

    /// The verdict of `payload` from `host` when the policy said `review`.
    fn verdict(&self, host: Host, payload: &Value) -> (Verdict, Decision) {
        let request = host.parse_request(&payload.to_string()).unwrap();
        let hook = |h: Host| Some(self.hook_file(h));
        let review = Decision::new(Verdict::Review);
        let d = tightened(&request, &self.ctx(), &hook, review);
        (d.verdict, d)
    }

    fn claude(&self, tool: &str, input: Value) -> (Verdict, Decision) {
        let mut payload = json!({
            "hook_event_name": "PreToolUse", "session_id": "s", "cwd": self.file(""),
            "tool_name": tool,
        });
        payload["tool_input"] = input;
        self.verdict(Host::ClaudeCode, &payload)
    }

    fn codex_patch(&self, patch: &str) -> (Verdict, Decision) {
        let payload = json!({
            "hook_event_name": "PreToolUse", "session_id": "s", "cwd": self.file(""),
            "tool_name": "apply_patch", "tool_input": {"command": patch},
        });
        self.verdict(Host::Codex, &payload)
    }

    fn opencode(&self, tool: &str, args: Value) -> (Verdict, Decision) {
        let mut payload = json!({
            "hook_event_name": "tool.execute.before", "tool": tool,
            "sessionID": "ses_1", "callID": "c", "directory": self.file(""),
            "worktree": self.file(""), "mcpServers": [],
        });
        payload["args"] = args;
        self.verdict(Host::OpenCode, &payload)
    }

    fn pi(&self, tool: &str, input: Value) -> (Verdict, Decision) {
        let mut payload = json!({
            "hook_event_name": "tool_call", "toolName": tool,
            "toolCallId": "t", "sessionId": "s", "cwd": self.file(""), "hasUI": true,
        });
        payload["input"] = input;
        self.verdict(Host::Pi, &payload)
    }
}

fn denied(result: &(Verdict, Decision)) -> bool {
    result.0 == Verdict::Deny && result.1.rules == [super::super::RULE]
}

const CODEX_OFF: &str = "[features]\nhooks = false\n";

#[test]
fn a_whole_file_that_turns_a_hook_off_is_denied_whoever_writes_it() {
    let p = Project::new();
    let codex = p.file(".codex/config.toml");
    let r = p.claude("Write", json!({"file_path": codex, "content": CODEX_OFF}));
    assert!(denied(&r), "{r:?}");
    assert!(
        r.1.reasons[0].contains("`features.hooks` turns off"),
        "{r:?}"
    );
    // The deprecated alias, too.
    let alias = "[features]\ncodex_hooks = false\n";
    assert!(denied(
        &p.claude("Write", json!({"file_path": codex, "content": alias}))
    ));
    let opencode = p.file("opencode.json");
    for (file, content) in [
        (
            opencode.clone(),
            json!({"plugin": ["-openmoat"]}).to_string(),
        ),
        (
            p.file(".opencode/opencode.json"),
            json!({"plugins": ["-*"]}).to_string(),
        ),
        (
            p.file("opencode.jsonc"),
            "{ // off\n \"plugin\": [\"-openmoat\"], }".to_owned(),
        ),
    ] {
        let r = p.opencode("write", json!({"filePath": file, "content": content}));
        assert!(denied(&r), "{file}: {r:?}");
    }
    for extensions in [
        json!(["!**"]),
        json!(["!openmoat.js"]),
        json!(["-~/.pi/agent/extensions/openmoat.js"]),
    ] {
        let content = json!({ "extensions": extensions }).to_string();
        let r = p.pi(
            "write",
            json!({"path": p.file(".pi/settings.json"), "content": content}),
        );
        assert!(denied(&r), "{extensions}: {r:?}");
    }
}

#[test]
fn an_edit_or_patch_that_turns_a_hook_off_is_denied() {
    let p = Project::new();
    let codex = p.file(".codex/config.toml");
    fs::write(&codex, "model = \"gpt-5\"\n[features]\nhooks = true\n").unwrap();
    let edit =
        json!({"file_path": codex, "old_string": "hooks = true", "new_string": "hooks = false"});
    assert!(denied(&p.claude("Edit", edit)));
    let multi = json!({"file_path": codex, "edits": [
        {"old_string": "model = \"gpt-5\"", "new_string": "model = \"o3\""},
        {"old_string": "hooks = true", "new_string": "hooks = false"},
    ]});
    assert!(denied(&p.claude("MultiEdit", multi)));
    let update = "*** Begin Patch\n*** Update File: .codex/config.toml\n@@ [features]\n-hooks = true\n+hooks = false\n*** End Patch\n";
    assert!(denied(&p.codex_patch(update)));
    let add = format!(
        "*** Begin Patch\n*** Add File: {codex}\n+[features]\n+hooks = false\n*** End Patch\n"
    );
    assert!(denied(&p.codex_patch(&add)));
    // A file moved onto the settings file carries its content there.
    fs::write(p.file("notes.toml"), CODEX_OFF).unwrap();
    let moved = "*** Begin Patch\n*** Update File: notes.toml\n*** Move to: .codex/config.toml\n@@\n [features]\n*** End Patch\n";
    assert!(denied(&p.codex_patch(moved)));

    let opencode = p.file("opencode.json");
    fs::write(&opencode, "{\"plugin\": []}").unwrap();
    let r = p.opencode(
        "edit",
        json!({"filePath": opencode, "oldString": "[]", "newString": "[\"-openmoat\"]"}),
    );
    assert!(denied(&r), "{r:?}");
    // An empty `oldString` writes the whole file.
    let whole = json!({"filePath": p.file("opencode.jsonc"), "oldString": "", "newString": "{\"plugin\":[\"-openmoat\"]}"});
    assert!(denied(&p.opencode("edit", whole)));
    let patch = "*** Begin Patch\n*** Update File: opencode.json\n@@\n-{\"plugin\": []}\n+{\"plugin\": [\"-openmoat\"]}\n*** End Patch\n";
    assert!(denied(
        &p.opencode("apply_patch", json!({"patchText": patch}))
    ));

    let pi = p.file(".pi/settings.json");
    fs::write(&pi, "{\"extensions\": []}").unwrap();
    let edits = json!([{"oldText": "[]", "newText": "[\"!*.js\"]"}]);
    assert!(denied(&p.pi("edit", json!({"path": pi, "edits": edits}))));
}

#[test]
fn another_spelling_of_the_path_is_the_same_file() {
    let p = Project::new();
    let upper = p.file(".Codex/Config.toml");
    assert!(denied(&p.claude(
        "Write",
        json!({"file_path": upper, "content": CODEX_OFF})
    )));
    let dotted = p.file("src/../.codex/config.toml");
    assert!(denied(&p.claude(
        "Write",
        json!({"file_path": dotted, "content": CODEX_OFF})
    )));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(p.file(".codex"), p.file("cfg")).unwrap();
        let linked = p.file("cfg/config.toml");
        let r = p.claude("Write", json!({"file_path": linked, "content": CODEX_OFF}));
        assert!(denied(&r), "{r:?}");
    }
}

/// Benign changes to the same files keep the policy's verdict (`review`).
#[test]
fn other_changes_to_those_files_keep_their_verdict() {
    let p = Project::new();
    let kept = |r: (Verdict, Decision)| assert_eq!(r.0, Verdict::Review, "{r:?}");
    let codex = p.file(".codex/config.toml");
    for content in [
        "model = \"gpt-5\"\n[mcp_servers.db]\ncommand = \"db-mcp\"\n",
        "[features]\nhooks = true\nweb_search = false\n",
        "not = [valid toml",
    ] {
        kept(p.claude("Write", json!({"file_path": codex, "content": content})));
    }
    let opencode = p.file("opencode.json");
    for content in [
        json!({"$schema": "https://opencode.ai/config.json", "model": "x/y"}),
        json!({"mcp": {"db": {"type": "local", "command": ["db-mcp"]}}, "plugin": ["opencode-helper", "-other"]}),
    ] {
        kept(p.opencode(
            "write",
            json!({"filePath": opencode, "content": content.to_string()}),
        ));
    }
    let pi = p.file(".pi/settings.json");
    for content in [
        json!({"packages": ["npm:x"]}),
        json!({"extensions": ["./tools.ts", "!*.ts"]}),
    ] {
        kept(p.pi("write", json!({"path": pi, "content": content.to_string()})));
    }
    // A file of the same name elsewhere is not a host's settings file.
    kept(p.claude(
        "Write",
        json!({"file_path": p.file("docs/config.toml"), "content": CODEX_OFF}),
    ));
    let written = json!({"file_path": p.file("codex/config.toml"), "content": CODEX_OFF});
    kept(p.claude("Write", written));
}

/// A write whose outcome is not known before it runs keeps the policy's verdict.
#[test]
fn a_write_whose_outcome_is_unknown_keeps_its_verdict() {
    let p = Project::new();
    let kept = |r: (Verdict, Decision)| assert_eq!(r.0, Verdict::Review, "{r:?}");
    let codex = p.file(".codex/config.toml");
    // The file is missing, so the edit fails.
    kept(p.claude(
        "Edit",
        json!({"file_path": codex, "old_string": "a", "new_string": "b"}),
    ));
    fs::write(&codex, "[features]\nhooks = true\n").unwrap();
    // The text to replace is not in the file.
    kept(p.claude(
        "Edit",
        json!({"file_path": codex, "old_string": "x", "new_string": CODEX_OFF}),
    ));
    kept(p.codex_patch("*** Begin Patch\n*** Update File: .codex/config.toml\n@@\n-absent\n+hooks = false\n*** End Patch\n"));
    // A shell redirect sends no content.
    let shell = json!({"command": format!("printf '[features]\\nhooks=false' > {codex}")});
    kept(p.claude("Bash", shell));
    // A deny stays the policy's.
    let request = Host::ClaudeCode
        .parse_request(
            &json!({"session_id": "s", "cwd": p.file(""), "tool_name": "Write",
                "tool_input": {"file_path": codex, "content": CODEX_OFF}})
            .to_string(),
        )
        .unwrap();
    let mut deny = Decision::new(Verdict::Deny);
    deny.rules.push("kernel-self".to_owned());
    let hook = |h: Host| Some(p.hook_file(h));
    assert_eq!(tightened(&request, &p.ctx(), &hook, deny.clone()), deny);
}
