//! OpenMoat's OpenCode plugin (`src/host/opencode/integration/openmoat.js`)
//! run under Node against a stand-in for `openmoat guard` (`opencode.mjs`),
//! as OpenCode 1 and as OpenCode 2 load it: a deny throws the guard's reason,
//! an allow or no answer lets the call run, an ask is a block on OpenCode 1
//! and OpenCode's own prompt on OpenCode 2, every other outcome throws, the
//! checked call cannot change afterwards, not by a plugin that runs later
//! either, and each way of loading it reports loading (ADR-042).

use serde_json::Value;

fn opencode() -> Option<Value> {
    super::report("opencode", "opencode/integration/openmoat.js")
}

fn outcome<'a>(report: &'a Value, mode: &str) -> &'a str {
    report["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["mode"] == mode)
        .and_then(|r| r["outcome"].as_str())
        .unwrap_or_else(|| panic!("no result for {mode}: {report}"))
}

#[test]
fn the_opencode_plugin_blocks_on_everything_but_allow_and_no_answer() {
    let Some(report) = opencode() else {
        return;
    };

    // What the guard is given: the call, the instance and the MCP servers.
    let payload = &report["payload"];
    assert_eq!(payload["hook_event_name"], "tool.execute.before");
    assert_eq!(payload["tool"], "bash");
    assert_eq!(payload["sessionID"], "ses_1");
    assert_eq!(payload["callID"], "call_1");
    assert_eq!(payload["args"]["command"], "cat ~/.ssh/id_rsa");
    assert_eq!(payload["directory"], report["dir"]);
    assert_eq!(payload["worktree"], report["dir"]);
    assert_eq!(payload["mcpServers"], serde_json::json!(["github"]));
    assert!(payload["platform"].is_string(), "{payload}");
    assert_eq!(report["argv"], serde_json::json!(["--host", "opencode"]));
    assert_eq!(
        report["cwdIsDirectory"], true,
        "the guard runs in the directory"
    );

    assert_eq!(
        outcome(&report, "deny"),
        "threw: moat: deny [secrets-paths] — secret material"
    );
    assert_eq!(outcome(&report, "allow"), "ran");
    assert_eq!(outcome(&report, "defer"), "ran");
    let blocked = "threw: OpenMoat blocked this call: ";
    for (mode, why) in [
        ("ask", "an answer it should not give"),
        ("crash", "exited 1: boom"),
        ("garbage", "no readable answer"),
        ("deny-exit-0", "an answer it should not give"),
        ("allow-exit-3", "exited 3 with an answer it should not give"),
        ("hang", "did not answer in time"),
        ("missing-binary", "could not run"),
        ("no-input", "could not run"),
    ] {
        let text = outcome(&report, mode);
        assert!(
            text.starts_with(blocked) && text.contains(why),
            "{mode}: {text}"
        );
    }
    // The checked arguments are frozen, nested objects too.
    for result in report["results"].as_array().unwrap() {
        assert_eq!(result["frozen"], true, "{result}");
    }
}

/// OpenCode 1's `server` and OpenCode 2's `setup` each report loading once;
/// a plugin pointing at a missing binary loads without one.
#[test]
fn the_opencode_plugin_reports_loading_from_both_apis() {
    let Some(report) = opencode() else {
        return;
    };
    let beat = serde_json::json!([["--heartbeat", "--host", "opencode"]]);
    assert_eq!(report["heartbeats"]["server"], beat, "{report}");
    assert_eq!(report["heartbeats"]["setup"], beat, "{report}");
}

#[test]
fn on_opencode_2_the_plugin_checks_asks_and_pins_the_call() {
    let Some(report) = opencode() else {
        return;
    };
    let v2 = &report["v2"];

    // What the guard is given: OpenCode 2's event, the instance and the MCP servers.
    let payload = &v2["payload"];
    assert_eq!(payload["hook_event_name"], "execute.before");
    assert_eq!(payload["tool"], "shell");
    assert_eq!(payload["sessionID"], "ses_2");
    assert_eq!(payload["agent"], "build");
    assert_eq!(payload["messageID"], "msg_1");
    assert_eq!(payload["callID"], "call_deny");
    assert_eq!(payload["input"]["command"], "cat ~/.ssh/id_rsa");
    assert_eq!(payload["directory"], report["dir"]);
    assert_eq!(payload["worktree"], report["dir"]);
    assert_eq!(payload["mcpServers"], serde_json::json!(["github"]));
    assert!(payload["platform"].is_string(), "{payload}");

    let v2_outcome = |mode| outcome(v2, mode);
    assert_eq!(
        v2_outcome("deny"),
        "threw: moat: deny [secrets-paths] — secret material"
    );
    for mode in ["allow", "defer", "ask-approved", "minimal-allow"] {
        assert_eq!(v2_outcome(mode), "ran", "{mode}");
    }
    assert!(v2_outcome("ask-rejected").starts_with("threw: "), "{v2}");
    let blocked = "threw: OpenMoat blocked this call: ";
    for (mode, why) in [
        ("crash", "exited 1: boom"),
        ("garbage", "no readable answer"),
        ("deny-exit-0", "an answer it should not give"),
        ("hang", "did not answer in time"),
        ("missing-binary", "could not run"),
        ("minimal-ask", "openmoat allow --last"),
    ] {
        let text = v2_outcome(mode);
        assert!(
            text.starts_with(blocked) && text.contains(why),
            "{mode}: {text}"
        );
    }
    // Every call's tool and input are pinned to what was checked.
    for result in v2["results"].as_array().unwrap() {
        assert_eq!(result["frozen"], true, "{result}");
    }

    asks_reach_the_person(v2);
    later_plugins_cannot_change_the_call(&v2["later"]);
}

/// An ask is put to the person as OpenCode's `openmoat` permission, made an
/// ask whatever the rules say (here they allow), with OpenMoat's reason.
fn asks_reach_the_person(v2: &Value) {
    let asked = v2["asked"].as_array().unwrap();
    assert_eq!(asked.len(), 2, "{asked:?}");
    for ask in asked {
        assert_eq!(ask["action"], "openmoat", "{ask}");
        assert_eq!(ask["effect"], "ask", "{ask}");
        assert_eq!(ask["resources"], serde_json::json!(["write"]), "{ask}");
        assert_eq!(ask["source"]["type"], "tool", "{ask}");
        assert!(
            ask["message"]
                .as_str()
                .unwrap_or_default()
                .contains("runs-later"),
            "{ask}"
        );
    }
}

/// A plugin after OpenMoat's that rewrites the command, replaces the input or
/// changes the tool fails, and the call stays the one checked.
fn later_plugins_cannot_change_the_call(later: &Value) {
    for name in ["rewrite-command", "replace-input", "change-tool"] {
        let case = &later[name];
        assert!(
            case["outcome"]
                .as_str()
                .unwrap_or_default()
                .starts_with("threw: "),
            "{name}: {case}"
        );
        assert_eq!(case["checked"]["tool"], "shell", "{name}: {case}");
        assert_eq!(case["checked"]["command"], "git status", "{name}: {case}");
        assert_eq!(case["runs"]["tool"], "shell", "{name}: {case}");
        assert_eq!(case["runs"]["command"], "git status", "{name}: {case}");
    }
    let shell = &later["shell-rewrite"];
    assert!(
        shell["outcome"]
            .as_str()
            .unwrap_or_default()
            .starts_with("threw: "),
        "{shell}"
    );
    assert_eq!(shell["runs"], "git status", "{shell}");
    assert_eq!(
        shell["cwd"], "/resolved",
        "OpenCode's own shell tool still sets it: {shell}"
    );
    // A shell OpenMoat did not check (the person's `!` command) is not
    // pinned: the later hook still changes it, as without OpenMoat.
    assert_eq!(shell["unchecked"], "cat ~/.ssh/id_rsa", "{shell}");
}
