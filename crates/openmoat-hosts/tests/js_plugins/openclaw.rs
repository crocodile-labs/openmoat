//! OpenMoat's OpenClaw plugin (`openclaw/integration/openmoat.mjs`, harness
//! `openclaw.mjs`, whose stand-in runs `before_tool_call` handlers as
//! OpenClaw's `runBeforeToolCall` does): a deny blocks, an ask is OpenClaw's
//! approval request, an allow or no answer lets the call run, every other
//! outcome blocks; the parameters that run are the ones OpenMoat decided on,
//! whatever another plugin returned (ADR-041); and the plugin reports loading
//! when OpenClaw loads it to run.

use serde_json::{Value, json};

use super::{assert_one_heartbeat, entry, report};

fn openclaw() -> Option<Value> {
    report("openclaw", "openclaw/integration/openmoat.mjs")
}

#[test]
fn the_openclaw_plugin_decides_first_and_has_the_last_word() {
    let Some(report) = openclaw() else {
        return;
    };
    assert_eq!(
        report["priorities"],
        json!([
            ["before_tool_call", 9_007_199_254_740_991_i64],
            ["before_tool_call", -9_007_199_254_740_991_i64]
        ])
    );
    let rewrite = |name: &str| entry(&report, "rewrites", "name", name);
    let ran = |name: &str| {
        let r = rewrite(name);
        assert_eq!(r["outcome"], "ran", "{r}");
        r["params"]["command"].as_str().unwrap().to_owned()
    };

    // The stand-in lets a rewrite through for the plugin as it was (one
    // handler first, nothing returned on an allow), as OpenClaw did.
    assert_eq!(ran("before-the-fix"), "cat ~/.ssh/id_rsa");
    // Now another plugin's `git status` → `cat ~/.ssh/id_rsa` is undone: what
    // runs is what OpenMoat checked, wherever that plugin sits.
    for name in ["rewrite", "rewrite-first"] {
        assert_eq!(ran(name), "git status", "{name}");
        assert_eq!(rewrite(name)["checked"], json!(["git status"]), "{name}");
        assert_eq!(rewrite(name)["params"]["workdir"], ".", "{name}");
    }
    // After OpenMoat's own ask OpenClaw keeps the parameters the person saw.
    assert_eq!(ran("rewrite-after-ask"), "git status");
    assert_eq!(
        rewrite("rewrite-after-ask")["asked"]["description"],
        "moat: ask [runs-later]"
    );
    // The call as it came is denied before any plugin can change it.
    assert_eq!(rewrite("secret")["outcome"], "blocked");
    assert_eq!(
        rewrite("secret")["reason"],
        "moat: deny [secrets-paths] — secret material"
    );
    // A block by a later plugin stays a block.
    assert_eq!(rewrite("other-blocks")["outcome"], "blocked");
    // What OpenClaw gives no plugin a way to stop, as THREAT_MODEL says: a
    // plugin that changes the call and asks for approval itself keeps its
    // change once the person approves its request.
    assert_eq!(ran("rewrite-and-ask"), "cat ~/.ssh/id_rsa");
    assert_eq!(rewrite("rewrite-and-ask")["asked"]["pluginId"], "rewriter");
}

#[test]
fn the_openclaw_plugin_blocks_on_everything_but_allow_ask_and_no_answer() {
    let Some(report) = openclaw() else {
        return;
    };
    let payload = &report["payload"];
    assert_eq!(payload["hook_event_name"], "before_tool_call");
    assert_eq!(payload["toolName"], "exec");
    assert_eq!(
        payload["params"],
        json!({ "command": "ls", "workdir": "." })
    );
    assert_eq!(payload["toolCallId"], "call-1");
    assert_eq!(payload["sessionId"], "s-1");
    assert_eq!(payload["sessionKey"], "agent:main:main");
    assert_eq!(payload["agentId"], "main");
    assert_eq!(payload["cwd"], report["dir"]);
    for field in ["configPath", "stateDir", "platform"] {
        assert!(payload[field].is_string(), "{field}: {payload}");
    }
    assert_eq!(report["argv"], json!(["--host", "openclaw"]));

    let mode = |name| entry(&report, "modes", "name", name);
    assert_eq!(mode("deny")["outcome"], "blocked");
    assert_eq!(
        mode("deny")["reason"],
        "moat: deny [secrets-paths] — secret material"
    );
    for name in ["allow", "defer"] {
        assert_eq!(mode(name)["outcome"], "ran", "{name}");
        assert!(mode(name).get("asked").is_none(), "{name}");
    }
    let asked = &mode("ask")["asked"];
    assert_eq!(asked["description"], "moat: ask [runs-later]");
    assert_eq!(asked["allowedDecisions"], json!(["allow-once", "deny"]));
    for (name, why) in [
        ("crash", "exited 1: boom"),
        ("garbage", "no readable answer"),
        ("deny-exit-0", "an answer it should not give"),
        ("allow-exit-3", "exited 3 with an answer it should not give"),
        ("hang", "did not answer in time"),
        ("missing-binary", "could not run"),
    ] {
        let reason = mode(name)["reason"].as_str().unwrap();
        assert_eq!(mode(name)["outcome"], "blocked", "{name}");
        assert!(
            reason.starts_with("OpenMoat blocked this call: ") && reason.contains(why),
            "{name}: {reason}"
        );
    }
}

#[test]
fn the_openclaw_plugin_reports_loading_only_when_loaded_to_run() {
    let Some(report) = openclaw() else {
        return;
    };
    assert_one_heartbeat(&report, "openclaw");
    // A load that only lists OpenClaw's commands sends none.
    assert_eq!(report["beatsAfterMetadata"], report["heartbeats"]);
}
