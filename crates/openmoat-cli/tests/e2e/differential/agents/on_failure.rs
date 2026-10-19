//! `"onFailure": "block"` with the pinned Claude Code: `moat init` writes it
//! only when the `claude` on `PATH` is v2.1.295 or later, and with it a hook
//! that cannot start blocks the call. With an older pin the second half is
//! reported, not asserted: that version runs the call, which is the gap the key
//! closes, and bumping the pin is a separate change.

use serde_json::{Value, json};

use super::{Agent, Home, call, session};
use crate::common::text;

/// The first Claude Code release that reads `onFailure`.
const ON_FAILURE_SINCE: (u64, u64, u64) = (2, 1, 295);

#[test]
fn real_claude_hook_failure_blocks_from_2_1_295() {
    let Some(agent) = Agent::find("onFailure: block") else {
        return;
    };
    let version = agent.version();
    let knows = version >= ON_FAILURE_SINCE;
    let home = Home::installed(&agent, |_| {});

    // init asked the pinned binary: the key is there exactly when it knows it.
    let path = home.settings();
    let mut settings: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let ours = moat_hook(&mut settings);
    assert_eq!(
        ours.get("onFailure") == Some(&json!("block")),
        knows,
        "Claude Code {version:?}: hook entry {ours}"
    );

    // A hook binary that is gone: the call must not run where the key is honoured.
    let missing = home.sb.home.join("no-such-moat");
    ours["command"] = json!(missing.to_string_lossy());
    std::fs::write(&path, settings.to_string()).unwrap();
    let id = session(8);
    let probe = json!({"command": "printf 'moat-%s\\n' ran", "description": "moat probe"});
    let said = home.claude(&agent, &id, &json!([call("Bash", probe)]), "Bash");
    let ran = text(&said).contains("moat-ran");
    if knows {
        assert!(!ran, "a failing hook let the call run: {}", text(&said));
    } else {
        eprintln!(
            "known gap: the pinned Claude Code {}.{}.{} is older than 2.1.295, so init \
             wrote no onFailure, and with the hook binary missing the call {}",
            version.0,
            version.1,
            version.2,
            if ran { "ran" } else { "did not run" }
        );
    }
}

/// OpenMoat's `PreToolUse` handler in Claude Code's settings.
fn moat_hook(settings: &mut Value) -> &mut Value {
    let shown = settings.to_string();
    settings["hooks"]["PreToolUse"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .flat_map(|entry| entry["hooks"].as_array_mut().into_iter().flatten())
        .find(|hook| hook["args"].get(0) == Some(&json!("guard")))
        .unwrap_or_else(|| panic!("no moat hook in {shown}"))
}
