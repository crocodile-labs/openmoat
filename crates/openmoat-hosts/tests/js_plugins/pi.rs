//! OpenMoat's pi extension (`pi/integration/openmoat.js`, harness `pi.mjs`):
//! a deny blocks with the guard's reason, an allow or no answer lets the call
//! run, an ask is put to the person where pi has a screen and blocks where it
//! has none, every other outcome blocks, and the extension reports loading.

use super::{assert_one_heartbeat, entry, report};

#[test]
fn the_pi_extension_blocks_on_everything_but_allow_no_answer_and_an_approved_ask() {
    let Some(report) = report("pi", "pi/integration/openmoat.js") else {
        return;
    };

    let payload = &report["payload"];
    assert_eq!(payload["hook_event_name"], "tool_call");
    assert_eq!(payload["toolName"], "bash");
    assert_eq!(payload["input"]["command"], "ls");
    assert_eq!(payload["toolCallId"], "call-1");
    assert_eq!(payload["sessionId"], "ses-1");
    assert_eq!(payload["cwd"], report["dir"]);
    assert_eq!(payload["hasUI"], true);
    assert!(payload["platform"].is_string(), "{payload}");
    assert_eq!(report["argv"], serde_json::json!(["--host", "pi"]));

    let result = |mode| entry(&report, "results", "mode", mode);
    let outcome = |mode| result(mode)["outcome"].as_str().unwrap().to_owned();
    assert_eq!(
        outcome("deny"),
        "blocked: moat: deny [secrets-paths] — secret material"
    );
    assert_eq!(outcome("allow"), "ran");
    assert_eq!(outcome("defer"), "ran");

    // An ask is the person's to answer, in pi's dialog, with the guard's reason.
    assert_eq!(outcome("ask-approved"), "ran");
    assert_eq!(
        result("ask-approved")["asked"][0]["message"],
        "moat: ask [runs-later]"
    );
    assert_eq!(
        outcome("ask-declined"),
        "blocked: not approved: moat: ask [runs-later]"
    );
    // Without a screen nobody is asked, and the call is blocked.
    assert_eq!(result("ask-no-screen")["asked"], serde_json::json!([]));
    assert!(outcome("ask-no-screen").starts_with("blocked: OpenMoat blocked this call: "));

    let blocked = "blocked: OpenMoat blocked this call: ";
    for (mode, why) in [
        ("crash", "exited 1: boom"),
        ("garbage", "no readable answer"),
        ("deny-exit-0", "an answer it should not give"),
        ("allow-exit-3", "exited 3 with an answer it should not give"),
        ("hang", "did not answer in time"),
        ("cancelled", "the tool call was cancelled"),
        ("missing-binary", "could not run"),
    ] {
        let text = outcome(mode);
        assert!(
            text.starts_with(blocked) && text.contains(why),
            "{mode}: {text}"
        );
    }
    assert_one_heartbeat(&report, "pi");
}
