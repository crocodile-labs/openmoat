use super::handle;

fn ask(request: &str) -> String {
    handle(request.as_bytes())
}

/// The `engine` handle in a `compile` answer.
fn compile(context: &str) -> u32 {
    let policy = ask(r#"{"op":"default_policy"}"#);
    let yaml = policy
        .strip_prefix(r#"{"ok":{"policy":"#)
        .and_then(|rest| rest.strip_suffix("}}"))
        .unwrap();
    let answer = ask(&format!(
        r#"{{"op":"compile","policy":{yaml},"context":{context}}}"#
    ));
    answer
        .strip_prefix(r#"{"ok":{"engine":"#)
        .and_then(|rest| rest.strip_suffix("}}"))
        .unwrap_or_else(|| panic!("{answer}"))
        .parse()
        .unwrap()
}

const CONTEXT: &str = r#"{"home":"/h","cwd":"/p","project":"/p"}"#;

#[test]
fn info_names_the_versions() {
    assert_eq!(
        ask(r#"{"op":"info"}"#),
        format!(
            r#"{{"ok":{{"version":"{}","policy_schema_version":1,"abi":1}}}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[test]
fn compile_decide_paths_and_release() {
    let e = compile(CONTEXT);
    assert_eq!(
        ask(&format!(
            r#"{{"op":"decide","engine":{e},"action":{{"type":"fs_read","path":"~/.ssh/id_rsa"}}}}"#
        )),
        r#"{"ok":{"verdict":"deny","rules":["secrets-paths"],"reasons":["secret material: read /h/.ssh/id_rsa"],"context":[]}}"#
    );
    assert_eq!(
        ask(&format!(
            r#"{{"op":"paths","engine":{e},"action":{{"type":"shell","command":"cat a"}}}}"#
        )),
        r#"{"ok":{"paths":["/p/a"]}}"#
    );
    assert_eq!(
        ask(&format!(r#"{{"op":"release","engine":{e}}}"#)),
        r#"{"ok":{"released":true}}"#
    );
    // A released handle is never reused and names no engine.
    assert_eq!(
        ask(&format!(r#"{{"op":"release","engine":{e}}}"#)),
        r#"{"ok":{"released":false}}"#
    );
    let gone = ask(&format!(
        r#"{{"op":"decide","engine":{e},"action":{{"type":"shell","command":"ls"}}}}"#
    ));
    assert!(gone.starts_with(r#"{"error":"no engine"#), "{gone}");
    assert!(compile(CONTEXT) > e);
}

#[test]
fn a_recorded_session_tightens_the_next_decision() {
    let e = compile(CONTEXT);
    let net = r#"{"type":"net","url":"https://api.github.com"}"#;
    let facts = r#"{"links":{"/p/k":"/h/.ssh/id_rsa"}}"#;
    let recorded = ask(&format!(
        r#"{{"op":"record","engine":{e},"action":{{"type":"fs_read","path":"/p/k"}},"facts":{facts}}}"#
    ));
    let session = recorded
        .strip_prefix(r#"{"ok":{"session":"#)
        .and_then(|rest| rest.strip_suffix("}}"))
        .unwrap_or_else(|| panic!("{recorded}"));
    let after = ask(&format!(
        r#"{{"op":"decide","engine":{e},"action":{net},"session":{session}}}"#
    ));
    assert!(after.contains(r#""rules":["session-taint"]"#), "{after}");
}

/// Malformed input is an error answer, never a decision.
#[test]
fn bad_requests_are_errors() {
    let e = compile(CONTEXT);
    for request in [
        "",
        "not json",
        r#"{"op":"launch"}"#,
        r#"{"op":"info","extra":1}"#,
        r#"{"op":"compile","policy":"version: 9","context":{"home":"/h","cwd":"/p"}}"#,
        r#"{"op":"compile","policy":"version: 1","context":{"home":"h","cwd":"/p"}}"#,
        &format!(r#"{{"op":"decide","engine":{e},"action":{{"type":"shell","cmd":"ls"}}}}"#),
        &format!(
            r#"{{"op":"decide","engine":{e},"action":{{"type":"shell","command":"ls"}},"session":"[["}}"#
        ),
        &format!(
            r#"{{"op":"decide","engine":{e},"action":{{"type":"shell","command":"ls"}},"facts":{{"link":{{}}}}}}"#
        ),
    ] {
        let answer = ask(request);
        assert!(answer.starts_with(r#"{"error":"#), "{request} -> {answer}");
    }
    assert!(handle(&[0xff, 0xfe]).contains("not UTF-8"));
}
