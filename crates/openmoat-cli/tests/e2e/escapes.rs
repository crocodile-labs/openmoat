//! Terminal escapes in what an agent sends never reach the person's terminal:
//! a logged command could otherwise set the window title or write the
//! clipboard (OSC 52) when someone reads it with `moat show`.

use std::process::Output;

use crate::common::{Sandbox, bash_payload, output};

/// Writes "fake" to the clipboard, then sets the window title.
const ESCAPES: &str = "\x1b]52;c;ZmFrZQ==\x07\x1b]0;title\x07";

fn assert_clean(what: &str, out: &Output) {
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let controls: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| (b.is_ascii_control() && *b != b'\n') || *b == 0x7f)
            .collect();
        assert!(
            controls.is_empty(),
            "{what} {stream} carries control bytes {controls:?}: {}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn logged_escapes_are_shown_as_question_marks() {
    let sb = Sandbox::installed(&[".claude"]);
    let ask = format!("npm install left-pad{ESCAPES}");
    let deny = format!("cat ~/.ssh/id_rsa{ESCAPES}");
    for command in [&ask, &deny] {
        let guard = sb.guard("claude-code", &bash_payload("s1", &sb.project(), command));
        assert_clean("moat guard", &guard);
    }

    let show = sb.moat(&["show"]);
    assert_clean("moat show", &show);
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(
        shown.contains("left-pad?]52;c;ZmFrZQ==??]0;title?"),
        "{shown}"
    );
    for args in [
        &["show", "1"][..],
        &["show", "2"],
        &["status"],
        &["replay"],
        &["policy", "check", &ask],
        &["policy", "check", &deny],
    ] {
        assert_clean(&format!("moat {}", args[0]), &sb.moat(args));
    }
    assert_clean("moat", &output(&mut sb.command(), Some("")));
    assert_clean(
        "moat allow --last",
        &sb.moat_approving(&["allow", "--last"]),
    );
}
