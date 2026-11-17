//! `moat edit`, end to end, with a script standing in for the person's editor.

use crate::common::{Sandbox, USAGE, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

#[test]
fn edit_without_a_terminal_is_refused() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let out = sb.moat(&["edit"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("must be run by a person in a terminal"));
}

#[cfg(unix)]
mod with_editor {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Output;

    use crate::common::{OK, Sandbox, USAGE, output, text};

    /// Run `moat edit` as a person whose editor runs `script` on the file and
    /// who then types `answer`.
    fn edit(sb: &Sandbox, script: &str, answer: &str) -> Output {
        let editor = sb.home.join("editor.sh");
        std::fs::write(&editor, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cmd = sb.command();
        cmd.arg("edit")
            .env("MOAT_ASSUME_TTY", "1")
            .env("EDITOR", &editor);
        output(&mut cmd, Some(answer))
    }

    fn policy(sb: &Sandbox) -> String {
        std::fs::read_to_string(sb.home.join(".moat/policy.yaml")).unwrap()
    }

    fn intact(sb: &Sandbox) {
        let doctor = sb.moat(&["doctor"]);
        assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
    }

    const APPEND: &str = r#"printf '# edited by the owner\n' >> "$1""#;

    #[test]
    fn edit_shows_the_diff_and_applies_only_on_yes() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(openmoat_hosts::Host::ClaudeCode)]);
        let before = policy(&sb);

        let out = edit(&sb, APPEND, "n\n");
        let message = text(&out);
        assert_eq!(out.status.code(), Some(OK), "{message}");
        assert!(
            message.contains("+# edited by the owner") && message.contains("Apply? [y/N]"),
            "{message}"
        );
        assert!(message.contains("the policy was not changed"), "{message}");
        assert_eq!(policy(&sb), before);

        let out = edit(&sb, APPEND, "y\n");
        let message = text(&out);
        assert_eq!(out.status.code(), Some(OK), "{message}");
        assert!(
            message.contains("lock re-pinned") && message.contains("undo:"),
            "{message}"
        );
        assert!(policy(&sb).ends_with("# edited by the owner\n"));
        let backup = std::fs::read_to_string(sb.home.join(".moat/policy.yaml.bak")).unwrap();
        assert_eq!(backup, before);
        assert!(
            !sb.home.join(".moat/policy.edit.yaml").exists(),
            "draft removed"
        );
        intact(&sb);
    }

    #[test]
    fn edit_with_no_changes_does_nothing() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(openmoat_hosts::Host::ClaudeCode)]);
        let lock = std::fs::read(sb.home.join(".moat/policy.lock")).unwrap();
        let out = edit(&sb, "true", "");
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(text(&out).contains("no changes"), "{}", text(&out));
        assert_eq!(
            std::fs::read(sb.home.join(".moat/policy.lock")).unwrap(),
            lock
        );
    }

    #[test]
    fn edit_never_writes_a_policy_that_does_not_lint() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(openmoat_hosts::Host::ClaudeCode)]);
        let before = policy(&sb);
        let out = edit(
            &sb,
            r#"printf 'version: 1\ndeny:\n  - id: broken\n' > "$1""#,
            "\n",
        );
        let message = text(&out);
        assert_eq!(out.status.code(), Some(USAGE), "{message}");
        assert!(
            message.contains("does not lint") && message.contains("Edit again?"),
            "{message}"
        );
        assert_eq!(policy(&sb), before);
        intact(&sb);
    }

    #[test]
    fn edit_refuses_over_a_drifted_lock() {
        let sb = Sandbox::installed(&[&crate::hosts::dir_of(openmoat_hosts::Host::ClaudeCode)]);
        let path = sb.home.join(".moat/policy.yaml");
        let tampered = policy(&sb) + "\n# tampered\n";
        std::fs::write(&path, &tampered).unwrap();
        let out = edit(&sb, APPEND, "y\n");
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));
        assert_eq!(policy(&sb), tampered);
    }
}
