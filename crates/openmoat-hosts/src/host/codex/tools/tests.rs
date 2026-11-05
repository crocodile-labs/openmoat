use openmoat_core::Action;
use serde_json::json;

use super::stdin::reads_commands;
use crate::{Host, HostError};

fn parse(tool: &str, input: serde_json::Value) -> Result<Option<Action>, HostError> {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "c1",
        "cwd": "/p",
        "tool_name": tool,
    });
    payload["tool_input"] = input;
    Host::Codex
        .parse_request(&payload.to_string())
        .map(|r| r.action)
}

/// Starting a program that reads its commands from its input is held, since
/// `write_stdin` types into it unhooked; one given its commands is not.
#[test]
fn a_start_that_reads_commands_from_input_is_told_from_one_that_does_not() {
    for command in [
        "bash",
        "bash -i",
        "bash -l",
        "sh -s arg",
        "zsh --norc",
        "/bin/bash",
        "python3",
        "python3.12",
        "python3 -i x.py",
        "python3 -",
        "node",
        "node -i",
        "irb",
        "perl",
        "php -a",
        "sqlite3",
        "sqlite3 app.db",
        "psql -h db -U me",
        "mysql -u root",
        "ssh host",
        "ssh -p 22 -i key host",
        "vim notes.txt",
        "ed file",
        "tmux",
        "tmux new -s x",
        "script -q /dev/null",
        "docker run -it alpine sh",
        "kubectl exec -it pod -- sh",
        "env FOO=1 bash",
        "sudo -i",
        "sudo -u me bash",
        "cd /p && bash",
        "true; python3",
        "FOO=1 node",
        "deno",
        "bun repl",
        "su",
    ] {
        assert!(reads_commands(command).is_some(), "{command}");
    }
    for command in [
        "bash script.sh",
        "bash -lc 'git status'",
        "sh -c 'echo hi'",
        "bash -euxc 'x'",
        "bash --version",
        "python3 x.py",
        "python3 -c 'print(1)'",
        "python3 -m pytest",
        "node x.js",
        "node -e '1'",
        "perl -pe 's/a/b/' f",
        "perl -i -pe 's/a/b/' f",
        "ruby x.rb",
        "php -r 'echo 1;'",
        "sqlite3 app.db 'select 1'",
        "psql -c 'select 1'",
        "psql -f x.sql",
        "mysql -e 'select 1'",
        "ssh host ls",
        "ssh -N -L 1:a:2 host",
        "emacs --batch -l x.el",
        "tmux ls",
        "tmux new -d -s x",
        "screen -dmS x cmd",
        "script -q /dev/null cmd",
        "docker run alpine ls",
        "docker run -d -i alpine",
        "kubectl get pods",
        "echo x | bash",
        "bash < x.sh",
        "python3 <<EOF\nprint(1)\nEOF",
        "bash &",
        "command -v bash",
        "git status",
        "cargo test",
        "deno run x.ts",
        "su -c id",
        "nohup bash",
    ] {
        assert_eq!(reads_commands(command), None, "{command}");
    }
}

#[test]
fn codex_holds_such_a_start_and_names_the_program() {
    match parse("Bash", json!({ "command": "bash -i" })).unwrap() {
        Some(Action::Unchecked { action, reason }) => {
            assert_eq!(
                *action,
                Action::Shell {
                    command: "bash -i".to_owned()
                }
            );
            assert!(reason.contains("`bash`") && reason.contains("write_stdin"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        parse("Bash", json!({ "command": "bash x.sh" })).unwrap(),
        Some(Action::Shell {
            command: "bash x.sh".to_owned()
        })
    );
}

/// Codex's `read_mcp_resource` and `view_image` are checked as what they read.
#[test]
fn resource_and_image_reads_are_checked() {
    let resource = parse(
        "read_mcp_resource",
        json!({ "server": "filesystem", "uri": "file:///h/.ssh/id_rsa" }),
    )
    .unwrap();
    match resource {
        Some(Action::McpTool { name, reads, .. }) => {
            assert_eq!(name, "mcp__filesystem__read_resource");
            assert_eq!(reads, ["/h/.ssh/id_rsa"]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        parse("view_image", json!({ "path": "shot.png" })).unwrap(),
        Some(Action::FsRead {
            path: "shot.png".to_owned()
        })
    );
    assert_eq!(
        parse("view_image", json!({ "path": "https://x.test/a.png" })).unwrap(),
        Some(Action::Fetch {
            url: "https://x.test/a.png".to_owned()
        })
    );
    assert!(matches!(
        parse("view_image", json!({ "path": "file:rel.png" })),
        Err(HostError::MalformedArguments { .. })
    ));
    assert!(matches!(
        parse("view_image", json!({})),
        Err(HostError::MissingField { .. })
    ));
    assert_eq!(parse("list_mcp_resources", json!({})).unwrap(), None);
}
