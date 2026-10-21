use std::collections::HashMap;
use std::io;

use super::{Process, agent_name, walk};

fn argv(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

#[test]
fn agent_hosts_are_known_by_program_or_script() {
    for (line, agent) in [
        ("claude", "claude"),
        ("/Users/me/.local/bin/claude --resume", "claude"),
        ("/Users/me/.local/share/claude/versions/2.1.283", "claude"),
        (
            "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            "claude-code",
        ),
        ("node /usr/local/bin/codex exec", "codex"),
        (
            "/opt/codex/vendor/aarch64-apple-darwin/codex/codex",
            "codex",
        ),
        ("C:\\Tools\\Codex.exe", "codex"),
        (
            "node /home/me/.local/share/cursor-agent/versions/1.0/index.js",
            "cursor-agent",
        ),
        ("cursor-agent", "cursor-agent"),
        (
            "node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway",
            "openclaw",
        ),
        (
            "/usr/local/bin/node /Users/me/.npm-global/lib/node_modules/openclaw/dist/index.js gateway",
            "openclaw",
        ),
        ("pi", "pi"),
        ("/Users/me/.local/bin/pi --continue", "pi"),
        (
            "node /usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js",
            "pi-coding-agent",
        ),
        ("cn", "cn"),
        ("/Users/me/.npm-global/bin/cn -p hello", "cn"),
        (
            "node /usr/local/lib/node_modules/@continuedev/cli/dist/index.js",
            "@continuedev",
        ),
        ("copilot", "copilot"),
        (
            "node /usr/local/lib/node_modules/@github/copilot/index.js",
            "@github",
        ),
        ("gemini", "gemini"),
        (
            "node /usr/local/lib/node_modules/@google/gemini-cli/dist/index.js",
            "@google",
        ),
        (
            "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin) --type=utility --utility-sub-type=node.mojom.NodeService",
            "Cursor Helper",
        ),
        (
            "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper --type=utility",
            "Cursor Helper",
        ),
        ("/usr/local/bin/moat run -- claude", "moat"),
        ("/usr/local/bin/openmoat run -- claude", "openmoat"),
        (
            "C:\\scoop\\apps\\openmoat\\current\\openmoat.exe run",
            "openmoat",
        ),
    ] {
        assert_eq!(agent_name(&argv(line)).as_deref(), Some(agent), "{line}");
    }
}

#[test]
fn a_persons_shell_and_tools_are_not_agents() {
    for line in [
        "-zsh",
        "/bin/bash --login",
        "/usr/bin/login -pfl me /bin/zsh",
        "/Applications/Cursor.app/Contents/MacOS/Cursor",
        "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin) --type=utility",
        "vim --cmd x /tmp/Cursor Helper.app/Contents/MacOS/Cursor Helper",
        "/usr/local/bin/cnpm install",
        "tmux new -s claude",
        "/Users/me/moat/bin/build.sh",
        "/Users/me/src/openmoat/target/debug/deps/e2e-1234",
        "/Users/me/work/openclaw/scripts/ci/quality-gate.sh",
        "vim claude.md",
        "/usr/bin/pip install x",
        "sshd: me@pts/0",
    ] {
        assert_eq!(agent_name(&argv(line)), None, "{line}");
    }
}

fn table(rows: &[(u32, u32, &str)]) -> HashMap<u32, Process> {
    rows.iter()
        .map(|(pid, ppid, line)| {
            (
                *pid,
                Process {
                    ppid: *ppid,
                    argv: argv(line),
                },
            )
        })
        .collect()
}

fn walk_in(table: &HashMap<u32, Process>, from: u32) -> io::Result<Option<String>> {
    walk(from, |pid| {
        table
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::other("gone"))
    })
}

#[test]
fn an_agent_anywhere_above_is_found_through_wrappers() {
    let t = table(&[
        (1, 0, "/sbin/launchd"),
        (50, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2"),
        (60, 50, "-zsh"),
        (70, 60, "claude"),
        (80, 70, "/bin/zsh -c script -q /dev/null moat allow"),
        (90, 80, "script -q /dev/null moat allow"),
    ]);
    assert_eq!(walk_in(&t, 90).unwrap().as_deref(), Some("claude"));
    assert_eq!(walk_in(&t, 60).unwrap(), None, "a person's own shell");
}

#[test]
fn an_agent_as_the_container_init_is_found() {
    let t = table(&[
        (1, 0, "claude --dangerously-skip-permissions"),
        (5, 1, "sh"),
    ]);
    assert_eq!(walk_in(&t, 5).unwrap().as_deref(), Some("claude"));
}

#[test]
fn a_missing_parent_fails_but_a_hidden_init_ends_the_walk() {
    let t = table(&[(5, 4, "sh")]);
    assert!(walk_in(&t, 5).is_err(), "pid 4 cannot be read");
    let t = table(&[(5, 1, "sh")]);
    assert_eq!(walk_in(&t, 5).unwrap(), None, "pid 1 hidden");
}

#[test]
fn a_loop_in_the_table_ends() {
    let t = table(&[(5, 6, "sh"), (6, 5, "sh")]);
    assert!(walk_in(&t, 5).is_err());
    let t = table(&[(5, 5, "sh")]);
    assert_eq!(walk_in(&t, 5).unwrap(), None);
}

#[cfg(target_os = "linux")]
#[test]
fn proc_stat_and_cmdline_are_read() {
    let p =
        super::linux::parse("42 (my (odd) name) S 7 42 42 0", b"node\0/usr/bin/codex\0").unwrap();
    assert_eq!(p.ppid, 7);
    assert_eq!(p.argv, ["node", "/usr/bin/codex"]);
    let zombie = super::linux::parse("42 (claude) Z 7 42", b"").unwrap();
    assert_eq!(zombie.argv, ["claude"]);
    assert!(super::linux::parse("garbage", b"").is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn ps_lines_are_read() {
    let t = super::macos::parse("    1     0 /sbin/launchd\n  420   1 /bin/zsh -l\nbad line\n");
    assert_eq!(t[&420].ppid, 1);
    assert_eq!(t[&420].argv, ["/bin/zsh", "-l"]);
    assert_eq!(t.len(), 2);
}
