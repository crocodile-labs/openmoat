//! What an MCP server can reach, shown by what happened on disk: a server
//! (`mcp_boundary/escaping_server.py`) that tries to read a planted secret by a
//! relative path, by an absolute path and through a symbolic link out of its
//! folder, and to create a file outside the project. Its tools take no
//! arguments, so the hook and the gateway, which read a call's arguments, have
//! nothing to refuse: only the sandbox of `openmoat mcp proxy --sandbox` stands
//! between the server and the files. Without `--sandbox` the same calls reach
//! them, which shows the server really tries.
//!
//! The home lives below the target directory, outside every read root, so the
//! secret is out of reach only if the sandbox holds. Linux and macOS alike; on
//! CI a sandbox that does not start fails the test instead of skipping it.

use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{Value, json};

use crate::common::{OK, Sandbox, output, stderr, stdout, text};

const SERVER: &str = include_str!("mcp_boundary/escaping_server.py");
const SECRET: &str = "OPENMOAT-MCP-BOUNDARY-FAKE-SECRET";
const NOTES: &str = "OPENMOAT-MCP-BOUNDARY-NOTES";
/// What `openmoat run` prints once the server is in its sandbox.
const IN_SANDBOX: &str = "in a sandbox made from the policy";
/// What `openmoat run` adds to that line when it started the Isolated tier.
const ISOLATED: &str = "it sees only the project";
/// The tools that go for the secret.
const READS: [&str; 3] = ["relative", "absolute", "through_link"];
/// Every tool in the order the sessions call them; the id is the position.
const TOOLS: [&str; 5] = [
    "control",
    "relative",
    "absolute",
    "through_link",
    "write_outside",
];

struct Boundary {
    sb: Sandbox,
    project: PathBuf,
    canary: PathBuf,
    escaped: PathBuf,
}

impl Boundary {
    /// An installed home with the server in its project and its definitions
    /// and tools accepted, as a person would.
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let sb = Sandbox::installed_in(parent, &[".claude"]);
        let project = sb.project();
        let tools = project.join("tools");
        std::fs::create_dir_all(tools.join("data")).unwrap();
        std::fs::write(tools.join("escaping_server.py"), SERVER).unwrap();
        std::fs::write(tools.join("notes.txt"), NOTES).unwrap();
        let canary = sb.home.join("canary/secret.txt");
        std::fs::create_dir_all(canary.parent().unwrap()).unwrap();
        std::fs::write(&canary, SECRET).unwrap();
        std::os::unix::fs::symlink(&canary, tools.join("data/link")).unwrap();
        let escaped = sb.home.join("escaped.txt");
        let boundary = Self {
            sb,
            project,
            canary,
            escaped,
        };
        for (name, sandbox) in [("boundary-sandboxed", true), ("boundary-open", false)] {
            let line = boundary.proxy_line(sandbox);
            let args: Vec<&str> = line.iter().map(String::as_str).collect();
            boundary.sb.define_wrapped(name, &args);
        }
        boundary.sb.accept_mcp();
        // Listed without the sandbox, so a system that cannot start one still
        // gets here and the test can say so.
        let held = boundary.proxy(false, &[list()]);
        assert!(stdout(&held).contains(r#""tools":[]"#), "{}", text(&held));
        let accepted = boundary.sb.moat_approving(&["mcp", "accept", "boundary"]);
        assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
        boundary
    }

    /// What follows `mcp proxy` to start the server.
    fn proxy_line(&self, sandbox: bool) -> Vec<String> {
        let script = self.project.join("tools/escaping_server.py");
        let mut line = vec!["--server".to_owned(), "boundary".to_owned()];
        if sandbox {
            line.push("--sandbox".to_owned());
        }
        line.extend(["--", "python3", "-I"].map(str::to_owned));
        line.push(script.to_string_lossy().into_owned());
        line
    }

    /// One session of `lines`, started in the project as an agent would.
    fn proxy(&self, sandbox: bool, lines: &[String]) -> Output {
        let input: String = lines.iter().flat_map(|l| [l.as_str(), "\n"]).collect();
        output(
            self.sb
                .command()
                .current_dir(&self.project)
                .args(["mcp", "proxy"])
                .args(self.proxy_line(sandbox)),
            Some(&input),
        )
    }

    /// Every tool called once, each let through by the hook first.
    fn call_every_tool(&self, sandbox: bool) -> Output {
        let session = if sandbox { "sandboxed" } else { "open" };
        let lines: Vec<String> = TOOLS
            .iter()
            .zip(1_u64..)
            .map(|(tool, id)| {
                self.hook_lets_through(session, tool);
                json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": tool, "arguments": {}}})
                .to_string()
            })
            .collect();
        self.proxy(sandbox, &lines)
    }

    /// The hook's decision the gateway matches a call with: nothing in the
    /// arguments names a file, so it does not deny.
    fn hook_lets_through(&self, session: &str, tool: &str) {
        let payload = json!({
            "session_id": session, "cwd": self.project.to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": format!("mcp__boundary__{tool}"),
            "tool_input": {}, "tool_use_id": format!("{session}-{tool}"),
            "permission_mode": "default"
        });
        let out = self.sb.guard("claude-code", &payload.to_string());
        assert_ne!(out.status.code(), Some(2), "{tool}: {}", text(&out));
    }
}

fn list() -> String {
    json!({"jsonrpc": "2.0", "id": 100, "method": "tools/list"}).to_string()
}

/// The text `tool` answered with among what the host got.
fn answer_of(host: &str, tool: &str) -> String {
    let id = TOOLS.iter().position(|t| *t == tool).unwrap() + 1;
    let answer = host
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|m| m["id"] == id)
        .unwrap_or_else(|| panic!("no answer from {tool}: {host}"));
    answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{tool} did not answer with text: {answer}"))
        .to_owned()
}

/// Under `--sandbox` the server's own attempts fail at the operating system:
/// the secret stays where it is, unread, and no file appears outside the project.
#[test]
fn the_sandbox_holds_a_server_that_tries_to_leave_its_folder() {
    let boundary = Boundary::new();
    let out = boundary.call_every_tool(true);
    let shown = text(&out);
    if !stderr(&out).contains(IN_SANDBOX) {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must run the server in the sandbox: {shown}"
        );
        eprintln!("skipped: `openmoat run` cannot sandbox here: {shown}");
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    let host = stdout(&out);
    // The server ran, in the sandbox, and read what is its own.
    assert_eq!(answer_of(&host, "control"), NOTES, "{shown}");
    // The side effects, whatever anyone answered.
    assert!(!shown.contains(SECRET), "the secret came back: {shown}");
    assert_eq!(std::fs::read_to_string(&boundary.canary).unwrap(), SECRET);
    assert!(!boundary.escaped.exists(), "written outside: {shown}");
    // Each attempt reached the file system and was refused there. The
    // Lightweight tier (macOS, Linux without bubblewrap) denies a path that is there; the Isolated tier,
    // `openmoat run`'s default on Linux (ADR-080), does not mount the home at
    // all, so the same paths are not there, and Landlock denies the rest.
    let refusals: &[&str] = if stderr(&out).contains(ISOLATED) {
        &["refused: PermissionError", "refused: FileNotFoundError"]
    } else {
        &["refused: PermissionError"]
    };
    for tool in READS.iter().chain(&["write_outside"]) {
        let answer = answer_of(&host, tool);
        assert!(
            refusals.contains(&answer.as_str()),
            "{tool} answered {answer}: {shown}"
        );
    }
}

/// Without `--sandbox` the very same calls reach the files: the hook sees only
/// a call's arguments, and these name nothing (`docs/LIMITS.md`).
#[test]
fn without_the_sandbox_the_same_calls_reach_the_files() {
    let boundary = Boundary::new();
    let out = boundary.call_every_tool(false);
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    let host = stdout(&out);
    for tool in READS {
        assert_eq!(answer_of(&host, tool), SECRET, "{tool}: {shown}");
    }
    assert_eq!(answer_of(&host, "write_outside"), "wrote", "{shown}");
    assert_eq!(
        std::fs::read_to_string(&boundary.escaped).unwrap(),
        "ESCAPED"
    );
}
