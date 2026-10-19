//! The checks of #574–#577 under the real, pinned Claude Code with OpenMoat's
//! hook installed, where the rest of the suite feeds `moat guard` payloads it
//! wrote itself. `moat init` runs with the pinned `claude` first on `PATH`, so
//! the hook entry is the one a person with that version gets (`onFailure` only
//! from v2.1.295). Each scenario is one `claude -p` session in a git project
//! inside a throwaway home: the local fake Anthropic API
//! (`tests/differential/fake_api.py --calls`) asks for a fixed sequence of tool
//! calls, Claude Code runs its own `PreToolUse` hook (`moat guard`) and its own
//! permission flow, and the test reads what OpenMoat recorded for the session
//! and what the call left behind. Nothing leaves the machine: the API is on
//! loopback and every other request Claude Code makes goes to a dead proxy.
//!
//! Unlike [`super::claude`], this runs without `--bare`, which skips hooks.
//! The binary is `MOAT_CLAUDE_BIN` only; without it each test skips visibly,
//! except in CI's `standard tier` job, which fails it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

use super::claude::{FakeApi, PERL, claude_binary, python};
use crate::common::{OK, Sandbox, json, output, skip_without_host_binary, text};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod in_run;
mod on_failure;
mod scenarios;

/// Where Claude Code's own requests that are not for the fake API go: a port
/// nothing listens on, so none of them leaves the machine.
const DEAD_PROXY: &str = "http://127.0.0.1:9";

/// A file of this repository, by its path from the root.
fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// The pinned Claude Code and the python that runs the fake API and MCP server.
pub struct Agent {
    claude: PathBuf,
    python: PathBuf,
}

impl Agent {
    /// Both, or `None` after a visible skip (a failure in CI's standard tier).
    fn find(what: &str) -> Option<Self> {
        if let (Some(claude), Some(python)) = (claude_binary(), python()) {
            return Some(Self { claude, python });
        }
        skip_without_host_binary(&format!(
            "{what} under the real Claude Code (set MOAT_CLAUDE_BIN and MOAT_FAKE_API)"
        ));
        None
    }

    /// `(major, minor, patch)` from `claude --version` (`2.1.290 (Claude Code)`).
    fn version(&self) -> (u64, u64, u64) {
        let out = Command::new(&self.claude)
            .arg("--version")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("claude --version");
        let shown = text(&out);
        let first = shown.split_whitespace().next().unwrap_or_default();
        let mut parts = first.split('.').map(|p| {
            p.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("claude --version: {shown}"))
        });
        let mut next = || {
            parts
                .next()
                .unwrap_or_else(|| panic!("claude --version: {shown}"))
        };
        (next(), next(), next())
    }
}

/// A throwaway home with Claude Code, OpenMoat installed for it, and a git
/// project (`~/repo`, pushed to `~/origin.git`) the sessions run in.
pub struct Home {
    sb: Sandbox,
    project: PathBuf,
}

impl Home {
    /// `before` prepares the home (an MCP server in `~/.claude.json`), then
    /// `moat init --yes` runs with the pinned `claude` first on `PATH` and no
    /// version override, so it asks that binary which hook keys it knows.
    fn installed(agent: &Agent, before: impl FnOnce(&Path)) -> Self {
        let sb = Sandbox::bare(&[".claude"]);
        before(&sb.home);
        let dir = agent.claude.parent().expect("claude's directory");
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&inherited));
        let out = output(
            sb.command()
                .env_remove("MOAT_CLAUDE_CODE_VERSION")
                .env("PATH", std::env::join_paths(path).unwrap())
                .args(["init", "--yes"]),
            None,
        );
        assert_eq!(out.status.code(), Some(OK), "moat init: {}", text(&out));
        let project = crate::push::repo(&sb);
        Self { sb, project }
    }

    /// The settings file `moat init` wrote the hook into.
    fn settings(&self) -> PathBuf {
        self.sb.home.join(".claude/settings.json")
    }

    /// One `claude -p` session `session` in the project. The fake API asks for
    /// `calls` (`[{"name": "Bash", "input": {…}}, …]`) one after another;
    /// `allowed` is `--allowedTools`, what Claude Code runs without asking.
    fn claude(&self, agent: &Agent, session: &str, calls: &Value, allowed: &str) -> Output {
        let script = repo_file("tests/differential/fake_api.py");
        let calls = calls.to_string();
        let api = FakeApi::spawn(&agent.python, &script, &["--calls", &calls]);
        // A made-up key of the right shape, so Claude Code takes it as an API key.
        let key = format!("sk\x2dant\x2dapi03\x2d{}", "moatfake".repeat(4));
        let out = Command::new(PERL)
            // perl's alarm bounds a hung run; claude execs in its place.
            .args(["-e", "alarm 150; exec @ARGV"])
            .arg(&agent.claude)
            .args(["-p", "run it", "--permission-mode", "default"])
            .args(["--allowedTools", allowed, "--session-id", session])
            .current_dir(&self.project)
            .env_clear()
            .env(
                "PATH",
                format!("{}/bin:/usr/bin:/bin", self.project.display()),
            )
            .env("HOME", &self.sb.home)
            .env("ANTHROPIC_API_KEY", key)
            .env(
                "ANTHROPIC_BASE_URL",
                format!("http://127.0.0.1:{}", api.port),
            )
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("HTTPS_PROXY", DEAD_PROXY)
            .env("HTTP_PROXY", DEAD_PROXY)
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .env("DISABLE_AUTOUPDATER", "1")
            .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
            .stdin(Stdio::null())
            .output()
            .expect("running claude");
        drop(api);
        out
    }

    /// What OpenMoat recorded for the Claude Code hook in `session`, oldest first.
    fn rows(&self, session: &str) -> Vec<Value> {
        let shown = self
            .sb
            .moat(&["show", "--session", session, "--format", "json"]);
        json(&shown)
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["host"] == "claude-code")
            .cloned()
            .collect()
    }

    /// The row of `session` for `tool`. A missing row means the hook never
    /// ran for that call: the failure shows what Claude Code said.
    fn decided(&self, session: &str, tool: &str, said: &Output) -> Value {
        let rows = self.rows(session);
        rows.iter()
            .find(|row| row["tool"] == tool)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no claude-code row for {tool} in session {session} (did the hook run?)\n\
                     rows: {rows:?}\nclaude: {}",
                    text(said)
                )
            })
    }
}

/// A session id Claude Code accepts (`--session-id` takes a UUID), one per scenario.
fn session(n: u8) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

/// Whether `row` names `rule` among its rules.
fn has_rule(row: &Value, rule: &str) -> bool {
    row["rules"]
        .as_array()
        .is_some_and(|rules| rules.iter().any(|r| r == rule))
}

/// `row`'s verdict (`allow`, `defer`, `ask`, `deny`).
fn decided_verdict(row: &Value) -> &str {
    row["verdict"].as_str().unwrap_or_default()
}

/// `row`'s reasons as one string, for assertions.
fn reasons(row: &Value) -> String {
    row["reasons"].to_string()
}

/// A `{"name": …, "input": …}` call for the fake API.
fn call(name: &str, input: Value) -> Value {
    let mut call = serde_json::json!({ "name": name });
    call["input"] = input;
    call
}
