//! The harness every end-to-end module shares: an isolated home and the real
//! `moat` binary.
//!
//! Each command runs with the environment cleared except `PATH`, `HOME`,
//! `USERPROFILE` and (Windows) `SYSTEMROOT`, so nothing from the developer's machine (a real `~/.moat`,
//! `CLAUDE_CONFIG_DIR`, a terminal) leaks into a test.

use std::io::{BufRead as _, BufReader, ErrorKind, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

// The exit codes of `moat` (ADR-004, `src/exit.rs`).
/// Success, or verdict `allow`.
pub const OK: i32 = 0;
/// The agent `moat run` started failed; never a verdict.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub const FAILED: i32 = 1;
/// Verdict `deny`; also every error in `moat guard`.
pub const DENY: i32 = 2;
/// Verdict `ask` that `moat policy check` could not resolve.
pub const ASK: i32 = 3;
/// Usage or configuration error from a command a person ran.
pub const USAGE: i32 = 64;

/// The Claude Code version every command is told is installed: one that knows
/// `onFailure`, so `moat init` writes it.
pub const CLAUDE_CODE_VERSION: &str = "2.1.295 (Claude Code)";

/// A throwaway home directory.
pub struct Sandbox {
    _dir: TempDir,
    pub home: PathBuf,
}

impl Sandbox {
    /// A home containing the given host configuration directories
    /// (`.claude`, `.codex`, `.cursor`); nothing is installed.
    pub fn bare(host_dirs: &[&str]) -> Self {
        Self::bare_in(&std::env::temp_dir(), host_dirs)
    }

    /// [`Sandbox::bare`] in a temporary directory below `parent`.
    pub fn bare_in(parent: &Path, host_dirs: &[&str]) -> Self {
        let dir = tempfile::tempdir_in(parent).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        for host_dir in host_dirs {
            std::fs::create_dir_all(home.join(host_dir)).unwrap();
        }
        Self { _dir: dir, home }
    }

    /// `bare(host_dirs)` followed by a successful `moat init`.
    pub fn installed(host_dirs: &[&str]) -> Self {
        Self::installed_in(&std::env::temp_dir(), host_dirs)
    }

    /// [`Sandbox::installed`] with the policy's catch-all set back to `ask`, re-pinned
    /// as a person would: the strict choice ADR-025 keeps, under which a call no rule
    /// matches asks. The approval tests use it to reach `moat allow` and the home screen.
    pub fn installed_asking(host_dirs: &[&str]) -> Self {
        let sb = Self::installed(host_dirs);
        let policy = sb.home.join(".moat/policy.yaml");
        let text_now = std::fs::read_to_string(&policy).unwrap();
        assert!(text_now.contains("\"*\": defer"), "{text_now}");
        std::fs::write(&policy, text_now.replacen("\"*\": defer", "\"*\": ask", 1)).unwrap();
        let out = sb.moat_as_person(&["doctor", "--accept"]);
        assert!(text(&out).contains("re-pinned"), "{}", text(&out));
        sb
    }

    /// [`Sandbox::installed`] in a temporary directory below `parent`.
    pub fn installed_in(parent: &Path, host_dirs: &[&str]) -> Self {
        let sb = Self::bare_in(parent, host_dirs);
        let out = sb.moat(&["init", "--yes"]);
        assert_eq!(out.status.code(), Some(0), "openmoat init: {}", text(&out));
        sb
    }

    /// A git project inside the home, created on first use.
    pub fn project(&self) -> PathBuf {
        let project = self.home.join("proj");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        project
    }

    /// The command with the isolated environment; callers add arguments.
    pub fn command(&self) -> Command {
        self.command_at(Path::new(env!("CARGO_BIN_EXE_openmoat")))
    }

    /// [`Sandbox::command`] running the binary at `program` (a copy or a link).
    pub fn command_at(&self, program: &Path) -> Command {
        self.configure(Command::new(program))
    }

    /// `cmd` with [`Sandbox::command`]'s environment, started in the home
    /// directory: the test's own directory is inside this repository, which
    /// holds the built binary, and `init` refuses a binary inside the project.
    pub fn configure(&self, mut cmd: Command) -> Command {
        cmd.current_dir(&self.home)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            // Debug builds take Claude Code's version from here instead of
            // running the `claude` on `PATH` (`install/claude_version.rs`).
            .env("MOAT_CLAUDE_CODE_VERSION", CLAUDE_CODE_VERSION)
            // and OpenCode's from here instead of running the `opencode` on
            // `PATH` (`install/host_version.rs`); empty is none found
            .env("MOAT_OPENCODE_VERSION", "");
        // Windows sockets cannot start without it (`moat proxy` binds one).
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", root);
        }
        cmd
    }

    /// Run `moat` with no input.
    pub fn moat(&self, args: &[&str]) -> Output {
        output(self.command().args(args), None)
    }

    /// Run `moat` with `stdin` as its input (a hook payload).
    pub fn moat_stdin(&self, args: &[&str], stdin: &str) -> Output {
        output(self.command().args(args), Some(stdin))
    }

    /// Run `moat` as a person at a terminal would (`MOAT_ASSUME_TTY`, honoured
    /// by debug builds only).
    pub fn moat_as_person(&self, args: &[&str]) -> Output {
        output(self.command().args(args).env("MOAT_ASSUME_TTY", "1"), None)
    }

    /// As [`Sandbox::moat_as_person`], answering `y` to the question the
    /// command asks (`moat allow --last` asks before it approves).
    pub fn moat_approving(&self, args: &[&str]) -> Output {
        output(
            self.command().args(args).env("MOAT_ASSUME_TTY", "1"),
            Some("y\n"),
        )
    }

    /// Run the hook for `host` with `payload`.
    pub fn guard(&self, host: &str, payload: &str) -> Output {
        self.moat_stdin(&["guard", "--host", host], payload)
    }

    /// The verdict and reason the Claude Code hook gives one Bash `command` in `cwd`.
    pub fn guard_bash(&self, session: &str, cwd: &Path, command: &str) -> (String, String) {
        verdict_and_reason(&self.guard("claude-code", &bash_payload(session, cwd, command)))
    }

    /// Opt the host sandboxes into `moat proxy` on a free loopback port
    /// (`sandbox.proxy_port`), so no test meets a proxy the developer runs;
    /// re-pinned and the host sandboxes synced as a person would. Returns the port.
    pub fn use_free_proxy_port(&self) -> u16 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Edited as YAML, not as text: a Windows checkout has CRLF line endings.
        let path = self.home.join(".moat/policy.yaml");
        let mut policy: serde_json::Value =
            openmoat_core::yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        policy["sandbox"]["proxy_port"] = port.into();
        std::fs::write(&path, openmoat_core::yaml::to_string(&policy).unwrap()).unwrap();
        let accepted = self.moat_as_person(&["doctor", "--accept"]);
        assert!(text(&accepted).contains("re-pinned"), "{}", text(&accepted));
        let synced = self.moat_as_person(&["sandbox", "sync"]);
        assert_eq!(synced.status.code(), Some(0), "{}", text(&synced));
        port
    }

    /// Let `moat proxy` serve requests without a session credential
    /// (`sandbox.proxy_serve_without_credential`, ADR-044), re-pinned as a
    /// person would: what a host that cannot send one (Codex) needs.
    pub fn serve_proxy_without_credential(&self) {
        let path = self.home.join(".moat/policy.yaml");
        let mut policy: serde_json::Value =
            openmoat_core::yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        policy["sandbox"]["proxy_serve_without_credential"] = true.into();
        std::fs::write(&path, openmoat_core::yaml::to_string(&policy).unwrap()).unwrap();
        let accepted = self.moat_as_person(&["doctor", "--accept"]);
        assert!(text(&accepted).contains("re-pinned"), "{}", text(&accepted));
    }

    /// `moat proxy` on the policy's port, stopped when the guard drops.
    pub fn start_proxy(&self) -> RunningProxy {
        let mut child = self
            .command()
            .arg("proxy")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let running = RunningProxy {
            child,
            _stdout: stdout,
        };
        assert!(line.contains("listening on"), "moat proxy: {line:?}");
        running
    }
}

/// A `moat proxy` child, killed on drop. Its stdout stays open so a late line
/// cannot fail it.
pub struct RunningProxy {
    child: Child,
    _stdout: BufReader<ChildStdout>,
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a prepared command (see [`Sandbox::command`]) with optional input.
pub fn output(cmd: &mut Command, stdin: Option<&str>) -> Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A binary a test has just copied can be busy for a moment on Linux: a
    // process forked by another test holds the copy's write handle until it
    // execs. Retry instead of failing on that race.
    let mut tries = 0;
    let mut child = loop {
        match cmd.spawn() {
            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            spawned => break spawned.expect("spawning moat"),
        }
    };
    let mut pipe = child.stdin.take().expect("stdin is piped");
    if let Some(input) = stdin {
        // A command may exit before reading its input (`guard` refusing its own
        // arguments); its exit status is what the test checks, not this write.
        if let Err(error) = pipe.write_all(input.as_bytes()) {
            assert_eq!(
                error.kind(),
                ErrorKind::BrokenPipe,
                "writing stdin: {error}"
            );
        }
    }
    drop(pipe);
    child.wait_with_output().unwrap()
}

/// A golden payload, `<host id>/<file>` (e.g. `cursor/beforeReadFile.json`),
/// from `openmoat-hosts/src/host/<module>/fixtures/`.
pub fn fixture(relative: &str) -> String {
    let (id, name) = relative.split_once('/').unwrap();
    let host = openmoat_hosts::Host::EVERY
        .into_iter()
        .find(|h| h.id() == id)
        .unwrap_or_else(|| panic!("no host `{id}`"));
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../openmoat-hosts/src/host")
        .join(host.module())
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Standard output as text.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Standard error as text.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Standard output followed by standard error, for assertion messages.
pub fn text(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// Standard output parsed as one JSON document (`Null` when it is not JSON).
pub fn json(out: &Output) -> Value {
    serde_json::from_str(stdout(out).trim()).unwrap_or(Value::Null)
}

/// `hookSpecificOutput` of a Claude Code or Codex hook response. No output and
/// exit 0 is `defer` (ADR-025): the host's own permission flow decides, and the
/// reason is only in the audit log.
pub fn hook_output(out: &Output) -> Value {
    if out.status.code() == Some(0) && stdout(out).trim().is_empty() {
        return serde_json::json!({"permissionDecision": "defer", "permissionDecisionReason": ""});
    }
    json(out)["hookSpecificOutput"].clone()
}

/// `permissionDecision` of a Claude Code or Codex hook response; empty if there is none.
pub fn verdict(out: &Output) -> String {
    hook_output(out)["permissionDecision"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// [`verdict`] and `permissionDecisionReason` (as JSON text) of a hook response.
pub fn verdict_and_reason(out: &Output) -> (String, String) {
    (
        verdict(out),
        hook_output(out)["permissionDecisionReason"].to_string(),
    )
}

/// A Claude Code `PreToolUse` payload for one Bash command.
pub fn bash_payload(session: &str, cwd: &Path, command: &str) -> String {
    serde_json::json!({
        "session_id": session, "cwd": cwd.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t1"
    })
    .to_string()
}

/// Set by the CI job that fetches pinned host binaries (`standard tier`,
/// `scripts/ci/host-binaries.sh`). The required gate fetches none on purpose: it
/// must not run whatever `claude` or `codex` a developer has installed (#366).
#[cfg(unix)] // the host-sandbox tests run on macOS and Linux only
pub const REQUIRE_HOST_BINARIES: &str = "MOAT_REQUIRE_HOST_BINARIES";

/// Skip a test whose host binary is missing, saying so, or fail where
/// [`REQUIRE_HOST_BINARIES`] says this run must have it.
#[cfg(unix)]
pub fn skip_without_host_binary(what: &str) {
    assert!(
        std::env::var_os(REQUIRE_HOST_BINARIES).is_none(),
        "{REQUIRE_HOST_BINARIES} is set, so this run must have the host binary for {what}"
    );
    eprintln!("skipped: {what} (no host binary; the CI standard tier job runs it)");
}
