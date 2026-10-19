//! The Claude Code host-sandbox layer of the differential suite (#170): each
//! attack runs under Claude Code's own sandbox, configured from the settings
//! `moat sandbox show` generates. The real `claude` binary runs fully isolated,
//! the way the #119 sandbox spike ran it: a temp `CLAUDE_CONFIG_DIR`
//! holding only the generated sandbox settings (no OpenMoat hook, so this measures
//! the host sandbox, not the hook), a fake `HOME`, `--bare`, a fake API key and
//! a local fake Anthropic API (`tests/differential/fake_api.py`) that drives one
//! Bash tool call. `moat proxy` runs on the port the settings name. Nothing
//! leaves the machine.
//!
//! The binary is `MOAT_CLAUDE_BIN` only (never `claude` from `PATH`) and the fake API is
//! `MOAT_FAKE_API` (else `python3`); without either the layer skips visibly,
//! except in CI's `standard tier` job, which fails it (`skip_without_host_binary`).
//!
//! Scope: the layer asserts that every attack is **blocked**: the command fails,
//! or, where `scenarios.yaml` records it `contained` for this OS, it completes
//! inside the sandbox without changing the host home or showing a secret. On
//! Linux Claude Code's sandbox mounts an empty in-memory directory over the
//! home, so a write there completes and is discarded (#421). Every attack is
//! also checked against the host home outside the project and for a fake
//! secret in its output, so a sandbox that is not running fails the layer
//! instead of passing it. Claude Code grants
//! reads and writes in the session's working directories, which it establishes
//! interactively; a headless `claude -p --bare` has none, so benign project work
//! cannot be verified here and those rows are skipped with a notice (#238). A
//! readiness check (an allowed system read) proves the sandbox discriminates
//! rather than denying everything.

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::common::{json, skip_without_host_binary, text};

use super::{Fixtures, Verdict, scenarios};

mod observe;

use observe::{Run, Seen};

/// This OS's name for the layer in `contained:` lists.
const LAYER: &str = if cfg!(target_os = "linux") {
    "claude-linux"
} else {
    "claude-macos"
};

/// What bounds each `claude` run (`claude_output`).
pub(super) const PERL: &str = "/usr/bin/perl";

/// The issue tracking the headless benign-verification limitation.
const BENIGN_GAP: u32 = 238;

/// `MOAT_CLAUDE_BIN` only (scripts/ci/differential.sh sets it from `PATH`): the
/// quality gate must not run whatever Claude Code a developer has installed.
pub(super) fn claude_binary() -> Option<PathBuf> {
    std::env::var_os("MOAT_CLAUDE_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub(super) fn python() -> Option<PathBuf> {
    which("MOAT_FAKE_API", "python3")
}

fn which(var: &str, name: &str) -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// The fake Anthropic API, serving one Bash command or a sequence of tool
/// calls, on a loopback port.
pub(super) struct FakeApi {
    child: Child,
    pub(super) port: u16,
}

impl FakeApi {
    /// Start the fake API serving one Bash `command`.
    fn start(python: &Path, script: &Path, command: &str) -> Self {
        Self::spawn(python, script, &["--bash", command])
    }

    /// Start the fake API with `args` on a port the OS picks and read that port
    /// from its first stdout line, so no other process can take the port in between.
    pub(super) fn spawn(python: &Path, script: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(python)
            .arg("-I")
            .arg(script)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("starting fake api");
        let stdout = child.stdout.take().expect("fake api stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx.recv_timeout(Duration::from_secs(10));
        let port = line.as_deref().ok().and_then(|l| l.trim().parse().ok());
        let mut api = Self { child, port: 0 };
        // On failure `api` drops here, which kills the child.
        api.port = port.unwrap_or_else(|| panic!("fake api did not report its port: {line:?}"));
        api
    }
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fixtures {
    /// The Claude Code sandbox settings `moat sandbox show` generates, written
    /// as `settings.json` in a fresh config dir (no hook).
    fn write_claude_settings(&self, dir: &Path) {
        let out = self.sb.moat(&["sandbox", "show", "--format", "json"]);
        let settings = json(&out)["hosts"]["claude-code"]["settings"]
            .as_str()
            .expect("claude settings")
            .to_owned();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("settings.json"), settings).unwrap();
    }

    /// Run `command` under Claude Code's sandbox, watching the home.
    fn claude_run(
        &self,
        claude: &Path,
        python: &Path,
        script: &Path,
        id: &str,
        command: &str,
    ) -> Run {
        let project = self.tree(super::Project::Evil);
        Run::observe(&self.sb.home, project, || {
            let perl = Command::new(PERL);
            text(&self.claude_output(perl, claude, python, script, id, command))
        })
    }

    /// Run `command` in the evil project as the one Bash call of a `claude -p`
    /// session under Claude Code's sandbox; the output quotes the tool result.
    /// `perl` starts [`PERL`], which bounds the run and execs claude.
    fn claude_output(
        &self,
        mut perl: Command,
        claude: &Path,
        python: &Path,
        script: &Path,
        id: &str,
        command: &str,
    ) -> Output {
        let project = self.tree(super::Project::Evil);
        let config_dir = self.sb.home.join(format!(".cfg-{id}"));
        self.write_claude_settings(&config_dir);
        let wrapped = format!("set -eo pipefail; {command}");
        let api = FakeApi::start(python, script, &wrapped);

        // perl's alarm bounds a hung run; claude execs in its place.
        perl.args(["-e", "alarm 90; exec @ARGV"])
            .arg(claude)
            .args([
                "--bare",
                "-p",
                "run it",
                "--permission-mode",
                "default",
                "--allowedTools",
                "Bash",
            ])
            .current_dir(project)
            .env_clear()
            .env("PATH", format!("{}/bin:/usr/bin:/bin", project.display()))
            .env("HOME", &self.sb.home)
            .env("CLAUDE_CONFIG_DIR", &config_dir)
            .env("ANTHROPIC_API_KEY", "sk-ant-FAKE-moat-differential")
            .env(
                "ANTHROPIC_BASE_URL",
                format!("http://127.0.0.1:{}", api.port),
            )
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .output()
            .expect("running claude")
    }
}

#[test]
fn claude_layer_blocks_every_attack() {
    let (Some(claude), Some(python)) = (claude_binary(), python()) else {
        skip_without_host_binary(
            "claude layer (set MOAT_CLAUDE_BIN and MOAT_FAKE_API); the other layers ran",
        );
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/fake_api.py");
    let fx = Fixtures::build();
    // The generated settings send sandboxed traffic to `moat proxy` on this port.
    fx.sb.use_free_proxy_port();
    let _proxy = fx.sb.start_proxy();

    // Readiness: an allowed system read must run, or the sandbox is denying
    // everything and "blocked" would be meaningless.
    // What it changes in the home is Claude Code's own doing (its state under
    // `~/.claude` and `~/.config`), not a command's: left out below.
    let ready = fx.claude_run(&claude, &python, &script, "ready", "cat /etc/hosts");
    let artefacts = ready.changed.iter().cloned().collect();
    assert_eq!(
        ready.seen(&artefacts),
        Seen::Contained,
        "claude sandbox denied an allowed read (harness broken)"
    );

    let mut matrix = String::from("\ndifferential matrix (claude code sandbox):\n");
    let mut mismatches = Vec::new();
    for s in scenarios().iter().filter(|s| s.is_attack()) {
        let got = fx
            .claude_run(&claude, &python, &script, &s.id, &s.command)
            .seen(&artefacts);
        let _ = writeln!(matrix, "  {:<30} claude={}", s.id, got.label());
        // Every attack must be blocked, as recorded: refused, or contained
        // where `scenarios.yaml` says so for this OS.
        let expected = if s.contained.iter().any(|l| l == LAYER) {
            Seen::Contained
        } else {
            Seen::Refused
        };
        if got != expected || s.claude != Verdict::Deny {
            let detail = match &got {
                Seen::Escaped(detail) => detail.as_str(),
                _ => "",
            };
            mismatches.push(format!(
                "{}: claude {} (expected {}; scenarios.yaml says {}) {detail}",
                s.id,
                got.label(),
                expected.label(),
                s.claude.symbol().trim()
            ));
        }
    }
    // The unlisted host reached `moat proxy`, which refused and recorded it: the
    // sandbox sent it there, not to Claude Code's own proxy. (curl connects to
    // the metadata address directly, and the sandbox refuses that connection.)
    let shown = json(&fx.sb.moat(&["show", "--since", "all", "--format", "json"]));
    let refused: Vec<&str> = shown
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["host"] == "proxy" && row["verdict"] == "deny")
        .filter_map(|row| row["action"]["net"]["url"].as_str())
        .collect();
    if !refused.contains(&"connect://evil.example:443") {
        mismatches.push(format!(
            "evil.example did not reach moat proxy: {refused:?}"
        ));
    }
    let _ = writeln!(
        matrix,
        "  (benign rows skipped: headless claude has no working directory, #{BENIGN_GAP})\n  \
         (Claude Code's own writes, left out of the home check: {:?})",
        ready.changed
    );
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "claude disagreements:\n{}",
        mismatches.join("\n")
    );
}

/// The hostile project scripts (#346) under Claude Code's sandbox with the
/// settings `moat init` generates for the default policy: network through
/// Claude Code's own proxy, which allows only the policy's hosts.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn hostile_scripts_meet_the_claude_code_sandbox() {
    use super::scripts::executing::{NPM_TEST, OS, Run, fixtures, meet};
    use super::start;

    let (Some(claude), Some(python)) = (claude_binary(), python()) else {
        skip_without_host_binary(
            "hostile scripts under claude (set MOAT_CLAUDE_BIN and MOAT_FAKE_API)",
        );
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/fake_api.py");
    let fx = fixtures();
    meet(&format!("claude-{OS}"), &fx, |terminal| {
        let run = || {
            let perl = start(PERL, terminal);
            fx.claude_output(perl, &claude, &python, &script, "scripts", NPM_TEST)
        };
        let mut out = run();
        // Claude Code starts its own proxy on `localhost` for each session, and
        // a request made before it listens fails to connect (#554). Run again,
        // at most twice more; a proxy that forwards the request still fails the row.
        for _ in 0..2 {
            if !text(&out).contains("Failed to connect to localhost port ") {
                break;
            }
            eprintln!("retrying: Claude Code's proxy was not listening yet (#554)");
            out = run();
        }
        let shown = text(&out);
        // Claude Code's Bash tool reports a non-zero exit as "Exit code N".
        let completed = out.status.success() && !shown.contains("Exit code ");
        Some(Run { completed, shown })
    });
}
