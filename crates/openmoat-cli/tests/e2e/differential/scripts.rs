//! Hostile project scripts against the OS layer (#335, #346). The hook allows
//! `npm test` and cannot see the project's scripts, so whatever stops a payload
//! in them is the operating system. Each `scripts` entry of
//! `tests/differential/scenarios.yaml` becomes the evil project's test script
//! and runs as `npm test` under `moat run` (Seatbelt on macOS, Landlock and
//! seccomp on Linux), under Claude Code's sandbox (`claude.rs`) and under
//! Codex's `moat` profile (`codex.rs`), each configured as `moat init` leaves
//! it; the test asserts what the OS did to it (EPERM, EACCES, a proxy's 403)
//! and the side effects, and `docs/EVIDENCE.md` is the table generated from
//! the same list.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use super::{Gap, scenarios, suite};

/// What the operating system did to a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// A call failed with `EPERM` ("Operation not permitted").
    Eperm,
    /// A call failed with `EACCES` ("Permission denied").
    Eacces,
    /// A call failed with `EROFS` ("Read-only file system"): the sandbox
    /// mounted the path read-only.
    Erofs,
    /// A call failed with `ENOENT`: bubblewrap mounted an empty directory over
    /// the path, so it does not exist inside the sandbox.
    Enoent,
    /// A call failed with `EEXIST`: the sandbox mounted a file where the
    /// payload creates a directory.
    Eexist,
    /// A call failed with `EIO`: the kernel refused it, not the sandbox (Linux
    /// refuses `TIOCSTI` this way where `dev.tty.legacy_tiocsti` is 0).
    Eio,
    /// The connection was refused: the sandbox has its own network namespace,
    /// where nothing listens.
    Refused,
    /// The layer's proxy answered the request with 403.
    #[serde(rename = "proxy-403")]
    Proxy403,
    /// The payload completed inside the sandbox, but what it wrote or sent
    /// stayed there (an empty in-memory directory, its own network namespace):
    /// the side-effect checks show nothing reached the host.
    Contained,
    /// The sandbox failed to start the command; nothing of the payload ran.
    #[serde(rename = "sandbox-error")]
    SandboxError,
    /// The host started the command without a terminal it could act on.
    #[serde(rename = "no-terminal")]
    NoTerminal,
    /// The payload completed.
    Ran,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Eperm => "EPERM",
            Self::Eacces => "EACCES",
            Self::Erofs => "EROFS",
            Self::Enoent => "ENOENT",
            Self::Eexist => "EEXIST",
            Self::Eio => "EIO",
            Self::Refused => "refused",
            Self::Proxy403 => "proxy 403",
            Self::Contained => "contained",
            Self::SandboxError => "sandbox error",
            Self::NoTerminal => "no terminal",
            Self::Ran => "ran",
        }
    }
}

/// One hostile (or, for the control, ordinary) project test script.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    pub id: String,
    /// `T1…T12` for attacks; absent for the control.
    #[serde(default)]
    pub threat: Option<String>,
    pub why: String,
    /// The script body; `{tcp}` and `{udp}` name the test's loopback listeners.
    pub payload: String,
    /// Each layer runs on a pseudo-terminal of the test's own (`on_terminal.py`).
    #[serde(default)]
    pub terminal: bool,
    /// The outcome under `moat run` on macOS.
    pub seatbelt: Outcome,
    /// The outcome under `moat run` on Linux.
    pub landlock: Outcome,
    /// The outcome under `moat run --isolate` on Linux.
    #[serde(rename = "isolate-linux")]
    pub isolate_linux: Outcome,
    /// The outcome under Claude Code's sandbox on macOS.
    #[serde(rename = "claude-macos")]
    pub claude_macos: Outcome,
    /// The outcome under Claude Code's sandbox on Linux.
    #[serde(rename = "claude-linux")]
    pub claude_linux: Outcome,
    /// The outcome under `codex sandbox -P moat` on macOS.
    #[serde(rename = "codex-macos")]
    pub codex_macos: Outcome,
    /// The outcome under `codex sandbox -P moat` on Linux.
    #[serde(rename = "codex-linux")]
    pub codex_linux: Outcome,
    /// Layers where the script is a known gap, each tracked by an issue.
    #[serde(default)]
    pub gaps: Vec<Gap>,
}

/// The executing layers: id (as `gap.layer` names it) and the column heading.
const LAYERS: [(&str, &str); 7] = [
    ("seatbelt", "`openmoat run`, macOS (Seatbelt)"),
    ("landlock", "`openmoat run`, Linux (Landlock + seccomp)"),
    (
        "isolate-linux",
        "`openmoat run --isolate`, Linux (bubblewrap)",
    ),
    ("claude-macos", "Claude Code sandbox, macOS"),
    ("claude-linux", "Claude Code sandbox, Linux"),
    ("codex-macos", "Codex `moat` profile, macOS"),
    ("codex-linux", "Codex `moat` profile, Linux"),
];

impl Script {
    fn expected(&self, layer: &str) -> Outcome {
        match layer {
            "seatbelt" => self.seatbelt,
            "landlock" => self.landlock,
            "isolate-linux" => self.isolate_linux,
            "claude-macos" => self.claude_macos,
            "claude-linux" => self.claude_linux,
            "codex-macos" => self.codex_macos,
            "codex-linux" => self.codex_linux,
            _ => panic!("no layer {layer}"),
        }
    }

    fn gap_at(&self, layer: &str) -> Option<&Gap> {
        self.gaps.iter().find(|g| g.layer == layer)
    }
}

pub fn scripts() -> Vec<Script> {
    suite().scripts
}

#[test]
fn script_list_is_well_formed() {
    let mut ids: std::collections::BTreeSet<String> =
        scenarios().into_iter().map(|s| s.id).collect();
    for s in scripts() {
        assert!(ids.insert(s.id.clone()), "duplicate id {}", s.id);
        assert!(!s.why.trim().is_empty(), "{}: empty why", s.id);
        for gap in &s.gaps {
            assert!(LAYERS.iter().any(|(id, _)| *id == gap.layer), "{}", s.id);
            assert!(gap.issue > 0 && !gap.why.trim().is_empty(), "{}", s.id);
        }
        for (layer, _) in LAYERS {
            let ran = s.expected(layer) == Outcome::Ran;
            let gap = s.gap_at(layer).is_some();
            match &s.threat {
                // An attack the layer lets through is a known gap, never silent.
                Some(_) => assert!(!ran || gap, "{}: {layer}", s.id),
                // So is a layer that stops the ordinary work.
                None => assert!(ran != gap, "{}: the control must run at {layer}", s.id),
            }
        }
    }
}

/// `docs/EVIDENCE.md` is the table generated from the script list. Regenerate
/// with `OPENMOAT_TEST_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.
#[test]
fn evidence_table_is_current() {
    let mut doc = String::from(
        "# OS enforcement evidence\n\n\
         Generated from the `scripts` list in `tests/differential/scenarios.yaml` by the\n\
         differential suite; do not edit. Regenerate with\n\
         `OPENMOAT_TEST_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.\n\n\
         The hook allows project scripts (`npm test`, `make test`) and cannot see what they\n\
         do ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Each row is such a script: the payload is\n\
         the project's test script, started as `npm test` in a throwaway home with fake secrets,\n\
         under `openmoat run` (Lightweight tier), under `openmoat run --isolate` (Isolated tier, Linux)\n\
         and under each agent's own sandbox as `openmoat init`\n\
         configures it (Standard tier, [SANDBOX.md](SANDBOX.md)): Claude Code 2.1.290 runs\n\
         `claude -p --bare` against a local fake Anthropic API that asks for that one Bash call,\n\
         with only the generated settings (no hook, so the sandbox alone is measured), and\n\
         codex-cli 0.160.1 runs `codex sandbox -P moat`. No account, API key or internet is\n\
         used. A cell is what the operating system did to the payload. CI asserts it on every\n\
         pull request, together with its side effects (no secret printed, no file written,\n\
         nothing reached the listener), and fails when it changes. Network targets are loopback\n\
         listeners the test owns.\n\n",
    );
    doc.push_str("| Case | Threat | Payload |");
    for (_, heading) in LAYERS {
        let _ = write!(doc, " {heading} |");
    }
    doc.push_str("\n|---|---|---|");
    doc.push_str(&"---|".repeat(LAYERS.len()));
    doc.push('\n');
    let mut gaps = String::new();
    for s in scripts() {
        let threat = s.threat.as_deref().unwrap_or("control");
        let payload = s.payload.replace('|', "\\|");
        let on = if s.terminal { ", on a terminal" } else { "" };
        let _ = write!(doc, "| `{}` | {threat} | `{payload}`{on} |", s.id);
        for (layer, heading) in LAYERS {
            let outcome = s.expected(layer).label();
            match s.gap_at(layer) {
                Some(gap) => {
                    let _ = write!(doc, " **gap**: {outcome} (#{}) |", gap.issue);
                    let _ = writeln!(
                        gaps,
                        "- `{}` under {heading} (#{}): {}",
                        s.id, gap.issue, gap.why
                    );
                }
                None => {
                    let _ = write!(doc, " {outcome} |");
                }
            }
        }
        doc.push('\n');
    }
    doc.push_str(
        "\nEPERM, EACCES and EROFS: the system call failed with that error (EROFS: the \
         sandbox\nmounted the path read-only). ENOENT: the path does not exist\ninside the sandbox (bubblewrap mounted an empty directory over it, or did not mount it). EEXIST: the sandbox \
         mounted a\nfile where the payload creates a directory. refused: the \
         connection\nwas refused inside the sandbox's own network namespace. proxy 403: the \
         layer's proxy refused\nthe request (OpenMoat's under `openmoat run`, the agent's own, which \
         allows only the policy's\nhosts, under the Standard tier). contained: the payload \
         completed inside the sandbox, but\nwhat it wrote or sent stayed there (an empty \
         in-memory directory, its own network namespace)\nand nothing reached the host. sandbox \
         error: the sandbox failed to start the command, so\nnothing of the payload ran. no \
         terminal: the host gave the command no terminal. EIO: the kernel refused the call\nitself, \
         not the sandbox (the CI runner's kernel has `dev.tty.legacy_tiocsti` at 0; where it \
         is 1 the call goes through). ran: the payload completed. A row \
         on a terminal runs each layer on a pseudo-terminal of the test's own.\n\n## Known gaps\n\n",
    );
    doc.push_str(&gaps);
    doc.push_str(
        "\n## Layers\n\n| Layer | Status |\n|---|---|\n\
         | `openmoat run`, macOS (Seatbelt) | verified by the `macos-14` and `macos-15-intel` CI jobs |\n\
         | `openmoat run`, Linux (Landlock + seccomp) | verified by the `ubuntu-latest` CI job (Linux 6.7 or later) |\n\
         | `openmoat run --isolate`, Linux (bubblewrap) | verified by the `ubuntu-latest` CI job (bubblewrap installed) |\n\
         | `openmoat run --isolate`, macOS | not run: refused until the Isolated tier has a virtual machine there (#175) |\n\
         | Claude Code sandbox and Codex profile, macOS | verified by the `standard tier (macos-14)` CI job |\n\
         | Claude Code sandbox and Codex profile, Linux | verified by the `standard tier (ubuntu-latest)` CI job (bubblewrap and socat installed) |\n\
         | `openmoat run`, Windows | not run: `openmoat run` refuses on Windows, where OpenMoat generates no OS sandbox (#135) |\n\
         | Claude Code sandbox, Windows | not run: Claude Code's sandbox does not run on native Windows, so `openmoat init` writes no sandbox settings there ([SANDBOX.md](SANDBOX.md)) |\n\
         | Codex profile, Windows | not verified: the scripts and the project's `npm` shim are POSIX shell |\n\
         \nThe Standard tier columns cover the commands the agent runs and the processes they \
         start.\nNot verified here: what the agent's own process does outside its sandbox (Claude \
         Code's file\ntools and hooks), a real model choosing the command, and the opt-in \
         `sandbox.proxy_port` mode\nfor these scripts (the command-level scenarios of the \
         differential suite use it, and the\n`standard tier` jobs run them under both host \
         sandboxes). `scripts/ci/host-binaries.sh` fetches the\npinned binaries, and \
         `scripts/ci/differential.sh hostile_scripts` runs these rows under every layer\nthe \
         machine has.\n",
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/EVIDENCE.md");
    if std::env::var_os("OPENMOAT_TEST_UPDATE_EVIDENCE").is_some() {
        std::fs::write(&path, &doc).unwrap();
    }
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        current.replace("\r\n", "\n") == doc,
        "docs/EVIDENCE.md is out of date; run \
         `OPENMOAT_TEST_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod executing {
    use std::fmt::Write as _;
    use std::io::ErrorKind;
    use std::net::{TcpListener, UdpSocket};
    use std::path::{Path, PathBuf};

    use super::super::{Fixtures, Project, Verdict, start};
    use super::{Outcome, scripts};
    use crate::common::{output, text};
    use crate::run::confined::{isolated, ran, retried};

    /// This system, as the layer ids name it (`claude-macos`, `codex-linux`).
    #[cfg(target_os = "macos")]
    pub const OS: &str = "macos";
    #[cfg(target_os = "linux")]
    pub const OS: &str = "linux";

    /// What the agent runs; the project's `bin/npm` shim starts its test script.
    pub const NPM_TEST: &str = "npm test --silent";

    /// The fake secrets' contents: printed only where a read went through.
    const SECRETS: [&str; 3] = ["FAKE-PRIVATE-KEY", "key=FAKE", "TOKEN=secret"];

    /// What a layer reported for one run of `npm test`.
    pub struct Run {
        /// The payload completed (exit status 0).
        pub completed: bool,
        /// Everything it printed.
        pub shown: String,
    }

    /// The fixtures the scripts run in, with the home outside the temp
    /// directory: Landlock cannot deny inside a granted tree, `/tmp` is a read
    /// root and the host sandboxes let commands write their temp directory, so
    /// the home lives elsewhere, as a real home does.
    pub fn fixtures() -> Fixtures {
        Fixtures::build_in(Path::new(env!("CARGO_TARGET_TMPDIR")))
    }

    /// Run every script as the evil project's test script with `run`, under
    /// the layer `layer`, and compare what the operating system did with
    /// `scenarios.yaml`; then check that no refused call had its effect. `run`
    /// gets whether to [`start`] on a terminal; `None` means the layer cannot run.
    pub fn meet(layer: &str, fx: &Fixtures, mut run: impl FnMut(bool) -> Option<Run>) {
        let hook = fx.hook_decision("scripts", Project::Evil, NPM_TEST);
        assert_eq!(hook, Verdict::Allow, "the hook allows `npm test`");
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        udp.set_nonblocking(true).unwrap();
        let pinned = [".moat/policy.yaml", ".claude/settings.json"]
            .map(|file| (file, std::fs::read(fx.sb.home.join(file)).unwrap()));
        let project = fx.tree(Project::Evil);
        let env = std::fs::read(project.join(".env")).unwrap();

        let mut matrix = format!("\nhostile scripts under {layer}:\n");
        let mut mismatches = Vec::new();
        for s in scripts() {
            let payload = s
                .payload
                .replace("{tcp}", &tcp.local_addr().unwrap().port().to_string())
                .replace("{udp}", &udp.local_addr().unwrap().port().to_string());
            let build = fx.tree(Project::Evil).join(".build.sh");
            std::fs::write(build, format!("{payload}\n")).unwrap();
            let Some(mut out) = run(s.terminal) else {
                return;
            };
            // An outcome none of `observe`'s messages names is run once more
            // (a payload leaves the project as it found it, so a second run
            // meets the same layer); the mismatch below shows both outputs.
            if observe(&out).is_none() {
                eprintln!("retrying {}: no known outcome in:\n{}", s.id, out.shown);
                let Some(again) = run(s.terminal) else {
                    return;
                };
                out = Run {
                    completed: again.completed,
                    shown: format!("{}\n--- run again ---\n{}", out.shown, again.shown),
                };
            }
            let expected = s.expected(layer);
            // A contained payload completes; the checks below the loop prove
            // that its write or datagram did not reach the host.
            let got = observe(&out).map(|got| match (got, expected) {
                (Outcome::Ran, Outcome::Contained) => Outcome::Contained,
                _ => got,
            });
            let leaked = SECRETS.iter().any(|secret| out.shown.contains(secret));
            let planted = planted(project);
            let label = got.map_or("unexpected", Outcome::label);
            let _ = writeln!(matrix, "  {:<30} {label}", s.id);
            let escaped = leaked || !planted.is_empty();
            if got != Some(expected) || (escaped && expected != Outcome::Ran) {
                mismatches.push(format!(
                    "{}: {label} (leaked: {leaked}, planted: {planted:?}) but scenarios.yaml \
                     expects {}:\n{}",
                    s.id,
                    expected.label(),
                    out.shown
                ));
            }
            // The next script starts from the same project.
            std::fs::write(project.join(".env"), &env).unwrap();
            for path in planted.iter().filter(|p| !p.ends_with(".env")) {
                std::fs::remove_file(path).unwrap();
            }
        }
        eprintln!("{matrix}");
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        // What the refused calls would have done did not happen.
        assert!(!fx.sb.home.join("outside.txt").exists());
        for (file, before) in pinned {
            let after = std::fs::read(fx.sb.home.join(file)).unwrap();
            assert!(after == before, "{file} changed");
        }
        let accepted = tcp.accept().map(drop).map_err(|e| e.kind());
        assert_eq!(
            accepted,
            Err(ErrorKind::WouldBlock),
            "a TCP connection arrived"
        );
        let received = udp.recv(&mut [0; 16]).map(drop).map_err(|e| e.kind());
        assert_eq!(received, Err(ErrorKind::WouldBlock), "a datagram arrived");
    }

    /// The files below `dir` holding `PLANTED`, which the payloads that write
    /// into the project write, the script itself (`.build.sh`) aside.
    fn planted(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                found.extend(planted(&path));
            } else if !path.ends_with(".build.sh")
                && std::fs::read(&path).is_ok_and(|b| b.windows(7).any(|w| w == b"PLANTED"))
            {
                found.push(path);
            }
        }
        found
    }

    /// The outcome the payload's exit status and messages show, if any.
    fn observe(out: &Run) -> Option<Outcome> {
        let shows = |message: &str| out.shown.contains(message);
        if out.completed {
            Some(Outcome::Ran)
        } else if shows("error building bubblewrap command") {
            // Codex on Linux could not build its sandbox; nothing of the payload ran.
            Some(Outcome::SandboxError)
        } else if shows("no terminal: ") {
            Some(Outcome::NoTerminal)
        } else if shows("returned error: 403") {
            Some(Outcome::Proxy403)
        } else if shows("Operation not permitted") {
            Some(Outcome::Eperm)
        } else if shows("Permission denied") {
            Some(Outcome::Eacces)
        } else if shows("Read-only file system") {
            Some(Outcome::Erofs)
        } else if shows("No such file or directory") || shows("Directory nonexistent") {
            Some(Outcome::Enoent)
        } else if shows("File exists") {
            Some(Outcome::Eexist)
        } else if shows("Input/output error") {
            Some(Outcome::Eio)
        } else if shows("Connection refused") {
            Some(Outcome::Refused)
        } else {
            None
        }
    }

    #[test]
    fn hostile_scripts_meet_the_os_layer() {
        let layer = if OS == "macos" {
            "seatbelt"
        } else {
            "landlock"
        };
        under_moat_run(layer, &[]);
    }

    /// The Isolated tier, where bubblewrap can run (CI's Linux job installs it).
    #[cfg(target_os = "linux")]
    #[test]
    fn hostile_scripts_meet_the_isolated_tier() {
        under_moat_run("isolate-linux", &["--isolate"]);
    }

    /// Every script under `moat run <flags>`, as the layer `layer`.
    fn under_moat_run(layer: &str, flags: &[&str]) {
        let fx = fixtures();
        let project = fx.tree(Project::Evil);
        // The temp directory is outside the home, so a home write is not a
        // temp-directory write.
        let tmp = fx.sb.home.with_file_name("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        meet(layer, &fx, |terminal| {
            // Seatbelt on macos-14 sometimes refuses the connection to the
            // proxy (#280); `retried` recognises it by `moat run`'s notice.
            let out = retried(|| {
                output(
                    fx.sb
                        .configure(start(env!("CARGO_BIN_EXE_openmoat"), terminal))
                        .current_dir(project)
                        .env("PATH", format!("{}/bin:/usr/bin:/bin", project.display()))
                        .env("TMPDIR", &tmp)
                        .arg("run")
                        .args(flags)
                        .args(["--", "/bin/sh", "-c", NPM_TEST]),
                    None,
                )
            });
            (ran(&out) && isolated(&out)).then(|| Run {
                completed: out.status.success(),
                shown: text(&out),
            })
        });
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn hostile_scripts_are_not_run_without_an_os_layer() {
    eprintln!(
        "skipped: hostile scripts — `openmoat run` refuses on {}, where OpenMoat generates no OS \
         sandbox (#135; run.rs checks that it refuses), Claude Code's sandbox does not run, and \
         the scripts are POSIX shell",
        std::env::consts::OS
    );
}
