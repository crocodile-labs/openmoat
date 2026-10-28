//! The Codex host-sandbox layer of the differential suite (#170): each scenario
//! runs under `codex sandbox -P moat`, the Seatbelt (macOS) or Landlock (Linux)
//! profile Codex derives from the `[permissions.moat]` profile `moat init`
//! generates, with `moat proxy` running as Codex's upstream. The binary is
//! `MOAT_CODEX_BIN` only (scripts/ci/differential.sh sets it from `PATH`), so the
//! quality gate never picks up whatever `codex` a developer has installed; without
//! it the layer prints a visible skip and the suite passes on the other layers,
//! except in CI's `standard tier` job, which fails it (`skip_without_host_binary`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Fixtures, Project, Scenario, Verdict, scenarios};
use crate::common::{skip_without_host_binary, text};

/// The codex binary, or `None` to skip the layer.
fn binary() -> Option<PathBuf> {
    std::env::var_os("MOAT_CODEX_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

impl Fixtures {
    /// `moat sandbox sync` with `codex` first on `PATH`, as after a user's
    /// install: on Linux the profile then lets commands read the executable,
    /// which Codex runs again inside bubblewrap to apply seccomp (#371). The CI
    /// download directory is under no read root.
    fn sync_with_codex(&self, codex: &Path) {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dirs = std::iter::once(codex.parent().unwrap().to_path_buf())
            .chain(std::env::split_paths(&path));
        let synced = self
            .sb
            .command()
            .args(["sandbox", "sync"])
            .env("MOAT_ASSUME_TTY", "1")
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .output()
            .unwrap();
        assert_eq!(synced.status.code(), Some(0), "{}", text(&synced));
    }

    /// Run `scenario` under `codex sandbox -P moat`: `Allow` if the command (and
    /// every step of it, `set -eo pipefail`) completed, `Deny` if the sandbox
    /// stopped it. The project's own `bin/` holds the `npm`/`cargo` shims.
    /// Codex runs with `HTTP(S)_PROXY` naming `moat proxy` on `proxy_port`, so its
    /// own proxy hands what it allows on to OpenMoat's.
    fn codex_verdict(&self, codex: &Path, proxy_port: u16, scenario: &Scenario) -> Verdict {
        let proxy = format!("http://127.0.0.1:{proxy_port}");
        let codex = Command::new(codex);
        let mut cmd = self.codex_command(codex, scenario.project, &scenario.command);
        let out = cmd
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .output()
            .expect("running codex sandbox");
        if out.status.success() {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }

    /// `command` in `project` under `codex sandbox -P moat`, in the installed
    /// home and nothing else of the caller's environment; `cmd` starts codex.
    fn codex_command(&self, mut cmd: Command, project: Project, command: &str) -> Command {
        let project = self.tree(project);
        let path = format!("{}/bin:/usr/bin:/bin", project.display());
        // bash (not dash) for `pipefail`, so a blocked `curl … | sh` is a Deny
        // rather than the trailing shell's exit 0.
        let script = format!("set -eo pipefail; {command}");
        cmd.args(["sandbox", "-P", "moat", "-C"])
            .arg(project)
            .args(["--", "/bin/bash", "-c", &script])
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.sb.home)
            .env("CODEX_HOME", self.sb.home.join(".codex"));
        cmd
    }
}

/// The hostile project scripts (#346) under `codex sandbox -P moat`, the
/// profile `moat init` generates for the default policy, with no proxy
/// variables set: network as Codex itself gives it to the sandbox.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn hostile_scripts_meet_the_codex_profile() {
    use super::scripts::executing::{NPM_TEST, OS, Run, fixtures, meet};
    use super::start;

    let Some(codex) = binary() else {
        skip_without_host_binary("hostile scripts under codex (set MOAT_CODEX_BIN)");
        return;
    };
    let fx = fixtures();
    fx.sync_with_codex(&codex);
    meet(&format!("codex-{OS}"), &fx, |terminal| {
        let out = fx
            .codex_command(start(&codex, terminal), Project::Evil, NPM_TEST)
            .output()
            .expect("running codex sandbox");
        Some(Run {
            completed: out.status.success(),
            shown: text(&out),
        })
    });
}

#[test]
fn codex_layer_agrees_with_every_scenario() {
    let Some(codex) = binary() else {
        skip_without_host_binary("codex layer (set MOAT_CODEX_BIN); the hook layer still ran");
        return;
    };
    let fx = Fixtures::build();
    let port = fx.sb.use_free_proxy_port();
    // Codex's proxy sends no session credential (ADR-044): served without one.
    fx.sb.serve_proxy_without_credential();
    fx.sync_with_codex(&codex);
    let _proxy = fx.sb.start_proxy();
    let mut matrix = String::from("\ndifferential matrix (codex sandbox):\n");
    let mut mismatches = Vec::new();
    for s in &scenarios() {
        let got = fx.codex_verdict(&codex, port, s);
        if let Some(gap) = s.gap_at("codex") {
            let _ = writeln!(
                matrix,
                "  {:<30} codex={} GAP(#{}: {})",
                s.id,
                got.symbol(),
                gap.issue,
                gap.why
            );
            continue;
        }
        let _ = writeln!(matrix, "  {:<30} codex={}", s.id, got.symbol());
        if got != s.codex {
            mismatches.push(format!(
                "{}: codex {} but scenarios.yaml expects {} ({})",
                s.id,
                got.symbol().trim(),
                s.codex.symbol().trim(),
                s.why
            ));
        }
    }
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "codex disagreements:\n{}",
        mismatches.join("\n")
    );
}
