//! Differential fixtures (ADR-019, issue #170): one scenario suite run against
//! every enforcement point available on the machine. Each layer must give the
//! verdict recorded in `tests/differential/scenarios.yaml`; a disagreement
//! fails the suite.
//!
//! This module is the backbone and the always-on layer, the hook decision
//! (`moat guard` on a host payload). The executing host-sandbox layers are
//! stacked on top: `codex sandbox -P moat` (#170) and a fake-API `claude -p`.
//! Where a host binary is missing the layer prints a visible skip and the suite
//! still passes on the layers it can run. Hostile project scripts run under
//! `moat run` in `scripts`, which also generates `docs/EVIDENCE.md` (#335).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::common::{Sandbox, bash_payload, hook_output, json};

#[cfg(unix)]
pub mod claude;
#[cfg(unix)]
pub mod codex;
pub mod scripts;

/// A layer's verdict. Sandboxes express only `Allow` (ran) and `Deny` (blocked);
/// `Ask` is a hook outcome (the host prompts the person).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    fn symbol(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask ",
            Self::Deny => "deny",
        }
    }
}

/// Which fixture tree the command runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Project {
    /// A clean project whose scripts do ordinary work.
    #[default]
    Benign,
    /// A project whose `test`/`build.rs` scripts carry the attack payload.
    Evil,
}

/// One row of the matrix.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Unique across the file; also the audit session id.
    pub id: String,
    /// `T1…T12` for attacks; absent for benign scenarios.
    #[serde(default)]
    pub threat: Option<String>,
    /// A public advisory this scenario replays, by id.
    #[serde(default)]
    pub cite: Option<String>,
    /// Why the recorded verdicts are what they are.
    pub why: String,
    /// The command every layer runs; the hook classifies the same string.
    pub command: String,
    /// The fixture tree it runs in.
    #[serde(default)]
    pub project: Project,
    /// The expected hook decision.
    pub hook: Verdict,
    /// The expected outcome under `codex sandbox -P moat` (`allow` ran, `deny`
    /// blocked).
    pub codex: Verdict,
    /// The expected outcome under a fake-API `claude -p` (`allow` ran, `deny`
    /// blocked).
    pub claude: Verdict,
    /// A layer where this scenario is a known gap: its verdict is reported in
    /// the matrix (never silently skipped) but not asserted, pending the issue.
    #[serde(default)]
    pub gap: Option<Gap>,
    /// Host layers (`claude-linux`) where this attack completes inside the
    /// sandbox and what it wrote is discarded there, so the host never sees it.
    /// That layer's verdict stays `deny`; the layer proves the host unchanged
    /// instead of expecting the command to fail.
    #[serde(default)]
    pub contained: Vec<String>,
}

/// A documented known gap at one layer, tracked by an issue.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// `hook`, `codex` or `claude`.
    pub layer: String,
    /// The tracking issue number.
    pub issue: u32,
    /// Why the layer falls short.
    pub why: String,
}

impl Scenario {
    /// The tracking issue when this scenario is a known gap at `layer`.
    pub fn gap_at(&self, layer: &str) -> Option<&Gap> {
        self.gap.as_ref().filter(|g| g.layer == layer)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    attacks: Vec<Scenario>,
    benign: Vec<Scenario>,
    scripts: Vec<scripts::Script>,
}

fn suite() -> Suite {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/scenarios.yaml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_yaml_ng::from_str(&text).expect("scenarios.yaml")
}

/// The scenario file, attacks first.
pub fn scenarios() -> Vec<Scenario> {
    let suite = suite();
    let mut all = suite.attacks;
    for mut benign in suite.benign {
        assert!(
            benign.threat.is_none(),
            "{}: benign carries a threat",
            benign.id
        );
        benign.threat = None;
        all.push(benign);
    }
    all
}

impl Scenario {
    /// Whether this is an attack (carries a threat) or a benign scenario.
    pub fn is_attack(&self) -> bool {
        self.threat.is_some()
    }
}

/// The two fixture trees (a git project and a malicious one) and the home
/// files the scenarios read, inside a freshly `moat init`-ed home.
pub struct Fixtures {
    pub sb: Sandbox,
    pub benign: PathBuf,
    pub evil: PathBuf,
}

impl Fixtures {
    /// Build an installed home with both fixture trees and the secret files the
    /// attacks target.
    pub fn build() -> Self {
        Self::build_in(&std::env::temp_dir())
    }

    /// [`Fixtures::build`] with the home in a temporary directory below `parent`.
    pub fn build_in(parent: &Path) -> Self {
        let sb = Sandbox::installed_in(parent, &[".claude", ".codex"]);
        let w = |p: &Path, name: &str, body: &str| std::fs::write(p.join(name), body).unwrap();

        std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
        w(&sb.home.join(".ssh"), "id_rsa", "FAKE-PRIVATE-KEY");
        std::fs::create_dir_all(sb.home.join(".aws")).unwrap();
        w(&sb.home.join(".aws"), "credentials", "[default]\nkey=FAKE");
        std::fs::create_dir_all(sb.home.join(".cargo")).unwrap();
        w(&sb.home.join(".cargo"), "config.toml", "[build]\n");
        w(&sb.home, ".zshrc", "# rc\n");
        w(&sb.home, ".zshenv", "# env\n");

        let benign = Self::project(&sb, "proj", false);
        let evil = Self::project(&sb, "evil", true);
        Self { sb, benign, evil }
    }

    /// A git-initialised project. `bin/npm` and `bin/cargo` are shims (on the
    /// sandbox `PATH`) that run the project's own build script, so the hook sees
    /// an allowed `npm test` / `cargo build` while the payload stays inside the
    /// script; a host sandbox is then the only layer that can stop it. With
    /// `malicious` that script reads `~/.ssh/id_rsa`; otherwise it does nothing.
    fn project(sb: &Sandbox, name: &str, malicious: bool) -> PathBuf {
        let root = sb.home.join(name);
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let w = |name: &str, body: &str| std::fs::write(root.join(name), body).unwrap();
        w("src/main.rs", "fn main() {}\n");
        w(".env", "TOKEN=secret\n");
        w(".env.example", "TOKEN=\n");
        w(
            "package.json",
            "{\"scripts\":{\"test\":\"sh ./.build.sh\"}}\n",
        );
        w("Cargo.toml", "[package]\nname = \"p\"\n");
        let payload = if malicious {
            "cat ~/.ssh/id_rsa"
        } else {
            "echo ok"
        };
        w(".build.sh", &format!("{payload}\n"));
        for shim in ["npm", "cargo"] {
            let path = root.join("bin").join(shim);
            // The real command name reaches the hook; the shim runs .build.sh
            // for `npm test` and `cargo build` only: Claude Code itself runs
            // `npm root -g` from `PATH`, outside its sandbox, which must not
            // count as the payload escaping.
            std::fs::write(
                &path,
                "#!/bin/sh\ncase \"$1\" in test|build) \
                 exec /bin/sh \"$(dirname \"$0\")/../.build.sh\" ;; esac\n",
            )
            .unwrap();
            make_executable(&path);
        }
        root
    }

    /// The project tree a scenario runs in.
    pub fn tree(&self, project: Project) -> &Path {
        match project {
            Project::Benign => &self.benign,
            Project::Evil => &self.evil,
        }
    }

    /// The hook decision for `scenario`: `moat guard` on a Claude Code Bash
    /// payload, mapped from `permissionDecision`.
    pub fn hook_verdict(&self, scenario: &Scenario) -> Verdict {
        self.hook_decision(&scenario.id, scenario.project, &scenario.command)
    }

    /// The hook decision for `command` in `project`, under audit session `id`.
    pub fn hook_decision(&self, id: &str, project: Project, command: &str) -> Verdict {
        let payload = bash_payload(id, self.tree(project), command);
        let out = self.sb.guard("claude-code", &payload);
        let decision = hook_output(&out)["permissionDecision"].clone();
        match decision.as_str() {
            Some("allow") => Verdict::Allow,
            Some("ask") => Verdict::Ask,
            Some("deny") => Verdict::Deny,
            _ => panic!("{id}: no permissionDecision in {}", json(&out)),
        }
    }
}

#[test]
fn scenario_file_is_well_formed() {
    let all = scenarios();
    let mut ids = std::collections::BTreeSet::new();
    for s in &all {
        assert!(ids.insert(s.id.clone()), "duplicate id {}", s.id);
        assert!(!s.why.trim().is_empty(), "{}: empty why", s.id);
        if let Some(threat) = &s.threat {
            let n: u8 = threat
                .strip_prefix('T')
                .and_then(|d| d.parse().ok())
                .unwrap_or(0);
            assert!(
                (1..=12).contains(&n),
                "{}: threat {threat} not T1..T12",
                s.id
            );
        }
        if let Some(gap) = &s.gap {
            assert!(
                ["hook", "codex", "claude"].contains(&gap.layer.as_str()),
                "{}: gap layer {}",
                s.id,
                gap.layer
            );
            assert!(gap.issue > 0, "{}: gap has no issue", s.id);
            assert!(!gap.why.trim().is_empty(), "{}: gap has no why", s.id);
        }
        for layer in &s.contained {
            let verdict = match layer.as_str() {
                "claude-linux" | "claude-macos" => s.claude,
                "codex-linux" | "codex-macos" => s.codex,
                _ => panic!("{}: contained layer {layer}", s.id),
            };
            assert!(
                s.is_attack() && verdict == Verdict::Deny,
                "{}: only a blocked attack can be contained at {layer}",
                s.id
            );
        }
        // A host sandbox expected to let an attack run is a known gap, never a
        // silent expectation; this holds on hosts that cannot run that layer too.
        if s.is_attack() {
            for (layer, verdict) in [("codex", s.codex), ("claude", s.claude)] {
                assert!(
                    verdict != Verdict::Allow || s.gap_at(layer).is_some(),
                    "{}: {layer} is expected to allow an attack without a gap",
                    s.id
                );
            }
        }
    }
    assert!(all.iter().any(|s| s.cite.is_some()), "no CVE replays");
}

#[test]
fn hook_layer_agrees_with_every_scenario() {
    let fx = Fixtures::build();
    let all = scenarios();
    let mut matrix = String::from("\ndifferential matrix (scenario x layer):\n");
    let mut mismatches = Vec::new();
    for s in &all {
        let got = fx.hook_verdict(s);
        let kind = if s.is_attack() { "attack" } else { "benign" };
        let _ = writeln!(matrix, "  {kind} {:<28} hook={}", s.id, got.symbol());
        if got != s.hook {
            mismatches.push(format!(
                "{}: hook gave {} but scenarios.yaml expects {}",
                s.id,
                got.symbol().trim(),
                s.hook.symbol().trim()
            ));
        }
    }
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "disagreements:\n{}",
        mismatches.join("\n")
    );
}

/// Give `path` owner-execute, for the `npm`/`cargo` shims.
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// A command that starts `program`, on a pseudo-terminal of its own when
/// `terminal` (a script's `terminal: true`); the caller adds its arguments.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn start(program: impl AsRef<std::ffi::OsStr>, terminal: bool) -> std::process::Command {
    if !terminal {
        return std::process::Command::new(program);
    }
    let mut cmd = std::process::Command::new("/usr/bin/python3");
    let script = "../../tests/differential/on_terminal.py";
    cmd.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(script))
        .arg(program);
    cmd
}
