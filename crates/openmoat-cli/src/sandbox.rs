//! Standard tier (ADR-018): each host's own sandbox settings, generated from
//! the enforcement IR (ADR-019).
//!
//! The settings are host-wide (Claude Code user settings, Codex `config.toml`,
//! Cursor `sandbox.json`), so the IR is lowered once for no particular session:
//! [`PROJECT`] stands in for the project, and each backend maps it to the host's
//! own notion of the workspace (Claude Code's working directories, Codex
//! `:workspace_roots`, the workspace Cursor opened).
//! Backends only narrow, reported as losses, except where a host cannot run
//! without a wider grant; those are listed as allowances, never silent.
//!
//! The Lightweight tier's Seatbelt profile ([`seatbelt`]) and Landlock rules
//! ([`landlock`]) are lowered per session instead, for the project `moat run`
//! starts in; on Linux a seccomp filter (`seccomp`) closes the sockets Landlock
//! leaves open. The Isolated tier's bubblewrap mounts (`bwrap`, Linux) are built on
//! the same Landlock rules.

// Its tests walk real Unix paths, so they run on macOS too, not on Windows.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub mod bwrap;
pub mod claude;
pub mod codex;
pub mod cursor;
pub mod install;
pub mod landlock;
mod patterns;
pub mod seatbelt;
#[cfg(any(target_os = "linux", test))]
pub mod seccomp;

use openmoat_core::ir::{Access, Allowance, Effect, Enforcement, Loss};
use openmoat_core::{EvalContext, Policy, PolicyError};
use serde::Serialize;

/// Stand-in for the session's project in a host-wide lowering. Never a real
/// directory: it only marks the patterns that name `${project}`.
pub const PROJECT: &str = "/__moat_project__";

/// The loopback port of `moat proxy` the host sandboxes send their commands'
/// traffic to (`sandbox.proxy_port`); `None` leaves each host's own proxy in
/// charge (opt-in until `moat proxy` can run as a service, #272).
pub fn proxy_port(policy: &Policy) -> Option<u16> {
    policy
        .sandbox
        .as_ref()
        .and_then(|s| s.proxy_port)
        .map(std::num::NonZeroU16::get)
}

/// Lower `policy` for host-wide settings of a user whose home is `home`
/// (`real_home`: the same with symlinks resolved, when that differs) and whose
/// state and host directories moved as `moved_dirs` say.
pub fn lower_for_hosts(
    policy: &Policy,
    home: &str,
    real_home: Option<String>,
    moved_dirs: Vec<(String, String)>,
    case_insensitive_paths: bool,
) -> Result<Enforcement, PolicyError> {
    openmoat_core::ir::lower(
        policy,
        &EvalContext {
            home: home.to_owned(),
            project: Some(PROJECT.to_owned()),
            real_home,
            real_project: None,
            moved_dirs,
            cwd: PROJECT.to_owned(),
            case_insensitive_paths,
        },
    )
}

/// Everything the Standard tier writes for one policy on this machine.
#[derive(Debug)]
pub struct Plan {
    /// The policy had no `sandbox.read_roots`, so the default policy's apply.
    pub default_read_roots: bool,
    /// The loopback port the host sandboxes send their commands' traffic to,
    /// when the policy opts in.
    pub proxy_port: Option<u16>,
    /// Claude Code's settings.
    pub claude: claude::Generated,
    /// Codex's permissions profile.
    pub codex: codex::Generated,
    /// Cursor's `sandbox.json` keys.
    pub cursor: cursor::Generated,
}

/// `policy`, with the default policy's `sandbox.read_roots` when it has no
/// `sandbox` key, and whether they were filled in.
fn with_read_roots(policy: &Policy) -> anyhow::Result<(Policy, bool)> {
    let mut policy = policy.clone();
    let filled = policy.sandbox.is_none();
    if filled {
        policy.sandbox = Policy::parse(openmoat_core::DEFAULT_POLICY)?.sandbox;
    }
    Ok((policy, filled))
}

/// What a `moat run` session adds to the IR (Lightweight tier).
#[derive(Debug, Clone, Default)]
pub struct Grants {
    /// The loopback port of OpenMoat's egress proxy, the only network destination.
    pub proxy_port: Option<u16>,
    /// The temp directory, resolved, which commands may read and write.
    pub tmpdir: Option<String>,
    /// The program `moat run` starts, resolved: it must be readable to start.
    pub program: Option<String>,
    /// Paths given to `moat run --write`, resolved, which commands may read
    /// and write (the agent's own state).
    pub writes: Vec<String>,
}

/// The IR of a `moat run` session in `ctx`, and `grants` plus this process's
/// temp directory.
fn lower_for_session(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<(Enforcement, Grants)> {
    let (policy, _) = with_read_roots(policy)?;
    let tmpdir = std::fs::canonicalize(std::env::temp_dir())
        .ok()
        .map(|dir| crate::context::path_string(&dir));
    Ok((
        openmoat_core::ir::lower(&policy, ctx)?,
        Grants { tmpdir, ..grants },
    ))
}

/// The Seatbelt profile `moat run` applies on macOS.
pub fn seatbelt_profile(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<seatbelt::Generated> {
    let (ir, grants) = lower_for_session(policy, ctx, grants)?;
    Ok(seatbelt::generate(&ir, &grants))
}

/// The Landlock rules `moat run` applies on Linux.
pub fn landlock_rules(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<landlock::Generated> {
    let (ir, grants) = lower_for_session(policy, ctx, grants)?;
    landlock::generate(&ir, &grants)
}

/// The bubblewrap mounts and Landlock rules `moat run --isolate` applies on
/// Linux, for the project's spellings in `ctx` (the resolved one first).
#[cfg(target_os = "linux")]
pub fn bwrap_mounts(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<bwrap::Generated> {
    let (ir, grants) = lower_for_session(policy, ctx, grants)?;
    let project = ctx
        .real_project
        .iter()
        .chain(&ctx.project)
        .cloned()
        .collect::<Vec<_>>();
    bwrap::generate(&ir, &grants, &project)
}

/// Codex's `config.toml`, next to the hook file (`$CODEX_HOME` or `~/.codex`).
pub fn codex_config_path() -> anyhow::Result<std::path::PathBuf> {
    let hooks = crate::install::HostConfig::for_host(openmoat_hosts::Host::Codex)?.settings_path;
    Ok(codex_config_beside(&hooks))
}

/// Codex's `config.toml` next to its hook file `hooks`.
pub fn codex_config_beside(hooks: &std::path::Path) -> std::path::PathBuf {
    hooks.with_file_name("config.toml")
}

impl Plan {
    /// Generate every backend for `policy` and the current user's home.
    pub fn new(policy: &Policy) -> anyhow::Result<Self> {
        let (policy, default_read_roots) = with_read_roots(policy)?;
        let (home, real_home) = crate::context::home_spellings()?;
        let homes: Vec<String> = std::iter::once(home.clone())
            .chain(real_home.clone())
            .collect();
        let ir = lower_for_hosts(
            &policy,
            &home,
            real_home,
            crate::context::moved_dirs()?,
            crate::context::CASE_INSENSITIVE_PATHS,
        )?;
        let proxy_port = proxy_port(&policy);
        let mut claude = claude::generate(&ir, proxy_port, cfg!(target_os = "linux"))?;
        let claude_settings = install::settings_path(openmoat_hosts::Host::ClaudeCode)?;
        claude::protect(&mut claude, &claude_settings);
        let mut codex = codex::generate(&ir, &homes, proxy_port)?;
        if let Some(codex_home) = codex_config_path()?.parent() {
            codex::protect(&mut codex, codex_home);
        }
        if cfg!(target_os = "linux") {
            codex::read_own_binary(&mut codex, codex::own_binary().as_deref());
            codex::deny_names(&mut codex);
        }
        Ok(Self {
            default_read_roots,
            proxy_port,
            claude,
            codex,
            cursor: cursor::generate(&ir, proxy_port)?,
        })
    }
}

/// How one backend's output differs from the IR.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Where the host is stricter than the IR.
    pub losses: Vec<Loss>,
    /// Where the host is wider than the IR, the IR's own allowances included.
    pub allowances: Vec<Allowance>,
}

impl Report {
    fn loss(&mut self, kind: openmoat_core::Kind, rule: &str, message: String) {
        let loss = Loss {
            kind,
            rule: rule.to_owned(),
            message,
        };
        if !self.losses.contains(&loss) {
            self.losses.push(loss);
        }
    }

    fn allowance(
        &mut self,
        kind: openmoat_core::Kind,
        rule: &str,
        patterns: Vec<String>,
        message: &str,
    ) {
        self.allowances.push(Allowance {
            kind,
            rule: rule.to_owned(),
            patterns,
            message: message.to_owned(),
        });
    }

    /// The Lightweight tier reaches the hosts `net` allows only through OpenMoat's
    /// proxy, so a program that ignores the proxy settings reaches none.
    fn proxy_only(&mut self, net: &Access) {
        if net.default == Effect::Allow {
            let message = "every host is reachable only through OpenMoat's proxy";
            self.loss(openmoat_core::Kind::Net, "default.net", message.into());
        }
        for rule in &net.allow {
            let message = "these hosts are reachable only through OpenMoat's proxy: a program that \
                           ignores HTTP(S)_PROXY cannot reach them";
            self.loss(openmoat_core::Kind::Net, &rule.id, message.into());
        }
    }
}

/// Compare `actual` with `tests/fixtures/sandbox/<name>`; `MOAT_UPDATE_GOLDEN=1`
/// rewrites the file instead.
#[cfg(test)]
pub fn assert_golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/sandbox")
        .join(name);
    if std::env::var_os("MOAT_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        actual,
        expected,
        "MOAT_UPDATE_GOLDEN=1 updates {}",
        path.display()
    );
}
