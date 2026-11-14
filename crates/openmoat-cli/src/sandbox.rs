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
//! the same Landlock rules. There the agent itself runs inside the sandbox, so
//! `moat run` lowers a policy that keeps the agent's own login readable
//! ([`own_login`]); the host sandboxes deny every agent's login to commands.

pub mod backend;
// Its tests walk real Unix paths, so they run on macOS too, not on Windows.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub mod bwrap;
// The host sandbox backends, one per format a host's spec names: with
// `backend_of` below, the one place that lists them.
pub mod claude;
pub mod codex;
pub mod cursor;
#[cfg(test)]
mod differential;
pub mod exposure;
pub mod git_env;
#[cfg(test)]
mod hook_only;
pub mod install;
pub mod kerberos;
pub mod landlock;
mod links;
pub mod own_login;
mod patterns;
pub(crate) use patterns::RUNS_LATER;
mod plan;
pub use plan::Plan;
pub mod seatbelt;
#[cfg(any(target_os = "linux", test))]
pub mod seccomp;
pub mod shared_temp;

/// The backend that writes `format`: the one list of host sandbox backends,
/// with their module declarations above. The match is exhaustive, so a format
/// a host's spec can name without a backend fails to compile.
pub fn backend_of(format: openmoat_hosts::SandboxFormat) -> &'static dyn backend::SandboxBackend {
    use openmoat_hosts::SandboxFormat;
    match format {
        SandboxFormat::ClaudeSettings => &claude::backend::BACKEND,
        SandboxFormat::CodexProfile => &codex::backend::BACKEND,
        SandboxFormat::CursorSandbox => &cursor::backend::BACKEND,
    }
}

use openmoat_core::ir::{Access, Allowance, Effect, Enforcement, Loss};
use openmoat_core::{EvalContext, Policy, PolicyError};
use serde::Serialize;

/// Stand-in for the session's project in a host-wide lowering. Never a real
/// directory: it only marks the patterns that name `${project}`.
pub const PROJECT: &str = "/__moat_project__";

/// The rule id of the policy's `defaults: net`, which a backend reports when
/// it cannot reproduce an allow-by-default network.
pub const DEFAULT_NET_RULE: &str = "default.net";

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
    /// The temp directory, resolved, which commands may read and write: the
    /// run's own (`commands/run/temp.rs`), or, when `None`, this process's
    /// (`--isolate`, which covers it with an empty `tmpfs`).
    pub tmpdir: Option<String>,
    /// The program `moat run` starts, resolved: it must be readable to start.
    pub program: Option<String>,
    /// Paths given to `moat run --write`, resolved, which commands may read
    /// and write (the agent's own state).
    pub writes: Vec<String>,
    /// The terminal devices `moat run`'s standard input, output and error are
    /// on, resolved: besides `/dev/tty` (the controlling terminal) the only
    /// terminals commands may open, so none of the person's other terminals.
    pub terminals: Vec<String>,
    /// The directory of the run's CA files (ADR-043), resolved, inside the
    /// temp directory, which commands may read already. Under `--isolate`,
    /// whose temp directory starts empty, it is bound in read-only.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only the Linux `--isolate` tier binds it in")
    )]
    pub trust: Option<String>,
    /// The tool-shell wrapper of this run (ADR-075), read-only for commands.
    pub tool_shell: Option<ToolShellGrant>,
}

/// The paths the tool-shell wrapper needs (`commands/run/tool_shell.rs`).
#[derive(Debug, Clone)]
pub struct ToolShellGrant {
    /// Its directory, resolved.
    pub dir: String,
    /// The `openmoat` binary the wrapper's links name, resolved.
    pub moat: String,
}

/// The IR of a `moat run` session in `ctx`, and `grants` with this process's
/// temp directory where they name none of the run's own.
fn lower_for_session(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<(Enforcement, Grants)> {
    let (policy, _) = with_read_roots(policy)?;
    let tmpdir = grants.tmpdir.clone().or_else(session_tmpdir);
    Ok((
        openmoat_core::ir::lower(&policy, ctx)?,
        Grants { tmpdir, ..grants },
    ))
}

/// This process's temp directory, resolved: what `moat run --isolate` covers
/// with an empty `tmpfs`, and what holds the run's own.
pub fn session_tmpdir() -> Option<String> {
    std::fs::canonicalize(std::env::temp_dir())
        .ok()
        .map(|dir| crate::context::path_string(&dir))
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

/// The Landlock rules `moat run` applies on Linux where no mount can cover
/// paths inside the project (no network namespace): the project granted entry
/// by entry ([`landlock::entries`], ADR-090). With them, the paths the policy
/// denies in the project that stay open to commands, or why they could not be
/// listed.
#[cfg(target_os = "linux")]
pub fn landlock_entries(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
) -> anyhow::Result<(landlock::Generated, Result<Vec<String>, String>)> {
    let (ir, grants) = lower_for_session(policy, ctx, grants)?;
    let mut generated = landlock::generate(&ir, &grants)?;
    let project = project_spellings(ctx);
    let landlock::Generated { rules, report } = &mut generated;
    landlock::entries::split_project(&ir, rules, report, &project)?;
    let open = match project.first() {
        Some(real) => bwrap::project_masks(&ir, std::slice::from_ref(real))
            .map(|masks| landlock::entries::open(&masks.mounts, &generated.rules))
            .map_err(|error| format!("{error:#}")),
        None => Ok(Vec::new()),
    };
    Ok((generated, open))
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
    bwrap::generate(&ir, &grants, &project_spellings(ctx))
}

/// The masks `moat run`'s network namespace on Linux adds over the paths deny
/// rules name inside the read roots and `--write` paths of `rules`
/// ([`bwrap::grant_masks`]).
#[cfg(target_os = "linux")]
pub fn netns_masks(
    policy: &Policy,
    ctx: &EvalContext,
    rules: &landlock::Rules,
) -> anyhow::Result<Vec<bwrap::Mount>> {
    let (ir, _) = lower_for_session(policy, ctx, Grants::default())?;
    bwrap::grant_masks(&ir, rules, &project_spellings(ctx))
}

/// The masks `moat run`'s network namespace on Linux adds over the project of
/// `ctx`, as the Isolated tier's, with the placeholders it creates
/// ([`bwrap::project_masks`], ADR-090).
#[cfg(target_os = "linux")]
pub fn netns_project_masks(
    policy: &Policy,
    ctx: &EvalContext,
) -> anyhow::Result<bwrap::ProjectMasks> {
    let (ir, _) = lower_for_session(policy, ctx, Grants::default())?;
    bwrap::project_masks(&ir, &project_spellings(ctx))
}

/// [`netns_project_masks`] for the project's top and the folders directly in
/// it only, where the whole walk failed ([`bwrap::project_masks_near_top`]).
#[cfg(target_os = "linux")]
pub fn netns_project_masks_near_top(
    policy: &Policy,
    ctx: &EvalContext,
) -> anyhow::Result<bwrap::ProjectMasks> {
    let (ir, _) = lower_for_session(policy, ctx, Grants::default())?;
    bwrap::project_masks_near_top(&ir, &project_spellings(ctx))
}

/// The agents' hook settings missing in the project of `ctx`, which `moat
/// run` on Linux without a network namespace cannot cover
/// ([`bwrap::missing_hook_settings`]).
#[cfg(target_os = "linux")]
pub fn missing_hook_settings(policy: &Policy, ctx: &EvalContext) -> anyhow::Result<Vec<String>> {
    let (ir, _) = lower_for_session(policy, ctx, Grants::default())?;
    Ok(bwrap::missing_hook_settings(&ir, &project_spellings(ctx)))
}

/// The paths `kernel-self` keeps from commands (OpenMoat's state, an agent's
/// hook settings) that lie in one of `writes`, the `moat run --write` paths,
/// each with the path that holds it. Landlock cannot deny inside a grant, so
/// without a network namespace on Linux these would be open to commands
/// ([`exposure::kernel_self_refusal`]). A write path counts when it holds an
/// absolute rule's path or lies inside a tree one denies (`~/.codex/**` holds
/// `--write ~/.codex/sessions`). A `**/` rule matches at any depth, so every
/// write path outside the project holds it (another repository's hook
/// settings); inside the project it stays the hook's.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub fn kernel_self_in_writes(
    policy: &Policy,
    ctx: &EvalContext,
    writes: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    let (ir, _) = lower_for_session(policy, ctx, Grants::default())?;
    let ci = crate::context::CASE_INSENSITIVE_PATHS;
    let projects: Vec<&String> = ctx.project.iter().chain(&ctx.real_project).collect();
    let in_project = |w: &str| projects.iter().any(|p| exposure::within(w, p, ci));
    let mut held: Vec<(String, String)> = Vec::new();
    let mut record = |holder: &str, path: String| {
        if !held.iter().any(|(_, p)| *p == path) {
            held.push((holder.to_owned(), path));
        }
    };
    let rules = ir.fs.write.deny.iter().chain(&ir.fs.read.deny);
    for rule in rules.filter(|r| r.id == KERNEL_SELF_RULE) {
        for pattern in patterns::split(&rule.patterns).0 {
            if let Some(rest) = pattern.strip_prefix("**/") {
                for write in writes.iter().filter(|w| !in_project(w)) {
                    record(write, format!("{}/**/{rest}", write.trim_end_matches('/')));
                }
                continue;
            }
            let base = pattern
                .split(['*', '?', '[', '{'])
                .next()
                .unwrap_or(pattern);
            let base = base.trim_end_matches('/');
            if !base.starts_with('/') {
                continue;
            }
            // `dir/**` denies the whole tree, so a write path inside it is held too.
            let tree = pattern.strip_suffix("/**") == Some(base);
            // The writes are resolved: compare where the rule's path resolves
            // (`~/.claude/settings.json` with `~/.claude` a link). Linux only,
            // where this refusal applies; elsewhere a made-up path in a test
            // would resolve by the machine (macOS links `/home`).
            #[cfg(target_os = "linux")]
            let base = links::real_path(base);
            #[cfg(not(target_os = "linux"))]
            let base = base.to_owned();
            let base = base.as_str();
            let holder = writes
                .iter()
                .find(|w| exposure::within(base, w, ci) || (tree && exposure::within(w, base, ci)));
            if let Some(holder) = holder {
                record(holder, pattern.to_owned());
            }
        }
    }
    Ok(held)
}

/// The rule id of the default policy's self-protection.
#[cfg(any(target_os = "linux", test))]
#[cfg(any(target_os = "linux", all(test, unix)))]
const KERNEL_SELF_RULE: &str = "kernel-self";

/// The project's spellings in `ctx`, the resolved one first.
#[cfg(target_os = "linux")]
fn project_spellings(ctx: &EvalContext) -> Vec<String> {
    ctx.real_project
        .iter()
        .chain(&ctx.project)
        .cloned()
        .collect()
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
        // two policy rules may need the same allowance; it is reported once
        if self.allowances.iter().any(|a| {
            a.kind == kind && a.rule == rule && a.patterns == patterns && a.message == message
        }) {
            return;
        }
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
            self.loss(openmoat_core::Kind::Net, DEFAULT_NET_RULE, message.into());
        }
        for rule in &net.allow {
            let message = "these hosts are reachable only through OpenMoat's proxy: a program that \
                           ignores HTTP(S)_PROXY cannot reach them";
            self.loss(openmoat_core::Kind::Net, &rule.id, message.into());
        }
    }
}

/// Compare `actual` with `tests/fixtures/sandbox/<name>`; `OPENMOAT_TEST_UPDATE_GOLDEN=1`
/// rewrites the file instead.
#[cfg(test)]
pub fn assert_golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/sandbox")
        .join(name);
    if std::env::var_os("OPENMOAT_TEST_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        actual,
        expected,
        "OPENMOAT_TEST_UPDATE_GOLDEN=1 updates {}",
        path.display()
    );
}
