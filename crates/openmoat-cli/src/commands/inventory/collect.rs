//! What `openmoat inventory` reads (ADR-119): one machine's state, from the
//! same checks `openmoat status` and `doctor` make, as a document with no
//! secret and no file's contents in it. Paths are written with the person's
//! home as `~`, and every text passes the audit log's redaction
//! ([`redacted`]). The host name is never read: the machine is named only by
//! the `machine:` of an accepted delivery configuration.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;
use serde::Serialize;
use serde_json::Value;

use crate::heartbeat::Loaded;
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::Lock;
use crate::protection::{self, Level};

/// The document's `format`; a new shape gets a new value.
pub const FORMAT: &str = "openmoat-inventory-v1";

/// One machine's inventory.
#[derive(Debug, Serialize)]
pub struct Inventory {
    pub format: &'static str,
    pub openmoat_version: &'static str,
    pub generated_ms: i64,
    pub machine: Machine,
    pub agents: Vec<Agent>,
    pub run_tiers: Vec<RunTier>,
    pub foreign_hooks: ForeignHooks,
    pub mcp_servers: Vec<McpServer>,
    pub mcp_proxied: Vec<McpProxied>,
    pub policy: PolicyState,
    pub lock: LockState,
    pub audit: AuditState,
}

#[derive(Debug, Serialize)]
pub struct Machine {
    /// The `machine:` of the accepted delivery configuration, if any.
    pub name: Option<String>,
    pub os: &'static str,
    pub arch: &'static str,
}

/// One agent OpenMoat knows.
#[derive(Debug, Serialize)]
pub struct Agent {
    pub id: &'static str,
    pub name: &'static str,
    /// Its configuration directory is on this machine.
    pub present: bool,
    /// What its program on the search path reports.
    pub version: Option<String>,
    /// OpenMoat's hook or plugin is installed for it, and current.
    pub hook_installed: bool,
    /// Whether the agent ran OpenMoat's hook since it last changed (ADR-104).
    pub hook_liveness: Option<Loaded>,
    pub protection: AgentProtection,
}

#[derive(Debug, Serialize)]
pub struct AgentProtection {
    pub level: Level,
    /// `hook-and-os-sandbox`, `openmoat-run` (a sandboxed start, ADR-106),
    /// `hook-only` or `none`.
    pub tier: &'static str,
    /// The protection score of the tier (ADR-108): `openmoat run`'s here for
    /// `openmoat-run`, 0 for the hook alone; `None` for an agent's own
    /// sandbox, which the score does not weigh, and for no hook.
    pub score: Option<u32>,
    pub reason: Option<String>,
    /// Whether it meets the level the policy requires (ADR-064).
    pub required_met: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RunTier {
    pub tier: &'static str,
    pub score: Option<u32>,
    pub complete: bool,
}

/// The foreign-hook ledger (ADR-109), as counts.
#[derive(Debug, Default, Serialize)]
pub struct ForeignHooks {
    /// `hooks.foreign` in force.
    pub mode: &'static str,
    pub recorded: usize,
    /// New or changed, waiting for `openmoat hooks accept`.
    pub waiting: usize,
    /// Of those, the ones that hold the agent's calls.
    pub holding: usize,
}

/// One MCP server definition the agents read.
#[derive(Debug, Serialize)]
pub struct McpServer {
    pub host: String,
    pub name: String,
    pub file: String,
    /// The lock pins its definition (ADR-026).
    pub pinned: bool,
    /// The first 16 hex digits of the pinned definition's digest.
    pub digest: Option<String>,
    /// The package release the pin records (ADR-114).
    pub release: Option<Release>,
    pub protected: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Release {
    pub ecosystem: String,
    pub package: String,
    pub version: Option<String>,
    pub integrity: Option<String>,
}

/// A server `openmoat mcp proxy` pinned the tools of.
#[derive(Debug, Serialize)]
pub struct McpProxied {
    pub server: String,
    pub tools: usize,
    pub held: usize,
}

#[derive(Debug, Serialize)]
pub struct PolicyState {
    /// SHA-256 of `policy.yaml`.
    pub sha256: Option<String>,
    pub version: Option<u32>,
    /// `team` when a team bundle is joined, else `local`.
    pub source: &'static str,
    pub team: Option<Team>,
    pub packs: Vec<String>,
    pub deny_rules: usize,
    pub allow_rules: usize,
    pub review_rules: usize,
    /// Why the policy does not load; every call is denied then.
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Team {
    pub name: String,
    pub serial: u64,
    pub signer: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct LockState {
    pub present: bool,
    pub intact: bool,
    pub pinned: usize,
    pub drifted: usize,
}

#[derive(Debug, Serialize)]
pub struct AuditState {
    pub events: Option<u64>,
    /// The checkpoint signing key's fingerprint (ADR-110).
    pub signing_key: Option<String>,
    pub checkpoint: Option<CheckpointState>,
}

#[derive(Debug, Serialize)]
pub struct CheckpointState {
    pub size: u64,
    /// The log still holds what it states.
    pub holds: bool,
}

/// This machine's inventory.
pub fn collect(home: &Home, binary: &Path, now_ms: i64) -> Result<Inventory> {
    crate::install::host_version::prefetch_present(home);
    let lock = Lock::load(&home.lock_path()).ok();
    let delivery = crate::delivery::load_pinned(home).ok().flatten();
    Ok(Inventory {
        format: FORMAT,
        openmoat_version: env!("CARGO_PKG_VERSION"),
        generated_ms: now_ms,
        machine: Machine {
            name: delivery.map(|(config, _)| config.machine),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        },
        agents: agents(home, binary)?,
        run_tiers: run_tiers(),
        foreign_hooks: foreign_hooks(home, binary, lock.as_ref()),
        mcp_servers: mcp_servers(home, binary, lock.as_ref()),
        mcp_proxied: crate::mcp::tools::all(home)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, pins)| McpProxied {
                server: pins.server.clone(),
                tools: pins.tools.len(),
                held: pins.held_count(),
            })
            .collect(),
        policy: policy(home),
        lock: lock_state(home, lock.as_ref()),
        audit: audit(home),
    })
}

fn agents(home: &Home, binary: &Path) -> Result<Vec<Agent>> {
    let liveness = crate::heartbeat::all(home, binary);
    let shims = crate::start::Record::load(home).unwrap_or_default();
    let run_score = run_tiers()
        .into_iter()
        .find(|t| t.tier != HOOK_ONLY)
        .and_then(|t| t.score);
    let mut out = Vec::new();
    for found in protection::report(home, binary)? {
        let Some(host) = Host::ALL.into_iter().find(|h| h.id() == found.host) else {
            continue;
        };
        let present = HostConfig::for_host(home, host).is_ok_and(|c| c.host_present());
        let shimmed = shims.shims.iter().any(|s| s.host == found.host);
        let (tier, score) = match found.level {
            Level::HookAndOsSandbox => ("hook-and-os-sandbox", None),
            Level::HookOnly if shimmed => ("openmoat-run", run_score),
            Level::HookOnly => (HOOK_ONLY, Some(0)),
            Level::NotProtected | Level::NotSetUp | Level::NotFound => ("none", None),
        };
        out.push(Agent {
            id: found.host,
            name: found.name,
            present,
            version: present
                .then(|| crate::install::host_version::reported(host))
                .flatten(),
            hook_installed: found.level.hooked(),
            hook_liveness: liveness
                .iter()
                .find(|l| l.host == found.host)
                .map(|l| l.loaded.clone()),
            protection: AgentProtection {
                level: found.level,
                tier,
                score,
                reason: found.reason.clone(),
                required_met: found.required.as_ref().map(|r| r.met),
            },
        });
    }
    Ok(out)
}

/// The tier name of the hook alone.
const HOOK_ONLY: &str = "hook-only";

fn run_tiers() -> Vec<RunTier> {
    crate::commands::run::score::tiers()
        .into_iter()
        .map(|t| RunTier {
            tier: t.tier,
            score: t.score.as_ref().map(|s| s.points),
            complete: t
                .score
                .as_ref()
                .is_some_and(openmoat_core::boundary::ProtectionScore::complete),
        })
        .collect()
}

fn foreign_hooks(home: &Home, binary: &Path, lock: Option<&Lock>) -> ForeignHooks {
    let mode = home
        .load_policy()
        .map(|p| p.foreign_hooks())
        .unwrap_or_default();
    let mode_name = match mode {
        openmoat_core::ForeignHooks::Hold => "hold",
        openmoat_core::ForeignHooks::Warn => "warn",
    };
    let Some(lock) = lock else {
        return ForeignHooks {
            mode: mode_name,
            ..ForeignHooks::default()
        };
    };
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(home, binary);
    match crate::hook_ledger::review_here(home, lock, &hosts, cwd.as_deref()) {
        Ok(found) => ForeignHooks {
            mode: mode_name,
            recorded: found.pin_count,
            waiting: found.changes.len(),
            holding: found.changes.iter().filter(|c| c.holds(found.mode)).count(),
        },
        Err(_) => ForeignHooks {
            mode: mode_name,
            ..ForeignHooks::default()
        },
    }
}

fn mcp_servers(home: &Home, binary: &Path, lock: Option<&Lock>) -> Vec<McpServer> {
    let cwd = std::env::current_dir().ok();
    let status = crate::mcp::status::report(home, binary, cwd.as_deref())
        .map(|r| r.servers)
        .unwrap_or_default();
    let pins = lock.and_then(|l| l.mcp_servers.clone()).unwrap_or_default();
    let mut out: Vec<McpServer> = pins
        .values()
        .map(|pin| McpServer {
            host: pin.host.clone(),
            name: pin.name.clone(),
            file: pin.file.clone(),
            pinned: true,
            digest: Some(pin.digest.chars().take(16).collect()),
            release: pin.provenance.as_ref().map(|p| Release {
                ecosystem: p.ecosystem.clone(),
                package: p.package.clone(),
                version: p.version.clone(),
                integrity: p.integrity.clone(),
            }),
            protected: status
                .iter()
                .find(|s| s.host == pin.host && s.name == pin.name)
                .map(|s| s.protected),
        })
        .collect();
    for server in &status {
        if !out
            .iter()
            .any(|s| s.host == server.host && s.name == server.name)
        {
            out.push(McpServer {
                host: server.host.to_owned(),
                name: server.name.clone(),
                file: server.file.to_string_lossy().into_owned(),
                pinned: false,
                digest: None,
                release: None,
                protected: Some(server.protected),
            });
        }
    }
    out
}

fn policy(home: &Home) -> PolicyState {
    let bytes = std::fs::read(home.policy_path()).ok();
    let joined = crate::team::joined(home).ok().flatten();
    let packs = crate::packs::Packs::load(&home.packs_path())
        .map(|p| p.packs.into_keys().collect())
        .unwrap_or_default();
    let loaded = home.load_policy();
    let (deny, allow, review) = loaded
        .as_ref()
        .map(openmoat_core::Policy::rule_count)
        .unwrap_or_default();
    PolicyState {
        sha256: bytes.as_deref().map(crate::integrity::sha256_hex),
        version: loaded.as_ref().ok().map(|p| p.version),
        source: if joined.is_some() { "team" } else { "local" },
        team: joined.map(|j| Team {
            name: j.name,
            serial: j.serial,
            signer: j.signer,
            manifest_sha256: j.manifest_sha256,
        }),
        packs,
        deny_rules: deny,
        allow_rules: allow,
        review_rules: review,
        error: loaded.err().map(|e| format!("{e:#}")),
    }
}

fn lock_state(home: &Home, lock: Option<&Lock>) -> LockState {
    let drifted = lock.map(|l| l.verify().len()).unwrap_or_default();
    LockState {
        present: home.lock_path().is_file(),
        intact: lock.is_some() && drifted == 0,
        pinned: lock.map(|l| l.entries.len()).unwrap_or_default(),
        drifted,
    }
}

fn audit(home: &Home) -> AuditState {
    let store = home.open_audit().ok();
    let events = store.as_ref().and_then(|s| s.count().ok());
    let key = crate::audit_signing::read(home).ok().flatten();
    let checkpoint = key.as_ref().and_then(|key| {
        let (_, note) = crate::audit_signing::latest(home, key.verifier())?;
        let cp = openmoat_audit::Checkpoint::open(&note, key.verifier()).ok()?;
        let holds = store
            .as_ref()
            .and_then(|s| s.check_checkpoint(&cp).ok())
            .is_some_and(openmoat_audit::CheckpointCheck::holds);
        Some(CheckpointState {
            size: cp.size,
            holds,
        })
    });
    AuditState {
        events,
        signing_key: key.map(|k| k.verifier().fingerprint()),
        checkpoint,
    }
}

/// `value` with the person's home written as `~` in every text and every
/// text redacted as the audit log is (`openmoat_audit::redact`).
pub fn redacted(value: Value) -> Value {
    // The home as the platform writes it and in the slash form of `paths.rs`.
    let homes: Vec<String> = crate::home::user_home()
        .ok()
        .map(|h| {
            let native = h.to_string_lossy().into_owned();
            let slashed = native.replace('\\', "/");
            vec![native, slashed]
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|h| h.len() > 1)
        .collect();
    tilde(openmoat_audit::redact_value(value), &homes)
}

/// `value` with each of `homes` in a text written as `~`.
pub fn tilde(value: Value, homes: &[String]) -> Value {
    match value {
        Value::String(text) => Value::String(
            homes
                .iter()
                .fold(text, |text, home| text.replace(home.as_str(), "~")),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(|v| tilde(v, homes)).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, tilde(v, homes))).collect())
        }
        other => other,
    }
}
