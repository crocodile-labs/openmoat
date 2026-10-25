//! `moat doctor --bundle <FILE>`: one local file a person attaches to a bug
//! report themselves. Nothing is sent anywhere.
//!
//! The audit events in it keep only their time, host, tool name, verdict and
//! rule ids: never the command, path, URL, arguments or reasons. Every string
//! in the document then passes through `openmoat_audit::redact`, and the
//! home directory reads `~`.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_audit::{Event, Store};
use openmoat_core::DEFAULT_POLICY;
use openmoat_hosts::Host;
use serde::Serialize;
use serde_json::Value;

use super::json::Row;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::protection::{self, Level};

mod os;

const NOTICE: &str = "Written by `openmoat doctor --bundle` on this machine; nothing was sent. \
     Recent decisions keep only time, host, tool name, verdict and rule ids: no commands, \
     paths, arguments, URLs or file contents. The home directory reads `~`. Read the file \
     before you attach it to an issue.";

/// Everything the bundle is made from, gathered before it is scrubbed.
struct Facts<'a> {
    policy: PolicyFacts,
    agents: Vec<Agent>,
    doctor: &'a [Row],
    audit: AuditFacts,
}

#[derive(Serialize)]
struct Bundle<'a> {
    notice: &'static str,
    moat: Build,
    system: os::System,
    policy: PolicyFacts,
    agents: Vec<Agent>,
    doctor: &'a [Row],
    audit: AuditFacts,
}

#[derive(Serialize)]
struct Build {
    version: &'static str,
    /// The operating system and architecture this binary was built for.
    target: String,
    /// `release` or `debug`.
    profile: &'static str,
}

#[derive(Debug, Default, Serialize)]
struct PolicyFacts {
    loads: bool,
    /// Why the policy does not load.
    error: Option<String>,
    /// The policy's `version:`.
    version: Option<u32>,
    /// `moat policy lint` warnings.
    lint_warnings: Vec<String>,
    /// Whether `policy.yaml` is this release's default, unchanged.
    matches_default: Option<bool>,
    /// What `moat policy upgrade` would add, as `moat doctor` says it.
    default_changes: Option<String>,
}

#[derive(Debug, Serialize)]
struct Agent {
    host: &'static str,
    hook: &'static str,
    protection: Level,
    reason: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct AuditFacts {
    /// Why the audit log could not be read.
    error: Option<String>,
    /// Newest first.
    recent_decisions: Vec<Decision>,
}

/// One audit event, without anything the agent sent.
#[derive(Debug, Serialize)]
struct Decision {
    time: String,
    host: String,
    tool: String,
    verdict: &'static str,
    rules: Vec<String>,
}

impl From<&Event> for Decision {
    fn from(event: &Event) -> Self {
        Self {
            time: crate::time::timestamp(event.ts_ms),
            host: event.host.clone(),
            tool: event.tool.clone(),
            verdict: event.verdict.as_str(),
            rules: event.rules.clone(),
        }
    }
}

/// Write the bundle to `path`, which must not exist yet, and say where it is.
pub(super) fn write(
    home: &Home,
    binary: &Path,
    rows: &[Row],
    path: &Path,
    events: usize,
) -> Result<Code> {
    // Run by a person: an agent could otherwise have OpenMoat create a file for it.
    crate::terminal::refuse_agent("openmoat doctor --bundle")?;
    let facts = Facts {
        policy: policy_facts(home),
        agents: agents(home, binary)?,
        doctor: rows,
        audit: audit_facts(home, events),
    };
    let user_home = crate::home::user_home().ok();
    let mut text = serde_json::to_string_pretty(&document(facts, user_home.as_deref())?)?;
    text.push('\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "creating {}; name a file that does not exist yet",
                path.display()
            )
        })?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "wrote {}", path.display())?;
    writeln!(
        out,
        "Nothing was sent. Read the file before you attach it to an issue: it lists your \
         agents, the doctor checks, policy findings and the last {events} decisions \
         (time, host, tool name, verdict and rule ids only)."
    )?;
    Ok(Code::Ok)
}

/// The bundle as JSON, every string redacted and the home directory as `~`.
fn document(facts: Facts<'_>, user_home: Option<&Path>) -> Result<Value> {
    let bundle = Bundle {
        notice: NOTICE,
        moat: Build {
            version: crate::VERSION,
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
        },
        system: os::System::this(),
        policy: facts.policy,
        agents: facts.agents,
        doctor: facts.doctor,
        audit: facts.audit,
    };
    let value = openmoat_audit::redact_value(serde_json::to_value(&bundle)?);
    let homes = home_spellings(user_home);
    Ok(map_strings(value, &|text| {
        homes.iter().fold(text, |text, home| tilde(&text, home))
    }))
}

/// The home directory as paths spell it: as the system gives it and with `/`
/// separators. Empty for a home of `/` or none, which no path should lose.
fn home_spellings(user_home: Option<&Path>) -> Vec<String> {
    let Some(home) =
        user_home.map(|h| h.to_string_lossy().trim_end_matches(['/', '\\']).to_owned())
    else {
        return Vec::new();
    };
    if home.is_empty() {
        return Vec::new();
    }
    let slashed = home.replace('\\', "/");
    if slashed == home {
        vec![home]
    } else {
        vec![home, slashed]
    }
}

/// `text` with every whole occurrence of `home` as `~`: `/home/u/x` and
/// `/home/u` change, `/home/user2` does not.
fn tilde(text: &str, home: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(home) {
        let after = &rest[at + home.len()..];
        let whole = after
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.')));
        out.push_str(&rest[..at]);
        out.push_str(if whole { "~" } else { home });
        rest = after;
    }
    out.push_str(rest);
    out
}

fn map_strings(value: Value, f: &impl Fn(String) -> String) -> Value {
    match value {
        Value::String(text) => Value::String(f(text)),
        Value::Array(items) => Value::Array(items.into_iter().map(|v| map_strings(v, f)).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, v)| (key, map_strings(v, f)))
                .collect(),
        ),
        other => other,
    }
}

fn policy_facts(home: &Home) -> PolicyFacts {
    match home.load_policy() {
        Ok(policy) => PolicyFacts {
            loads: true,
            error: None,
            version: Some(policy.version),
            lint_warnings: openmoat_core::lint::warnings(&policy)
                .iter()
                .map(ToString::to_string)
                .collect(),
            matches_default: fs::read_to_string(home.policy_path())
                .ok()
                .map(|text| text.replace("\r\n", "\n") == DEFAULT_POLICY),
            default_changes: crate::upgrade::available(home),
        },
        Err(error) => PolicyFacts {
            error: Some(format!("{error:#}")),
            ..PolicyFacts::default()
        },
    }
}

fn agents(home: &Home, binary: &Path) -> Result<Vec<Agent>> {
    protection::report(home, binary)?
        .into_iter()
        .map(|agent| {
            let host: Host = agent.host.parse()?;
            let config = HostConfig::for_host(home, host)?;
            let hook = match config.state(binary) {
                HookState::Installed => "installed",
                HookState::Missing if !config.host_present() => "host not found",
                HookState::Missing => "missing",
                HookState::Stale { .. } => "out of date",
                HookState::Unreadable(_) => "unreadable",
                HookState::Unapproved(_) => "not approved",
            };
            Ok(Agent {
                host: agent.host,
                hook,
                protection: agent.level,
                reason: agent.reason,
            })
        })
        .collect()
}

fn audit_facts(home: &Home, events: usize) -> AuditFacts {
    match Store::open_read_only(&home.audit_path()).and_then(|store| store.recent(events)) {
        Ok(recent) => AuditFacts {
            error: None,
            recent_decisions: recent.iter().map(Decision::from).collect(),
        },
        Err(error) => AuditFacts {
            error: Some(error.to_string()),
            recent_decisions: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests;
