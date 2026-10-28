//! The proxy's [`Gate`] (ADR-045): what may reach the MCP server, and the
//! audit row each call leaves.
//!
//! A `tools/call` the pins let through passes only when both hold:
//! - the policy, with the lock intact, does not deny it as it is about to
//!   reach the server: the name `mcp__<server>__<tool>` and every path and URL
//!   its arguments name, read as the hook reads them;
//! - the hook let exactly this call through: a decision for the same tool and
//!   arguments, under an hour old and not used before (`mcp_tickets`). That
//!   decision carries what only the hook knows (the session's taint, a grant,
//!   the person's answer to an `ask`), and it names the session: the row this
//!   call leaves carries the hook's session and call id. A call no hook decided
//!   (a host that skipped its hook, or arguments changed after it ran) is
//!   refused.
//!
//! `resources/read` is decided on the policy alone (a `file:` URI as the file
//! it names, any other as a host): a host also reads resources for the person,
//! with no hook. `prompts/get` and the server's own requests are recorded.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context as _, Result};
use openmoat_audit::{KnownSecrets, NewEvent, Store, Ticket};
use openmoat_core::{Action, CompiledPolicy, Decision, Verdict};
use openmoat_hosts::Host;
use serde_json::Value;

use crate::environment::{Snapshot, WithOwnBinary};
use crate::home::Home;
use crate::mcp::relay::{Call, Gate, Method};
use crate::realpath::FsPathResolver;
use crate::{context, integrity, secrets};

/// Host id of the proxy's audit rows.
const AUDIT_HOST: &str = "mcp-proxy";
/// Rule ids of the proxy's decisions.
const PASSED_RULE: &str = "mcp-proxy";
const HELD_RULE: &str = "mcp-tool-held";
const UNATTRIBUTED_RULE: &str = "mcp-unattributed";
const SERVER_REQUEST_RULE: &str = "mcp-server-request";

pub struct Gateway {
    home: Home,
    server: String,
    /// Where the host started the server: the context of a call no hook
    /// decision names a directory for.
    cwd: PathBuf,
    /// The session of rows no hook decision names.
    session: String,
}

/// What the gateway made of one call.
struct Outcome {
    action: Action,
    decision: Decision,
    /// The hook's decision the call matched.
    ticket: Option<Ticket>,
    /// The directory the call was decided in.
    cwd: Option<String>,
    /// The brokered secret values the row masks, from the policy that
    /// decided the call.
    known: KnownSecrets,
}

impl Gateway {
    pub fn new(home: Home, server: &str) -> Result<Self> {
        Ok(Self {
            home,
            server: server.to_owned(),
            cwd: std::env::current_dir().context("reading the working directory")?,
            session: format!(
                "mcp-{server}-{}-{}",
                std::process::id(),
                crate::time::now_ms()
            ),
        })
    }

    /// The name the policy and the audit log give `call`.
    fn name(&self, call: &Call<'_>) -> String {
        match call.method {
            Method::Tool | Method::Prompt => format!("mcp__{}__{}", self.server, call.name),
            Method::Resource => format!("mcp__{}__read_resource", self.server),
        }
    }

    fn decide(&self, call: &Call<'_>, store: &Store) -> Result<Outcome> {
        let name = self.name(call);
        let none = Value::Null;
        let action = match call.method {
            Method::Tool => {
                openmoat_hosts::mcp_call_action(&name, call.arguments.unwrap_or(&none))?
            }
            Method::Resource => openmoat_hosts::mcp_resource_action(&self.server, call.name)?,
            Method::Prompt => {
                let decision = Decision::single(Verdict::Allow, PASSED_RULE, "a prompt, recorded");
                return Ok(self.outcome(Action::mcp(name), decision, None, None));
            }
        };
        // Taken before the policy is read: the hook's directory is the
        // context the call is decided in, as the hook decided it.
        let ticket = match call.method {
            Method::Tool => self.take_ticket(store, call)?,
            _ => None,
        };
        let cwd = match &ticket {
            Some(t) => store.get(t.event_id)?.and_then(|e| e.cwd),
            None => None,
        };
        let (decided, known) = self.policy(&action, cwd.as_deref())?;
        let decision = match (&ticket, call.method) {
            _ if decided.verdict == Verdict::Deny => decided,
            (None, Method::Tool) => Decision::single(
                Verdict::Deny,
                UNATTRIBUTED_RULE,
                "OpenMoat's hook made no decision on this exact call (the same tool and \
                 arguments, within the hour): the host did not run the hook for it, or sent \
                 other arguments than it checked, so it is not passed on",
            ),
            (Some(t), _) => Decision::single(
                Verdict::Allow,
                PASSED_RULE,
                format!(
                    "passed to the server: the hook decided `{}` for this call (event {})",
                    t.verdict, t.event_id.0
                ),
            ),
            (None, _) => Decision::single(Verdict::Allow, PASSED_RULE, "passed to the server"),
        };
        Ok(Outcome {
            action,
            decision,
            ticket,
            cwd,
            known,
        })
    }

    /// The hook's decision for `call`, taken so it lets no second call through.
    fn take_ticket(&self, store: &Store, call: &Call<'_>) -> Result<Option<Ticket>> {
        let arguments = openmoat_hosts::mcp_call_arguments(call.arguments);
        let digest = integrity::sha256_hex(arguments.as_bytes());
        let (server, tool) = (self.server.as_str(), call.name);
        Ok(store.take_mcp_ticket(&digest, |t| {
            t.host
                .parse::<Host>()
                .is_ok_and(|host| names_tool(host, &t.tool, server, tool))
        })?)
    }

    /// The policy's decision for `action` in `cwd` (the server's own when
    /// `None`), with the lock checked first as the hook checks it, and the
    /// brokered secrets that policy names.
    fn policy(&self, action: &Action, cwd: Option<&str>) -> Result<(Decision, KnownSecrets)> {
        let verified = integrity::check(&self.home)?;
        if let Some(deny) = verified.checked.deny {
            return Ok((deny, self.known()));
        }
        let home = verified.home;
        let cwd = cwd.map_or_else(|| self.cwd.clone(), PathBuf::from);
        let ctx = context::eval_context(&home, Some(&cwd), None)?;
        let policy = crate::repo::effective_policy(&home, &ctx)?;
        let compiled = CompiledPolicy::compile(&policy, &ctx)?;
        let snapshot = Snapshot::load_in(&home)?;
        let programs = WithOwnBinary {
            snapshot: &snapshot,
            binary: &verified.lock.binary,
        };
        let known = secrets::known(&policy.secrets, &ctx.home)?;
        Ok((
            compiled.decide_with(action, &programs, &FsPathResolver),
            known,
        ))
    }

    /// The brokered secrets of the user's policy, for a row no policy decided;
    /// none when it cannot be read (the row names no arguments).
    fn known(&self) -> KnownSecrets {
        let Ok(policy) = self.home.load_policy() else {
            return KnownSecrets::default();
        };
        context::home_spellings()
            .and_then(|(home, _)| secrets::known(&policy.secrets, &home))
            .unwrap_or_default()
    }

    /// `outcome` for a call no policy decided.
    fn outcome(
        &self,
        action: Action,
        decision: Decision,
        ticket: Option<Ticket>,
        cwd: Option<String>,
    ) -> Outcome {
        Outcome {
            action,
            decision,
            ticket,
            cwd,
            known: self.known(),
        }
    }

    /// The audit log.
    fn store(&self) -> Result<Store> {
        Store::open_existing(&self.home.audit_path()).context("audit log unavailable")
    }

    /// Record `outcome`, masking the secrets its policy names as the hook's
    /// rows do.
    fn record(&self, store: Store, tool: &str, outcome: Outcome, started: Instant) -> Result<()> {
        let store = store.with_secrets(outcome.known);
        let ticket = outcome.ticket.as_ref();
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        store.record(&NewEvent {
            host: AUDIT_HOST,
            session_id: ticket.map_or(self.session.as_str(), |t| t.session_id.as_str()),
            call_id: ticket.and_then(|t| t.call_id.as_deref()),
            cwd: outcome.cwd.as_deref(),
            tool,
            action: Some(&outcome.action),
            decision: &outcome.decision,
            latency_us,
        })?;
        Ok(())
    }
}

impl Gate for Gateway {
    fn check(&self, call: &Call<'_>, held: Option<&str>) -> Result<Option<String>> {
        let started = Instant::now();
        let store = self.store()?;
        let name = self.name(call);
        let outcome = match held {
            Some(why) => self.outcome(
                Action::mcp(name.clone()),
                Decision::single(Verdict::Deny, HELD_RULE, why),
                None,
                None,
            ),
            None => self.decide(call, &store)?,
        };
        let refused = match outcome.decision.verdict {
            Verdict::Deny => Some(refusal(&outcome.decision)),
            _ => None,
        };
        self.record(store, &name, outcome, started)?;
        Ok(refused)
    }

    fn server_request(&self, method: &str) -> Result<()> {
        let store = self.store()?.with_secrets(self.known());
        let decision = Decision::single(
            Verdict::Allow,
            SERVER_REQUEST_RULE,
            format!("MCP server `{}` asked the agent: {method}", self.server),
        );
        store.record(&NewEvent {
            host: AUDIT_HOST,
            session_id: &self.session,
            call_id: None,
            cwd: None,
            tool: method,
            action: None,
            decision: &decision,
            latency_us: 0,
        })?;
        Ok(())
    }
}

/// What the host is told about a refused call.
fn refusal(decision: &Decision) -> String {
    let rules = decision.rules.join(", ");
    let reasons = decision.reasons.join("; ");
    format!("OpenMoat refused this call [{rules}]: {reasons}")
}

/// Whether `hook_name`, the MCP tool name `host`'s hook decided, names tool
/// `tool` of server `server`: the server as the host spells it
/// ([`crate::mcp::tool_of`]), then `__<tool>` (or `-<tool>` where the host
/// joins them so), the tool's name as written or with the characters a host
/// replaces in names as `_`.
pub(super) fn names_tool(host: Host, hook_name: &str, server: &str, tool: &str) -> bool {
    if tool.is_empty() || !crate::mcp::tool_of(host, hook_name, server) {
        return false;
    }
    let spelled = |keep: fn(char) -> bool| -> String {
        tool.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || keep(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let spellings = [
        tool.to_owned(),
        spelled(|c| c == '_' || c == '-'),
        spelled(|c| c == '_'),
    ];
    let joiner = if hook_name.starts_with("mcp__") {
        "__"
    } else {
        "-"
    };
    spellings
        .iter()
        .any(|t| hook_name.ends_with(&format!("{joiner}{t}")))
}

#[cfg(test)]
mod tests;
