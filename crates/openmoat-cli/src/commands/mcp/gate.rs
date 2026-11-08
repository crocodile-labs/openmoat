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
//!   the person's answer to a `review`), and it names the session: the row this
//!   call leaves carries the hook's session and call id. A call no hook decided
//!   (a host that skipped its hook, or arguments changed after it ran) is
//!   refused.
//!
//! `resources/read` is decided on the policy alone (a `file:` URI as the file
//! it names, any other as a host): a host also reads resources for the person,
//! with no hook. `prompts/get` and the server's own requests are recorded.
//!
//! The answer to each `tools/call` passed on a hook decision, a result or an
//! error (whose `message` and `data` the model reads too), has its pieces
//! kept under that decision's session (`mcp/flow.rs`, ADR-058), so the hook
//! can tell when a later call carries them to another server, and the
//! fingerprints of what it names kept as injected input (ADR-057), so a later
//! call that acts on a host, path or command it planted needs review. That
//! works for every agent, also one whose host reports no call output
//! (ADR-063, proposed).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{KnownSecrets, NewEvent, Store, Ticket};
use openmoat_core::{Action, CompiledPolicy, Decision, Verdict};
use openmoat_hosts::Host;
use serde_json::Value;

use crate::environment::{Snapshot, WithOwnBinary};
use crate::home::Home;
use crate::mcp::names_tool;
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
    /// The host and session of each tool call passed on and not answered
    /// yet, by request id: where its result's pieces go (ADR-058).
    awaiting: Mutex<HashMap<String, Awaiting>>,
}

/// Whose tool call a result answers, and the call itself.
struct Awaiting {
    host: String,
    session: String,
    /// The call as the policy read it, for injected input (ADR-057).
    action: Action,
    /// The directory the hook decided it in.
    cwd: Option<String>,
}

/// The most passed calls awaiting a result the gateway keeps, as many as the
/// relay lets the server leave unanswered.
const MAX_AWAITING: usize = 4096;

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
            awaiting: Mutex::new(HashMap::new()),
        })
    }

    /// Remember that the tool call `request`, `action` decided in `cwd`, was
    /// passed on for the hook's decision `ticket`, so its result is kept under
    /// that session.
    fn await_result(&self, request: &str, ticket: &Ticket, action: Action, cwd: Option<String>) {
        let mut awaiting = self.awaiting.lock().unwrap_or_else(PoisonError::into_inner);
        if awaiting.len() >= MAX_AWAITING
            && let Some(any) = awaiting.keys().next().cloned()
        {
            // A request the server never answered (cancelled, or lost).
            awaiting.remove(&any);
        }
        awaiting.insert(
            request.to_owned(),
            Awaiting {
                host: ticket.host.clone(),
                session: ticket.session_id.clone(),
                action,
                cwd,
            },
        );
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

    /// Record that the server was not started (ADR-049): a deny with the rule
    /// `moat guard` gives the tool calls of a server whose definition is not
    /// the accepted one, under the server's name.
    pub fn refused_start(&self, why: &str) -> Result<()> {
        let store = self.store()?.with_secrets(self.known());
        let name = format!("mcp__{}", self.server);
        let decision = Decision::single(Verdict::Deny, crate::mcp::SERVER_RULE, why);
        store.record(&NewEvent {
            host: AUDIT_HOST,
            session_id: &self.session,
            call_id: None,
            cwd: self.cwd.to_str(),
            tool: &name,
            action: Some(&Action::mcp(name.clone())),
            decision: &decision,
            latency_us: 0,
        })?;
        Ok(())
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
        let awaits = match (&outcome.ticket, call.request, &refused) {
            (Some(ticket), Some(request), None) => Some((
                request,
                ticket.clone(),
                outcome.action.clone(),
                outcome.cwd.clone(),
            )),
            _ => None,
        };
        self.record(store, &name, outcome, started)?;
        if let Some((request, ticket, action, cwd)) = awaits {
            self.await_result(request, &ticket, action, cwd);
        }
        Ok(refused)
    }

    /// Keep the pieces of a passed tool call's answer, its result or its error
    /// object (ADR-058), and the fingerprints of what it names (ADR-057) under
    /// the session the hook's decision named; the call no longer awaits an
    /// answer either way. A response to anything else is not a tool result of
    /// a session and is let through as it is.
    fn result(&self, request: &str, result: &Value) -> Result<()> {
        let awaiting = self
            .awaiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(request);
        let Some(awaiting) = awaiting else {
            return Ok(());
        };
        let store = self.store()?.with_secrets(self.known());
        let pieces = crate::mcp::flow::hashed(crate::mcp::flow::value_pieces(result));
        if !pieces.is_empty() {
            store
                .add_mcp_flow(&awaiting.host, &awaiting.session, &self.server, &pieces)
                .context("recording what the tool's result held")?;
        }
        self.injected(&store, &awaiting, result)
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

impl Gateway {
    /// Keep the injected-input fingerprints of a passed call's result, as the
    /// hook keeps those of a host's `PostToolUse` (`taint::injected`), with
    /// the policy of the directory the hook decided the call in. Under a
    /// drifted lock nothing is kept and the host gets an error in place of
    /// the result, as the hook denies every call then.
    fn injected(&self, store: &Store, awaiting: &Awaiting, result: &Value) -> Result<()> {
        let text = crate::mcp::flow::value_text(result);
        if text.trim().is_empty() {
            return Ok(());
        }
        let Ok(host) = awaiting.host.parse::<Host>() else {
            bail!(
                "the hook's decision names no known host (`{}`)",
                awaiting.host
            );
        };
        let verified = integrity::check(&self.home)?;
        if verified.checked.deny.is_some() {
            bail!("the policy lock does not match, so this tool's result is not kept");
        }
        let home = verified.home;
        let cwd = awaiting
            .cwd
            .as_deref()
            .map_or_else(|| self.cwd.clone(), PathBuf::from);
        let ctx = context::eval_context(&home, Some(&cwd), None)?;
        let policy = crate::repo::effective_policy(&home, &ctx)?;
        let compiled = CompiledPolicy::compile(&policy, &ctx)?;
        let output = crate::taint::injected::Output {
            host,
            session: &awaiting.session,
            action: &awaiting.action,
            cwd: &ctx.cwd,
            text: &text,
        };
        crate::taint::injected::record(&home, store, &compiled, &output)
            .context("keeping what the tool's result named")?;
        Ok(())
    }
}

/// What the host is told about a refused call.
fn refusal(decision: &Decision) -> String {
    let rules = decision.rules.join(", ");
    let reasons = decision.reasons.join("; ");
    format!("OpenMoat refused this call [{rules}]: {reasons}")
}

#[cfg(test)]
mod tests;
