//! Text the server sends the model outside a tool result (ADR-069): the
//! `instructions` of its `initialize` answer, which a host puts in the
//! model's prompt. It is untrusted content as a tool's result is, so each
//! session it reaches has it kept as one: its pieces for the cross-server flow
//! check (ADR-058), the fingerprints of what it names as injected input
//! (ADR-057), and a row that marks the session untrusted (ADR-020).
//!
//! The server answers `initialize` before any session made a call, and a
//! proxy learns a session only from the hook decision a call matches. So the
//! text is kept for a session when the proxy first passes a call of it, before
//! that call reaches the server; every session the proxy serves gets it once.
//! A session that never calls a tool of the server is not marked: what its
//! model read is only the text a person accepted (`openmoat mcp accept`).

use std::collections::HashSet;
use std::sync::PoisonError;

use anyhow::{Context as _, Result};
use openmoat_audit::{NewEvent, Ticket};
use openmoat_core::{Action, Decision, Verdict};
use serde_json::Value;

use super::{AUDIT_HOST, Awaiting, Gateway};

/// Rule id of the row that marks a session untrusted for what the server
/// sent it outside a tool result.
const SERVER_TEXT_RULE: &str = "mcp-server-text";

/// What the server sent outside its tool results, and which sessions have it.
#[derive(Default)]
pub(super) struct Sent {
    /// The `instructions` the host was passed, if any.
    instructions: Option<String>,
    /// The host and session of each session that has them.
    credited: HashSet<(String, String)>,
}

impl Gateway {
    /// Keep `text`, the `instructions` the relay passed to the host, for every
    /// session the proxy serves from now on.
    pub(super) fn keep_instructions(&self, text: &str) {
        let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        sent.instructions = Some(text.to_owned()).filter(|t| !t.trim().is_empty());
        sent.credited.clear();
    }

    /// Before the first call of `ticket`'s session passes: keep what the
    /// server sent outside its results for that session.
    pub(super) fn credit(&self, ticket: &Ticket, cwd: Option<&str>) -> Result<()> {
        let key = (ticket.host.clone(), ticket.session_id.clone());
        let whose = (ticket.host.as_str(), ticket.session_id.as_str());
        let text = {
            let sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
            if sent.credited.contains(&key) {
                return Ok(());
            }
            sent.instructions.clone()
        };
        if let Some(text) = text {
            self.untrusted(whose, cwd, "initialize", &text)
                .context("keeping the MCP server's instructions for this session")?;
        }
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .credited
            .insert(key);
        Ok(())
    }

    /// Keep `text`, which the server sent the model in `what` (an MCP method),
    /// as untrusted content of `host`'s `session`.
    fn untrusted(
        &self,
        (host, session): (&str, &str),
        cwd: Option<&str>,
        what: &str,
        text: &str,
    ) -> Result<()> {
        let name = format!("mcp__{}__{what}", self.server);
        let action = Action::mcp(name.clone());
        let store = self.store()?.with_secrets(self.known());
        let decision = Decision::single(
            Verdict::Allow,
            SERVER_TEXT_RULE,
            format!(
                "MCP server `{}` sent the agent text outside a tool result ({what}), which \
                 marks the session untrusted (recorded by {AUDIT_HOST})",
                self.server
            ),
        );
        store.record(&NewEvent {
            host,
            session_id: session,
            call_id: None,
            cwd,
            tool: &name,
            action: Some(&action),
            decision: &decision,
            latency_us: 0,
        })?;
        let awaiting = Awaiting {
            host: host.to_owned(),
            session: session.to_owned(),
            action,
            cwd: cwd.map(str::to_owned),
        };
        self.keep(&store, &awaiting, &Value::String(text.to_owned()))
    }
}
