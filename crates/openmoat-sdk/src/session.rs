//! What earlier calls of one agent session brought into it (session taint,
//! ADR-020): after a secret read, network to any other host asks; after
//! untrusted content (a fetch, a web search, an MCP result), a write to a
//! protected path asks. Taint only ever makes a decision stricter.

use serde::{Deserialize, Serialize};

use openmoat_core::Taint;

use crate::action::Action;
use crate::engine::Engine;
use crate::facts::Facts;

/// One agent session's history, as far as later decisions need it.
///
/// [`Session::record`] each call after it ran, and decide the next ones with
/// [`Engine::decide_with`]. Its JSON form (for keeping a session across
/// processes) is stable within a major version of the SDK; treat it as opaque.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Session {
    taint: Taint,
}

impl Session {
    /// A session nothing has run in yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that `action` ran, as decided by `engine` with `facts`. Record only
    /// calls that really ran (a person may have approved an `ask`); a denied
    /// call that did not run exposed nothing.
    pub fn record(&mut self, engine: &Engine, action: &Action, facts: &Facts) {
        self.taint.absorb(engine.exposure(action, facts));
    }

    /// Whether nothing recorded so far tightens later decisions.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.taint == Taint::default()
    }

    pub(crate) fn taint(&self) -> &Taint {
        &self.taint
    }
}
