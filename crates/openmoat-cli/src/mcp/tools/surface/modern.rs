//! What a server says of itself under MCP 2026-07-28, pinned as its
//! `initialize` answer is under earlier revisions (ADR-114).
//!
//! The 2026-07-28 revision removed the `initialize` handshake
//! (<https://modelcontextprotocol.io/specification/2026-07-28/changelog>, SEP-2575):
//! a server's instructions, capabilities and supported versions come from
//! `server/discover`
//! (<https://modelcontextprotocol.io/specification/2026-07-28/server/discover>),
//! and it names itself in every result's
//! `_meta["io.modelcontextprotocol/serverInfo"]`
//! (<https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta>).
//! So two things are pinned here:
//!
//! - the `server/discover` answer without what changes from one answer to the
//!   next (`resultType`, the cache hints `ttlMs` and `cacheScope`, `_meta`):
//!   held like held `initialize` instructions, the host gets the accepted
//!   answer, or one without instructions;
//! - the server's identity, its `serverInfo` with a version number pinned as
//!   any version (as `initialize`'s is): one a result names that differs from
//!   the accepted one holds the whole server, its calls refused, until a
//!   person accepts it. The specification calls `serverInfo` unverified and
//!   for display; a server that names itself differently is still not the one
//!   a person accepted.
//!
//! A server a person accepted under the older revision is not asked about
//! again when its host moves to this one, as long as what the model reads is
//! the same: the discovery's instructions are the accepted `initialize`
//! instructions, and its identity the accepted `serverInfo`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{EntryPin, HeldEntry, Introduced, Surface, describe, introduction};

/// The `_meta` key of a server's identity in each 2026-07-28 result.
pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The fields of a `server/discover` result that are not pinned: they
/// differ from one answer to the next without the server changing.
const UNPINNED: [&str; 4] = ["resultType", "ttlMs", "cacheScope", "_meta"];

/// The pins of a server's 2026-07-28 surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Modern {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover: Option<EntryPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover_held: Option<HeldEntry>,
    /// Whether a `server/discover` answer was ever read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub discover_seen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<EntryPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_held: Option<HeldEntry>,
}

impl Modern {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub(super) fn held_count(&self) -> usize {
        usize::from(self.discover_held.is_some()) + usize::from(self.identity_held.is_some())
    }

    pub(super) fn accept_held(&mut self) {
        if let Some(held) = self.discover_held.take() {
            self.discover = Some(held.pin);
        }
        if let Some(held) = self.identity_held.take() {
            self.identity = Some(held.pin);
        }
    }

    pub(super) fn describe_held(&self, server: &str, out: &mut Vec<String>) {
        if let Some(held) = &self.discover_held {
            let what = format!("the `server/discover` answer of MCP server `{server}`");
            out.push(describe(&what, self.discover.as_ref(), &held.pin));
        }
        if let Some(held) = &self.identity_held {
            let what = format!(
                "the server information MCP server `{server}` gives in its results (while it \
                 differs, OpenMoat refuses all its calls)"
            );
            out.push(describe(&what, self.identity.as_ref(), &held.pin));
        }
    }
}

/// What one result's identity did to the pins.
#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    /// It differs from the accepted identity, or none was accepted.
    pub held: bool,
    /// Whether the pins changed and must be saved.
    pub changed: bool,
    /// The accepted identity, to pass on in its place while held.
    pub accepted: Option<Value>,
}

/// The pinned part of a `server/discover` result.
pub fn discovery(result: &Value) -> Value {
    let Value::Object(fields) = result else {
        return Value::Null;
    };
    let kept: Map<String, Value> = fields
        .iter()
        .filter(|(key, _)| !UNPINNED.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Value::Object(kept)
}

/// A `serverInfo` as it is pinned: a version that reads as a version number
/// is any version ([`introduction`]).
pub fn identity_of(info: &Value) -> Value {
    introduction(&serde_json::json!({"serverInfo": info}))["serverInfo"].clone()
}

impl Surface {
    /// The identity a person accepted: the 2026-07-28 one, else the
    /// `serverInfo` of the accepted `initialize` answer.
    pub fn accepted_identity(&self) -> Option<Value> {
        if let Some(pin) = &self.modern.identity {
            return Some(pin.entry.clone());
        }
        self.server
            .as_ref()
            .map(|p| p.entry["serverInfo"].clone())
            .filter(|info| !info.is_null())
    }

    /// Whether a part of the 2026-07-28 surface was never read: the
    /// discovery answer, or (`identity`) the server's identity.
    pub fn modern_unseen(&self, identity: bool) -> bool {
        if identity {
            self.accepted_identity().is_none() && self.modern.identity_held.is_none()
        } else {
            !self.modern.discover_seen && self.modern.discover.is_none()
        }
    }

    /// Whether the server's identity is held: its calls are refused.
    pub fn identity_held(&self) -> bool {
        self.modern.identity_held.is_some()
    }

    /// Check a `server/discover` `result`, as [`Surface::introduce`] checks
    /// an `initialize` one. Pinned as it is when `trust` holds, or when its
    /// instructions are the accepted `initialize` instructions.
    pub fn discover(&mut self, result: &Value, trust: bool, now_ms: i64) -> Introduced {
        let entry = discovery(result);
        let pin = EntryPin::of(&entry);
        let modern = &mut self.modern;
        let mut changed = !modern.discover_seen;
        modern.discover_seen = true;
        let legacy_same = self
            .server
            .as_ref()
            .is_some_and(|p| p.entry["instructions"] == entry["instructions"]);
        let modern = &mut self.modern;
        if (trust || legacy_same)
            && modern.discover.is_none()
            && !super::super::has_invisible(&entry)
        {
            modern.discover = Some(pin.clone());
            changed = true;
        }
        let accepted_info = modern.discover.as_ref().map(|p| p.entry.clone());
        if modern
            .discover
            .as_ref()
            .is_some_and(|p| p.digest == pin.digest)
        {
            changed |= modern.discover_held.take().is_some();
            return Introduced {
                held: false,
                changed,
                accepted_info,
            };
        }
        if modern
            .discover_held
            .as_ref()
            .is_none_or(|h| h.pin.digest != pin.digest)
        {
            modern.discover_held = Some(HeldEntry {
                pin,
                seen_at_ms: now_ms,
            });
            changed = true;
        }
        Introduced {
            held: true,
            changed,
            accepted_info,
        }
    }

    /// Check the `serverInfo` one result names. `trust` pins it as it is
    /// when no identity was accepted.
    pub fn identity(&mut self, info: &Value, trust: bool, now_ms: i64) -> Identity {
        let entry = identity_of(info);
        let pin = EntryPin::of(&entry);
        let mut changed = false;
        if trust && self.accepted_identity().is_none() && !super::super::has_invisible(&entry) {
            self.modern.identity = Some(pin.clone());
            changed = true;
        }
        let accepted = self.accepted_identity();
        if accepted.as_ref() == Some(&entry) {
            changed |= self.modern.identity_held.take().is_some();
            return Identity {
                held: false,
                changed,
                accepted,
            };
        }
        if self
            .modern
            .identity_held
            .as_ref()
            .is_none_or(|h| h.pin.digest != pin.digest)
        {
            self.modern.identity_held = Some(HeldEntry {
                pin,
                seen_at_ms: now_ms,
            });
            changed = true;
        }
        Identity {
            held: true,
            changed,
            accepted,
        }
    }

    /// Whether an `initialize` answer's pinned part, `entry`, is what a person
    /// accepted under 2026-07-28: the same instructions and identity.
    pub(super) fn matches_modern(&self, entry: &Value) -> bool {
        let (Some(discover), Some(identity)) = (&self.modern.discover, &self.modern.identity)
        else {
            return false;
        };
        discover.entry["instructions"] == entry["instructions"]
            && identity.entry == entry["serverInfo"]
    }
}

#[cfg(test)]
mod tests;
