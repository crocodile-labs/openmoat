//! The rest of what a server says to the model, pinned with its tools
//! (ADR-069): its `initialize` answer's `instructions` and `serverInfo`, which
//! a host puts in the model's prompt, and the entries of its prompt, resource
//! and resource-template listings, whose descriptions a host shows the model
//! as it shows a tool's.
//!
//! Each is pinned by the SHA-256 of the whole entry in canonical JSON and held,
//! as a tool is, while it differs from the accepted pin or has none: held
//! instructions never reach the host, a held `serverInfo` is replaced by the
//! accepted one, and a held listing entry is left out of the listing (a held
//! prompt's `prompts/get` is refused). `openmoat mcp accept` shows each with
//! what changed and accepts it with the tools.
//!
//! A pin file written before these were pinned has none of them. For a server
//! whose tools a person accepted, each part is pinned as the server first says
//! it after the upgrade: the person accepted that server, and holding what they
//! never had to review would ask them again about a server that did not change.
//! A server nobody accepted has everything held, as a new server's tools are.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use similar::{Algorithm, udiff::unified_diff};

use super::super::pins::canonical;
use crate::integrity::sha256_hex;

/// One pinned entry: the digest of the entry, and the entry to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPin {
    pub digest: String,
    pub entry: Value,
}

impl EntryPin {
    pub fn of(entry: &Value) -> Self {
        Self {
            digest: sha256_hex(canonical(entry).as_bytes()),
            entry: entry.clone(),
        }
    }
}

/// An entry held until a person accepts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldEntry {
    #[serde(flatten)]
    pub pin: EntryPin,
    pub seen_at_ms: i64,
}

/// The pins of one listing (prompts, resources or resource templates), by
/// each entry's key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalogue {
    /// Whether a listing of this kind was ever read: an earlier pin file has
    /// none, and its first listing is pinned as it is when a person accepted
    /// the server's tools.
    #[serde(default)]
    pub seen: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accepted: BTreeMap<String, EntryPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub held: BTreeMap<String, HeldEntry>,
}

impl Catalogue {
    fn is_unseen(&self) -> bool {
        !self.seen && self.accepted.is_empty() && self.held.is_empty()
    }

    /// Check one listing's `entries`, each keyed by its `key` field; `trust`
    /// pins what is new as it is. The keys to leave out, and whether the pins
    /// changed. An entry without a string key is left out: no pin can
    /// match it.
    fn list(&mut self, entries: &[Value], key: &str, trust: bool, now_ms: i64) -> Listed {
        let mut listed = Listed {
            changed: !self.seen,
            ..Listed::default()
        };
        self.seen = true;
        let keyed: Vec<(String, EntryPin)> = entries
            .iter()
            .filter_map(|e| Some((e.get(key)?.as_str()?.to_owned(), EntryPin::of(e))))
            .collect();
        if trust {
            for (name, pin) in &keyed {
                if !self.accepted.contains_key(name) && !super::has_invisible(&pin.entry) {
                    self.accepted.insert(name.clone(), pin.clone());
                    listed.changed = true;
                }
            }
        }
        let accepted = |c: &Self, name: &str, pin: &EntryPin| {
            c.accepted.get(name).is_some_and(|p| p.digest == pin.digest)
        };
        let differs: BTreeSet<String> = keyed
            .iter()
            .filter(|(name, pin)| !accepted(self, name, pin))
            .map(|(name, _)| name.clone())
            .collect();
        for (name, pin) in keyed {
            if !differs.contains(&name) {
                listed.changed |= self.held.remove(&name).is_some();
                continue;
            }
            if listed.hidden.contains(&name) {
                continue;
            }
            if self
                .held
                .get(&name)
                .is_none_or(|h| h.pin.digest != pin.digest)
            {
                let held = HeldEntry {
                    pin,
                    seen_at_ms: now_ms,
                };
                self.held.insert(name.clone(), held);
                listed.changed = true;
            }
            listed.hidden.insert(name);
        }
        listed
    }

    fn accept_held(&mut self) {
        for (name, held) in std::mem::take(&mut self.held) {
            self.accepted.insert(name, held.pin);
        }
    }
}

/// What one listing did to the pins.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listed {
    /// Keys to leave out of the listing.
    pub hidden: BTreeSet<String>,
    /// Whether the pins changed and must be saved.
    pub changed: bool,
}

/// The listings a server answers besides its tools, as a host reads them:
/// the result's array, and the field that names each entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Prompts,
    Resources,
    Templates,
}

impl Kind {
    pub const ALL: [Self; 3] = [Self::Prompts, Self::Resources, Self::Templates];

    /// The pointer to the listing's array in a response.
    pub fn pointer(self) -> &'static str {
        match self {
            Self::Prompts => "/result/prompts",
            Self::Resources => "/result/resources",
            Self::Templates => "/result/resourceTemplates",
        }
    }

    /// The field that names an entry.
    pub fn key(self) -> &'static str {
        match self {
            Self::Prompts => "name",
            Self::Resources => "uri",
            Self::Templates => "uriTemplate",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Prompts => "prompt",
            Self::Resources => "resource",
            Self::Templates => "resource template",
        }
    }
}

/// Everything of a server but its tools that the pins hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Surface {
    /// The accepted `instructions` and `serverInfo` of its `initialize`
    /// answer, as one entry; `None` before the first answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<EntryPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_held: Option<HeldEntry>,
    /// Whether an `initialize` answer was ever read.
    #[serde(default)]
    pub server_seen: bool,
    /// Set for a pin file written before these pins, of a server whose tools
    /// a person accepted: each part never read is pinned as it is first read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub adopt: bool,
    #[serde(default, skip_serializing_if = "Catalogue::is_unseen")]
    pub prompts: Catalogue,
    #[serde(default, skip_serializing_if = "Catalogue::is_unseen")]
    pub resources: Catalogue,
    #[serde(default, skip_serializing_if = "Catalogue::is_unseen")]
    pub templates: Catalogue,
}

/// What one `initialize` answer did to the pins.
#[derive(Debug, PartialEq, Eq)]
pub struct Introduced {
    /// The answer differs from the accepted one, or none was accepted.
    pub held: bool,
    /// Whether the pins changed and must be saved.
    pub changed: bool,
    /// The `serverInfo` to pass on while held: the accepted one, if any.
    pub accepted_info: Option<Value>,
}

/// What a pinned `serverInfo` has for a `version` that reads as a version
/// number: an upgrade of the server changes it, and a person is not asked
/// again for that alone.
pub const ANY_VERSION: &str = "(any version)";

/// The pinned part of an `initialize` result: its `instructions` and its
/// `serverInfo`, null when absent. A `version` of at most 32 letters, digits,
/// `.`, `+`, `-` and `_` is pinned as [`ANY_VERSION`]; any other is pinned as
/// it is, since it is text a host may show.
pub fn introduction(result: &Value) -> Value {
    let field = |key: &str| result.get(key).cloned().unwrap_or(Value::Null);
    let mut info = field("serverInfo");
    if info
        .get("version")
        .and_then(Value::as_str)
        .is_some_and(is_version_like)
    {
        info["version"] = Value::String(ANY_VERSION.to_owned());
    }
    json!({"instructions": field("instructions"), "serverInfo": info})
}

/// Whether `version` reads as a version number ([`introduction`]).
pub fn is_version_like(version: &str) -> bool {
    (1..=32).contains(&version.len())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_'))
}

impl Surface {
    pub fn catalogue(&mut self, kind: Kind) -> &mut Catalogue {
        match kind {
            Kind::Prompts => &mut self.prompts,
            Kind::Resources => &mut self.resources,
            Kind::Templates => &mut self.templates,
        }
    }

    fn catalogue_of(&self, kind: Kind) -> &Catalogue {
        match kind {
            Kind::Prompts => &self.prompts,
            Kind::Resources => &self.resources,
            Kind::Templates => &self.templates,
        }
    }

    /// Check an `initialize` `result`. `trust` pins a first answer as it is:
    /// a first sight the policy trusts, or a server whose tools a person
    /// accepted before its pin file had these pins. Text a terminal does not
    /// show is never trusted on sight.
    pub fn introduce(&mut self, result: &Value, trust: bool, now_ms: i64) -> Introduced {
        let entry = introduction(result);
        let pin = EntryPin::of(&entry);
        let mut changed = !self.server_seen;
        self.server_seen = true;
        if trust && self.server.is_none() && !super::has_invisible(&entry) {
            self.server = Some(pin.clone());
            changed = true;
        }
        let accepted_info = self.server.as_ref().map(|p| p.entry["serverInfo"].clone());
        if self.server.as_ref().is_some_and(|p| p.digest == pin.digest) {
            changed |= self.server_held.take().is_some();
            return Introduced {
                held: false,
                changed,
                accepted_info,
            };
        }
        if self
            .server_held
            .as_ref()
            .is_none_or(|h| h.pin.digest != pin.digest)
        {
            self.server_held = Some(HeldEntry {
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

    /// Check one listing of `kind`; `trust` as for [`Self::introduce`].
    pub fn list(&mut self, kind: Kind, entries: &[Value], trust: bool, now_ms: i64) -> Listed {
        self.catalogue(kind)
            .list(entries, kind.key(), trust, now_ms)
    }

    /// Mark the listings the server's `capabilities` (of its `initialize`
    /// answer) does not offer as read, so entries it lists later are new and
    /// held: what is adopted unseen is only what the server offered when it
    /// was first read.
    pub fn unlisted_seen(&mut self, capabilities: &Value) {
        if capabilities.get("prompts").is_none() {
            self.prompts.seen = true;
        }
        if capabilities.get("resources").is_none() {
            self.resources.seen = true;
            self.templates.seen = true;
        }
    }

    /// Whether the pins hold the prompt `name`: it was listed, and differs
    /// from the accepted one or is new. A prompt never listed is not held:
    /// the pins protect what a listing shows the model, and what a prompt
    /// returns is the server's output, which the gate records.
    pub fn prompt_held(&self, name: &str) -> bool {
        self.prompts.held.contains_key(name)
    }

    /// Whether a part of `kind` was never read (`None` for the `initialize`
    /// answer).
    pub fn unseen(&self, kind: Option<Kind>) -> bool {
        match kind {
            None => !self.server_seen && self.server.is_none(),
            Some(kind) => self.catalogue_of(kind).is_unseen(),
        }
    }

    /// How many entries are held.
    pub fn held_count(&self) -> usize {
        usize::from(self.server_held.is_some())
            + Kind::ALL
                .iter()
                .map(|k| self.catalogue_of(*k).held.len())
                .sum::<usize>()
    }

    pub fn accept_held(&mut self) {
        if let Some(held) = self.server_held.take() {
            self.server = Some(held.pin);
        }
        for kind in Kind::ALL {
            self.catalogue(kind).accept_held();
        }
    }

    /// What accepting each held entry changes, for a person to read.
    pub fn describe_held(&self, server: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(held) = &self.server_held {
            let what = format!("the instructions and server information of MCP server `{server}`");
            out.push(describe(&what, self.server.as_ref(), &held.pin));
        }
        for kind in Kind::ALL {
            let catalogue = self.catalogue_of(kind);
            for (name, held) in &catalogue.held {
                let what = format!("{} `{name}` of MCP server `{server}`", kind.noun());
                out.push(describe(&what, catalogue.accepted.get(name), &held.pin));
            }
        }
        out
    }
}

fn describe(what: &str, old: Option<&EntryPin>, new: &EntryPin) -> String {
    let mut text = match old {
        Some(_) => format!("{what} changed:\n"),
        None => format!("{what} is new:\n"),
    };
    let render = |pin: Option<&EntryPin>| pin.map(|p| render_entry(&p.entry)).unwrap_or_default();
    let (before, after) = (render(old), render(Some(new)));
    let diff = unified_diff(
        Algorithm::Myers,
        &before,
        &after,
        crate::render::DIFF_CONTEXT_LINES,
        Some(("accepted", "listed now")),
    );
    let _ = write!(text, "{diff}");
    let invisible = crate::render::invisible_count(&after);
    if invisible > 0 {
        let _ = writeln!(text, "{}", super::invisible_warning(invisible));
    }
    // The server wrote all of it: an escape sequence could redraw the review.
    crate::render::clean_lines(&text)
}

/// An entry as a person reads it: each text field on its own lines, so a
/// long description diffs by line, then the rest as JSON.
fn render_entry(entry: &Value) -> String {
    let mut shown = String::new();
    let mut rest = serde_json::Map::new();
    for (key, value) in entry.as_object().into_iter().flatten() {
        match value {
            Value::String(text) => {
                let _ = writeln!(shown, "{key}:\n{text}");
            }
            Value::Null => {}
            other => {
                rest.insert(key.clone(), other.clone());
            }
        }
    }
    if !rest.is_empty() {
        let pretty = serde_json::to_string_pretty(&Value::Object(rest)).unwrap_or_default();
        let _ = writeln!(shown, "{pretty}");
    }
    shown
}

#[cfg(test)]
mod tests;
