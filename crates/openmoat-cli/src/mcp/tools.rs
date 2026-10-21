//! `~/.moat/mcp/<server>.json`: the tool definitions `moat mcp proxy` pinned
//! for one server.
//!
//! A tool is pinned by the SHA-256 of its name, title, description, input and
//! output schemas and annotations in canonical JSON: everything a host shows
//! the model or reads to decide whether to run a call unasked (`readOnlyHint`,
//! `destructiveHint`). Releases before this pinned only the name, description
//! and input schema; such a pin matches no listing any more, so each of its
//! tools is held once until a person accepts it again, and the hold says why.
//! A tool whose definition differs from its pin, or a tool with
//! no pin, is held: the proxy hides it from `tools/list` and refuses
//! `tools/call` for it until a person accepts it with `moat mcp accept
//! <server>`, which shows what changed. So the first time the proxy sees a
//! server, every tool it lists is held (ADR-032). Only a policy with
//! `mcp.trust_first_sight` has the first listing pinned as it is (ADR-026's
//! original behaviour, kept as an opt-in by ADR-032).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use similar::{Algorithm, udiff::unified_diff};

use super::pins::canonical;
use crate::home::{Home, write_private};
use crate::integrity::sha256_hex;

/// The format version of a server's tool-pin file this build reads and writes.
const VERSION: u32 = 1;

/// Characters of a server's name kept in its pin file's name; the digest
/// beside them tells longer names apart.
const MAX_FILE_NAME_CHARS: usize = 64;

/// One tool's pinned definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPin {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output_schema: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub annotations: Value,
}

impl ToolPin {
    /// The pin of one entry of a `tools/list` result; `None` without a name.
    /// A `title` that is not a string is kept in the digest as it is, so
    /// changing it is still a change.
    pub fn of(tool: &Value) -> Option<(String, Self)> {
        let name = tool.get("name")?.as_str()?.to_owned();
        let text = |key: &str| tool.get(key).and_then(Value::as_str).map(str::to_owned);
        let field = |key: &str| tool.get(key).cloned().unwrap_or(Value::Null);
        let hashed = json!({
            "name": name,
            "title": field("title"),
            "description": field("description"),
            "inputSchema": field("inputSchema"),
            "outputSchema": field("outputSchema"),
            "annotations": field("annotations"),
        });
        let digest = sha256_hex(canonical(&hashed).as_bytes());
        Some((
            name,
            Self {
                digest,
                title: text("title"),
                description: text("description"),
                input_schema: field("inputSchema"),
                output_schema: field("outputSchema"),
                annotations: field("annotations"),
            },
        ))
    }

    /// Whether this is a pin an earlier release recorded, from the name,
    /// description and input schema alone: its title, annotations and output
    /// schema were never pinned, so no listing matches it.
    fn is_earlier_form(&self, name: &str) -> bool {
        let hashed = json!({
            "name": name,
            "description": self.description,
            "inputSchema": self.input_schema,
        });
        self.digest == sha256_hex(canonical(&hashed).as_bytes())
    }
}

/// A tool the proxy hides until a person accepts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    #[serde(flatten)]
    pub pin: ToolPin,
    pub seen_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPins {
    pub version: u32,
    /// The server name `moat mcp proxy --server` was given.
    pub server: String,
    /// Accepted definitions, by tool name.
    pub tools: BTreeMap<String, ToolPin>,
    /// Listed definitions not accepted yet, by tool name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub held: BTreeMap<String, Held>,
}

/// What one `tools/list` result did to the pins.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// Tools to leave out of the result.
    pub hidden: BTreeSet<String>,
    /// Whether the pins changed and must be saved.
    pub changed: bool,
}

impl ToolPins {
    pub fn new(server: &str) -> Self {
        Self {
            version: VERSION,
            server: server.to_owned(),
            tools: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// The pins at `path`; `None` when the server was never seen.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let pins: Self =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if pins.version != VERSION {
            bail!(
                "{} has version {}; this build supports {VERSION}",
                path.display(),
                pins.version
            );
        }
        Ok(Some(pins))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }

    /// Check the `tools` array of a `tools/list` result. `first` pins
    /// everything listed as it is: a server never seen before, under a policy
    /// with `mcp.trust_first_sight`. Otherwise a tool with no pin is held.
    pub fn list(&mut self, tools: &[Value], first: bool, now_ms: i64) -> Listing {
        let mut listing = Listing::default();
        for (name, pin) in tools.iter().filter_map(ToolPin::of) {
            if first {
                listing.changed |= self.tools.insert(name, pin).is_none();
                continue;
            }
            if self
                .tools
                .get(&name)
                .is_some_and(|p| p.digest == pin.digest)
            {
                // Listed as accepted again: an older held version is moot.
                listing.changed |= self.held.remove(&name).is_some();
                continue;
            }
            if self
                .held
                .get(&name)
                .is_none_or(|h| h.pin.digest != pin.digest)
            {
                self.held.insert(
                    name.clone(),
                    Held {
                        pin,
                        seen_at_ms: now_ms,
                    },
                );
                listing.changed = true;
            }
            listing.hidden.insert(name);
        }
        listing
    }

    pub fn is_held(&self, tool: &str) -> bool {
        self.held.contains_key(tool)
    }

    /// Accept every held tool.
    pub fn accept_held(&mut self) {
        for (name, held) in std::mem::take(&mut self.held) {
            self.tools.insert(name, held.pin);
        }
    }

    /// What accepting each held tool changes, for a person to read.
    pub fn describe_held(&self) -> Vec<String> {
        self.held
            .iter()
            .map(|(name, held)| {
                let old = self.tools.get(name);
                let again = self.held_again(name, &held.pin);
                describe(&self.server, name, old, &held.pin, again)
            })
            .collect()
    }

    /// Why tools are held, for `status` and `doctor`: how many, and how many
    /// of them only because their pin is of the earlier form.
    pub fn held_summary(&self) -> String {
        let again = self
            .held
            .iter()
            .filter(|(name, held)| self.held_again(name, &held.pin))
            .count();
        let mut text = format!("{} tool(s) that changed or are new", self.held.len());
        if again > 0 {
            let _ = write!(
                text,
                " ({again} held once because OpenMoat now also pins each tool's {EARLIER_GAP})"
            );
        }
        text
    }

    /// Whether `name` is held only because its accepted pin is of the
    /// earlier form: the description and input schema are the accepted ones.
    fn held_again(&self, name: &str, listed: &ToolPin) -> bool {
        self.tools.get(name).is_some_and(|old| {
            old.is_earlier_form(name)
                && old.description == listed.description
                && old.input_schema == listed.input_schema
        })
    }
}

/// What an earlier release's tool pins left out.
const EARLIER_GAP: &str = "title, annotations and output schema";

fn describe(server: &str, name: &str, old: Option<&ToolPin>, new: &ToolPin, again: bool) -> String {
    let mut text = match old {
        Some(_) if again => format!(
            "tool `{name}` of MCP server `{server}` is held once: OpenMoat now also pins its \
             {EARLIER_GAP}, which the accepted pin did not record:\n"
        ),
        Some(_) => format!("tool `{name}` of MCP server `{server}` changed:\n"),
        None => format!("tool `{name}` of MCP server `{server}` is new:\n"),
    };
    let pretty = |value: &Value| serde_json::to_string_pretty(value).unwrap_or_default();
    let render = |pin: Option<&ToolPin>| {
        let Some(pin) = pin else {
            return String::new();
        };
        let mut shown = String::new();
        if let Some(title) = &pin.title {
            let _ = writeln!(shown, "title: {title}");
        }
        let _ = write!(
            shown,
            "description:\n{}\ninput schema:\n{}\n",
            pin.description.as_deref().unwrap_or("(none)"),
            pretty(&pin.input_schema)
        );
        if !pin.output_schema.is_null() {
            let _ = writeln!(shown, "output schema:\n{}", pretty(&pin.output_schema));
        }
        if !pin.annotations.is_null() {
            let _ = writeln!(shown, "annotations:\n{}", pretty(&pin.annotations));
        }
        shown
    };
    let (before, after) = (render(old), render(Some(new)));
    let labels = (format!("{name} (accepted)"), format!("{name} (listed now)"));
    let diff = unified_diff(
        Algorithm::Myers,
        &before,
        &after,
        crate::render::DIFF_CONTEXT_LINES,
        Some((labels.0.as_str(), labels.1.as_str())),
    );
    let _ = write!(text, "{diff}");
    text
}

/// The file of server `name`'s pins: its name with every character but
/// letters, digits, `-` and `_` as `_`, and a digest of the exact name so two
/// names that read alike never share a file.
pub fn path(home: &Home, name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .take(MAX_FILE_NAME_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let digest = sha256_hex(name.as_bytes());
    dir(home).join(format!("{safe}-{}.json", &digest[..8]))
}

/// The directory of every server's pins.
pub fn dir(home: &Home) -> PathBuf {
    home.root().join("mcp")
}

/// Every server's pins, by file.
pub fn all(home: &Home) -> Result<Vec<(PathBuf, ToolPins)>> {
    let dir = dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Some(pins) = ToolPins::load(&path)?
        {
            out.push((path, pins));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
mod tests;
