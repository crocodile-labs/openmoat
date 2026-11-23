//! What a tool's schemas ask of the host beyond describing its arguments
//! (ADR-114): the parameters that become HTTP headers (`x-mcp-header`), and
//! the `$ref`s a validator follows.
//!
//! MCP 2026-07-28 lets a tool mark a parameter with `x-mcp-header`, and a
//! client on Streamable HTTP then copies that argument into a
//! `Mcp-Param-<name>` header
//! (<https://modelcontextprotocol.io/specification/2026-07-28/server/tools#x-mcp-header>):
//! where the value of an argument goes is part of the tool's definition. The
//! mappings are inside `inputSchema`, so the tool's pin covers them; this
//! module reads them out for the review a person accepts, and refuses a tool
//! whose mappings break the rules the specification sets (an empty or
//! non-token name, one given twice, a parameter that is not a string, integer
//! or boolean, a parameter reached through anything but `properties`).
//!
//! The same revision asks implementations not to fetch a network `$ref` and
//! to bound the work a schema can cause
//! (<https://modelcontextprotocol.io/specification/2026-07-28/basic/index#%24ref-resolution>).
//! The gateway validates no arguments, but a host does: a tool whose schema
//! names a `$ref` outside itself, one that does not resolve, a chain of
//! `$ref`s that loops or runs deeper than [`MAX_REF_DEPTH`], or a schema
//! nested deeper than [`MAX_DEPTH`] or larger than [`MAX_NODES`] is refused.
//! A refused tool is left out of the listing and its calls are refused; it
//! cannot be accepted, since nothing about it is a matter of a person's
//! taste.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// How deep a schema may nest.
pub const MAX_DEPTH: usize = 64;
/// How many schema objects one schema may hold.
pub const MAX_NODES: usize = 4096;
/// How many `$ref`s a chain may follow.
pub const MAX_REF_DEPTH: usize = 16;

/// The keywords whose value is data, not a schema: a key inside them names
/// nothing.
const DATA_KEYWORDS: [&str; 4] = ["const", "enum", "default", "examples"];
/// The keywords whose value is a map of names to schemas, other than
/// `properties`.
const SCHEMA_MAPS: [&str; 5] = [
    "$defs",
    "definitions",
    "patternProperties",
    "dependentSchemas",
    "dependencies",
];
/// The keywords that point at another schema.
const REF_KEYWORDS: [&str; 3] = ["$ref", "$dynamicRef", "$recursiveRef"];

/// One `x-mcp-header` mapping: the argument at `path` (property names from
/// the root) is sent as header `Mcp-Param-<header>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub path: Vec<String>,
    pub header: String,
}

/// What reading a schema found.
#[derive(Debug, Default)]
struct Walk {
    mappings: Vec<Mapping>,
    problems: Vec<String>,
    /// The JSON pointer of each `$ref` and where it points.
    refs: Vec<(String, String)>,
    nodes: usize,
}

/// Why a tool entry is refused, if it is: its `inputSchema`'s and
/// `outputSchema`'s mappings and `$ref`s.
pub fn refusal(tool: &Value) -> Option<String> {
    let mut problems = Vec::new();
    for key in ["inputSchema", "outputSchema"] {
        let Some(schema) = tool.get(key) else {
            continue;
        };
        let walk = walk(schema);
        let mut found = walk.problems;
        if key == "inputSchema" {
            found.extend(mapping_problems(&walk.mappings));
        } else if !walk.mappings.is_empty() {
            found.push("`x-mcp-header` belongs in the input schema only".to_owned());
        }
        found.extend(ref_problems(schema, &walk.refs));
        problems.extend(found.into_iter().map(|p| format!("{key}: {p}")));
    }
    (!problems.is_empty()).then(|| problems.join("; "))
}

/// The header mappings of `schema`, an `inputSchema`, for a person to read;
/// the ones reachable as the specification allows.
pub fn mappings(schema: &Value) -> Vec<Mapping> {
    walk(schema).mappings
}

fn walk(schema: &Value) -> Walk {
    let mut out = Walk::default();
    visit(schema, &mut Vec::new(), "", true, 0, &mut out);
    if out.nodes > MAX_NODES {
        out.problems
            .push(format!("more than {MAX_NODES} schema objects"));
    }
    out
}

/// Read the schema at `node`: `path` is the chain of property names from the
/// root while every step was `properties` (`reachable`), `pointer` its JSON
/// pointer.
fn visit(
    node: &Value,
    path: &mut Vec<String>,
    pointer: &str,
    reachable: bool,
    depth: usize,
    out: &mut Walk,
) {
    let Value::Object(fields) = node else {
        if let Value::Array(items) = node {
            for (i, item) in items.iter().enumerate() {
                visit(item, path, &format!("{pointer}/{i}"), false, depth + 1, out);
            }
        }
        return;
    };
    out.nodes += 1;
    if depth > MAX_DEPTH {
        out.problems
            .push(format!("nested deeper than {MAX_DEPTH} levels"));
        return;
    }
    if out.nodes > MAX_NODES {
        return;
    }
    for (key, value) in fields {
        let here = format!("{pointer}/{}", escape(key));
        match key.as_str() {
            "x-mcp-header" => mapping(node, value, path, reachable, out),
            k if REF_KEYWORDS.contains(&k) => match value.as_str() {
                Some(target) => out.refs.push((here, target.to_owned())),
                None => out
                    .problems
                    .push(format!("`{k}` at {here} is not a string")),
            },
            k if DATA_KEYWORDS.contains(&k) => {}
            "properties" => {
                let Value::Object(properties) = value else {
                    continue;
                };
                for (name, schema) in properties {
                    path.push(name.clone());
                    let at = format!("{here}/{}", escape(name));
                    visit(schema, path, &at, reachable, depth + 1, out);
                    path.pop();
                }
            }
            k if SCHEMA_MAPS.contains(&k) => {
                let Value::Object(schemas) = value else {
                    continue;
                };
                for (name, schema) in schemas {
                    let at = format!("{here}/{}", escape(name));
                    visit(schema, &mut Vec::new(), &at, false, depth + 1, out);
                }
            }
            _ if value.is_object() || value.is_array() => {
                visit(value, &mut Vec::new(), &here, false, depth + 1, out);
            }
            _ => {}
        }
    }
}

/// Record the `x-mcp-header` of `schema`, the property at `path`.
fn mapping(schema: &Value, header: &Value, path: &[String], reachable: bool, out: &mut Walk) {
    let shown = path.join(".");
    if !reachable || path.is_empty() {
        out.problems.push(format!(
            "`x-mcp-header` on a schema not reached from the root through `properties` alone \
             ({})",
            if shown.is_empty() { "(root)" } else { &shown }
        ));
        return;
    }
    let Some(header) = header.as_str() else {
        out.problems
            .push(format!("`x-mcp-header` of `{shown}` is not a string"));
        return;
    };
    let primitive = schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| matches!(t, "string" | "integer" | "boolean"));
    if !primitive {
        out.problems.push(format!(
            "`{shown}` becomes a header but is not typed string, integer or boolean"
        ));
    }
    out.mappings.push(Mapping {
        path: path.to_vec(),
        header: header.to_owned(),
    });
}

/// RFC 9110 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn mapping_problems(mappings: &[Mapping]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for m in mappings {
        if m.header.is_empty() || !m.header.chars().all(is_tchar) {
            problems.push(format!(
                "`x-mcp-header` {:?} of `{}` is not an HTTP header name",
                m.header,
                m.path.join(".")
            ));
        }
        if !seen.insert(m.header.to_ascii_lowercase()) {
            problems.push(format!("`x-mcp-header` {:?} is given twice", m.header));
        }
    }
    problems
}

/// What is wrong with the `$ref`s of `schema`: one that leaves the schema,
/// does not resolve, loops or chains deeper than [`MAX_REF_DEPTH`].
fn ref_problems(schema: &Value, refs: &[(String, String)]) -> Vec<String> {
    let mut problems = Vec::new();
    // Each `$ref`'s pointer to the pointer of its target.
    let mut edges: BTreeMap<&str, String> = BTreeMap::new();
    for (at, target) in refs {
        let Some(pointer) = target.strip_prefix('#') else {
            problems.push(format!(
                "`$ref` {target:?} points outside the schema, which OpenMoat does not fetch"
            ));
            continue;
        };
        if !(pointer.is_empty() || pointer.starts_with('/')) {
            problems.push(format!(
                "`$ref` {target:?} names an anchor, which OpenMoat does not resolve"
            ));
            continue;
        }
        let decoded = decode(pointer);
        if schema.pointer(&decoded).is_none() {
            problems.push(format!("`$ref` {target:?} does not resolve"));
            continue;
        }
        edges.insert(at.as_str(), decoded);
    }
    let mut depths = BTreeMap::new();
    for start in edges.keys() {
        if let Err(why) = chain(&edges, start, &mut Vec::new(), &mut depths) {
            problems.push(why);
            break;
        }
    }
    problems
}

/// How many `$ref`s a validator follows from the one at `at`, at most: 1 for
/// its own, then the longest chain from any `$ref` inside its target. `stack`
/// holds the ones being followed, `depths` the ones already measured; why
/// the chain is refused when it loops or runs past [`MAX_REF_DEPTH`].
fn chain<'a>(
    edges: &BTreeMap<&'a str, String>,
    at: &'a str,
    stack: &mut Vec<&'a str>,
    depths: &mut BTreeMap<&'a str, usize>,
) -> Result<usize, String> {
    if let Some(depth) = depths.get(at) {
        return Ok(*depth);
    }
    if stack.contains(&at) {
        return Err(format!("`$ref`s through {at} form a loop"));
    }
    if stack.len() >= MAX_REF_DEPTH {
        return Err(format!(
            "`$ref`s through {at} chain deeper than {MAX_REF_DEPTH}"
        ));
    }
    let Some(target) = edges.get(at) else {
        return Ok(0);
    };
    stack.push(at);
    let mut deepest = 0;
    // Every `$ref` inside the target's subtree is followed from it.
    let inside: Vec<&'a str> = edges
        .keys()
        .copied()
        .filter(|k| *k == target || k.starts_with(&format!("{target}/")))
        .collect();
    for next in inside {
        deepest = deepest.max(chain(edges, next, stack, depths)?);
    }
    stack.pop();
    let depth = deepest + 1;
    depths.insert(at, depth);
    Ok(depth)
}

/// A key as a JSON pointer token.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// A `$ref`'s fragment as a JSON pointer: percent-escapes decoded.
fn decode(fragment: &str) -> String {
    let bytes = fragment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = fragment.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests;
