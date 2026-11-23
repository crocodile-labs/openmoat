//! An MCP fixture's `arguments:`, the call's arguments as a host sends them,
//! flattened as the CLI flattens them for `when:` conditions (ADR-113).

use std::collections::BTreeMap;

use openmoat_core::Arguments;
use serde::Deserialize;

/// One argument's value in a fixture: a string or a list of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum ArgValue {
    One(String),
    Many(Vec<String>),
}

/// `map` as the engine reads arguments, each value under its key.
pub(super) fn flatten(map: &BTreeMap<String, ArgValue>) -> Arguments {
    let mut out = Arguments::new();
    for (key, value) in map {
        match value {
            ArgValue::One(v) => out.push(&[key], v),
            ArgValue::Many(vs) => vs.iter().for_each(|v| out.push(&[key], v)),
        }
    }
    out
}
