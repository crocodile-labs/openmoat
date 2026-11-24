//! The inventory as OCSF 1.3.0 events (ADR-119, docs/TEAM.md "OCSF"):
//!
//! - one Software Inventory Info event (class 5020, Discovery) per agent on
//!   the machine, its `package` the agent and version, OpenMoat's view of it
//!   (hook, liveness, protection) under `unmapped.openmoat`
//!   (<https://schema.ocsf.io/1.3.0/classes/software_info>);
//! - one Device Config State event (class 5002) for the machine: policy, lock,
//!   foreign hooks, MCP servers, run tiers and the latest checkpoint under
//!   `unmapped.openmoat`, its severity raised when the lock drifted or the
//!   policy does not load (<https://schema.ocsf.io/1.3.0/classes/config_state>).
//!
//! Activity 2 (`Collect`), so `type_uid` is `class_uid * 100 + 2`. The OCSF
//! classes have no attributes for OpenMoat's own facts, which is what
//! `unmapped` is for. Built from the redacted document, so nothing here reads
//! a file.

use serde_json::{Value, json};

/// The OCSF schema version the events follow.
pub const OCSF_VERSION: &str = "1.3.0";

const DISCOVERY: u32 = 5;
const SOFTWARE_INVENTORY_INFO: u32 = 5020;
const DEVICE_CONFIG_STATE: u32 = 5002;
const COLLECT: u32 = 2;
const INFORMATIONAL: u32 = 1;
const HIGH: u32 = 4;

/// The events of the redacted inventory document `doc`.
pub fn events(doc: &Value) -> Vec<Value> {
    let time = doc.get("generated_ms").cloned().unwrap_or(json!(0));
    let device = device(doc);
    let metadata = json!({
        "version": OCSF_VERSION,
        "product": {
            "name": "OpenMoat",
            "vendor_name": "OpenMoat",
            "version": doc.get("openmoat_version").cloned().unwrap_or(Value::Null),
        },
        "log_name": "openmoat-inventory",
    });
    let mut out = Vec::new();
    for agent in doc
        .get("agents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("present") == Some(&Value::Bool(true)))
    {
        let version = agent
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let name = agent.get("name").cloned().unwrap_or(Value::Null);
        let level = agent
            .pointer("/protection/level")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        out.push(json!({
            "class_uid": SOFTWARE_INVENTORY_INFO,
            "class_name": "Software Inventory Info",
            "category_uid": DISCOVERY,
            "category_name": "Discovery",
            "activity_id": COLLECT,
            "activity_name": "Collect",
            "type_uid": SOFTWARE_INVENTORY_INFO * 100 + COLLECT,
            "severity_id": INFORMATIONAL,
            "time": time,
            "metadata": metadata,
            "device": device,
            "package": {
                "name": agent.get("id").cloned().unwrap_or(Value::Null),
                "version": version,
            },
            "product": { "name": name },
            "message": format!("{} {version}: {level}", agent["id"].as_str().unwrap_or_default()),
            "unmapped": { "openmoat": agent },
        }));
    }
    let drifted = doc.pointer("/lock/intact") != Some(&Value::Bool(true))
        || doc.pointer("/policy/error").is_some_and(|e| !e.is_null());
    let unmapped: serde_json::Map<String, Value> = [
        "policy",
        "lock",
        "audit",
        "foreign_hooks",
        "mcp_servers",
        "mcp_proxied",
        "run_tiers",
    ]
    .into_iter()
    .filter_map(|key| doc.get(key).map(|v| (key.to_owned(), v.clone())))
    .collect();
    out.push(json!({
        "class_uid": DEVICE_CONFIG_STATE,
        "class_name": "Device Config State",
        "category_uid": DISCOVERY,
        "category_name": "Discovery",
        "activity_id": COLLECT,
        "activity_name": "Collect",
        "type_uid": DEVICE_CONFIG_STATE * 100 + COLLECT,
        "severity_id": if drifted { HIGH } else { INFORMATIONAL },
        "time": time,
        "metadata": metadata,
        "device": device,
        "message": if drifted {
            "OpenMoat's lock or policy is not intact: every agent call is denied"
        } else {
            "OpenMoat's lock and policy are intact"
        },
        "unmapped": { "openmoat": unmapped },
    }));
    out
}

/// The OCSF `device`: type unknown (OpenMoat does not tell a laptop from a
/// server), its operating system, and the name the delivery configuration
/// gives it, else `unnamed`: the class requires one of its names, and the
/// host name is never read.
fn device(doc: &Value) -> Value {
    let os = doc
        .pointer("/machine/os")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = doc
        .pointer("/machine/name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed");
    json!({
        "type_id": 0,
        "type": "Unknown",
        "name": name,
        "os": { "name": os, "type_id": os_type(os) },
    })
}

/// OCSF's `os.type_id` for Rust's `std::env::consts::OS`.
fn os_type(os: &str) -> u32 {
    match os {
        "windows" => 100,
        "linux" => 200,
        "macos" => 300,
        _ => 0,
    }
}
