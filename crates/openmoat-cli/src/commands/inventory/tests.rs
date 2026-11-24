use std::collections::BTreeSet;

use openmoat_audit::KnownSecrets;
use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::collect::{
    AgentProtection, AuditState, CheckpointState, ForeignHooks, Inventory, LockState, Machine,
    McpProxied, McpServer, PolicyState, Release, RunTier, Team,
};
use super::*;
use crate::protection::Level;

/// An inventory as `collect` builds it, with every optional part filled, so
/// the snapshot below sees every key. Built by hand: a unit test reads no
/// agent's configuration directory.
fn sample(lock_intact: bool) -> Inventory {
    let host = Host::ALL[0];
    let other = Host::ALL[1];
    let agent = |host: Host, present: bool| collect::Agent {
        id: host.id(),
        name: host.display_name(),
        present,
        version: present.then(|| "1.2.3".to_owned()),
        hook_installed: present,
        hook_liveness: None,
        protection: AgentProtection {
            level: if present {
                Level::HookOnly
            } else {
                Level::NotFound
            },
            tier: if present { "hook-only" } else { "none" },
            score: present.then_some(0),
            reason: Some("/home/someone/.config/agent/settings.json is fine".into()),
            required_met: Some(true),
        },
    };
    Inventory {
        format: collect::FORMAT,
        openmoat_version: "0.0.0",
        generated_ms: 1_700_000_000_000,
        machine: Machine {
            name: Some("dev-17".into()),
            os: "linux",
            arch: "x86_64",
        },
        agents: vec![agent(host, true), agent(other, false)],
        run_tiers: vec![RunTier {
            tier: "lightweight",
            score: Some(70),
            complete: false,
        }],
        foreign_hooks: ForeignHooks {
            mode: "hold",
            recorded: 2,
            waiting: 1,
            holding: 1,
        },
        mcp_servers: vec![McpServer {
            host: host.id().into(),
            name: "files".into(),
            file: "/home/someone/.config/agent/mcp.json".into(),
            pinned: true,
            digest: Some("0123456789abcdef".into()),
            release: Some(Release {
                ecosystem: "npm".into(),
                package: "files-mcp".into(),
                version: Some("1.0.0".into()),
                integrity: Some("sha512-x".into()),
            }),
            protected: Some(false),
        }],
        mcp_proxied: vec![McpProxied {
            server: "files".into(),
            tools: 3,
            held: 0,
        }],
        policy: PolicyState {
            sha256: Some("ab".repeat(32)),
            version: Some(1),
            source: "team",
            team: Some(Team {
                name: "acme".into(),
                serial: 3,
                signer: "sec@acme.example".into(),
                manifest_sha256: "cd".repeat(32),
            }),
            packs: vec!["cloud".into()],
            deny_rules: 10,
            allow_rules: 4,
            review_rules: 6,
            error: None,
        },
        lock: LockState {
            present: true,
            intact: lock_intact,
            pinned: 12,
            drifted: usize::from(!lock_intact),
        },
        audit: AuditState {
            events: Some(42),
            signing_key: Some("SHA256:abc".into()),
            checkpoint: Some(CheckpointState {
                size: 1000,
                holds: true,
            }),
        },
    }
}

/// Every key path of `value`, arrays read through their first element.
fn paths(value: &Value, at: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let here = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                out.insert(here.clone());
                paths(v, &here, out);
            }
        }
        Value::Array(items) => {
            if let Some(first) = items.first() {
                paths(first, &format!("{at}[]"), out);
            }
        }
        _ => {}
    }
}

const SCHEMA: &[&str] = &[
    "format",
    "openmoat_version",
    "generated_ms",
    "machine",
    "machine.name",
    "machine.os",
    "machine.arch",
    "agents",
    "agents[].id",
    "agents[].name",
    "agents[].present",
    "agents[].version",
    "agents[].hook_installed",
    "agents[].hook_liveness",
    "agents[].protection",
    "agents[].protection.level",
    "agents[].protection.tier",
    "agents[].protection.score",
    "agents[].protection.reason",
    "agents[].protection.required_met",
    "run_tiers",
    "run_tiers[].tier",
    "run_tiers[].score",
    "run_tiers[].complete",
    "foreign_hooks",
    "foreign_hooks.mode",
    "foreign_hooks.recorded",
    "foreign_hooks.waiting",
    "foreign_hooks.holding",
    "mcp_servers",
    "mcp_servers[].host",
    "mcp_servers[].name",
    "mcp_servers[].file",
    "mcp_servers[].pinned",
    "mcp_servers[].digest",
    "mcp_servers[].release",
    "mcp_servers[].release.ecosystem",
    "mcp_servers[].release.package",
    "mcp_servers[].release.version",
    "mcp_servers[].release.integrity",
    "mcp_servers[].protected",
    "mcp_proxied",
    "mcp_proxied[].server",
    "mcp_proxied[].tools",
    "mcp_proxied[].held",
    "policy",
    "policy.sha256",
    "policy.version",
    "policy.source",
    "policy.team",
    "policy.team.name",
    "policy.team.serial",
    "policy.team.signer",
    "policy.team.manifest_sha256",
    "policy.packs",
    "policy.deny_rules",
    "policy.allow_rules",
    "policy.review_rules",
    "policy.error",
    "lock",
    "lock.present",
    "lock.intact",
    "lock.pinned",
    "lock.drifted",
    "audit",
    "audit.events",
    "audit.signing_key",
    "audit.checkpoint",
    "audit.checkpoint.size",
    "audit.checkpoint.holds",
];

/// The JSON document's shape (`openmoat-inventory-v1`): a key added, removed
/// or renamed changes what fleet tools read, so it changes this list and the
/// format name together.
#[test]
fn the_inventory_document_keeps_its_schema() {
    let doc = serde_json::to_value(sample(true)).unwrap();
    let mut found = BTreeSet::new();
    paths(&doc, "", &mut found);
    let expected: BTreeSet<String> = SCHEMA.iter().map(|k| (*k).to_owned()).collect();
    assert_eq!(found, expected);
    assert_eq!(doc["format"], "openmoat-inventory-v1");
    assert_eq!(doc["agents"][0]["protection"]["level"], "hook-only");
}

/// Each agent present is one Software Inventory Info event and the machine
/// one Device Config State event, each with the attributes OCSF 1.3.0
/// requires of the class outside its profiles.
#[test]
fn the_ocsf_events_carry_their_classes_and_required_attributes() {
    let doc = serde_json::to_value(sample(true)).unwrap();
    let events = ocsf::events(&doc);
    assert_eq!(events.len(), 2, "the absent agent has no event");
    for event in &events {
        for key in [
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "severity_id",
            "time",
            "metadata",
            "device",
        ] {
            assert!(event.get(key).is_some(), "{key}: {event}");
        }
        let class = event["class_uid"].as_u64().unwrap();
        assert_eq!(event["category_uid"], 5);
        assert_eq!(event["activity_id"], 2);
        assert_eq!(event["type_uid"].as_u64().unwrap(), class * 100 + 2);
        assert_eq!(event["metadata"]["version"], ocsf::OCSF_VERSION);
        assert_eq!(event["metadata"]["product"]["name"], "OpenMoat");
        assert_eq!(event["device"]["type_id"], 0);
        assert_eq!(event["device"]["name"], "dev-17");
        assert_eq!(event["device"]["os"]["type_id"], 200);
    }
    let software = &events[0];
    assert_eq!(software["class_uid"], 5020);
    assert_eq!(software["package"]["name"], Host::ALL[0].id());
    assert_eq!(software["package"]["version"], "1.2.3");
    assert_eq!(
        software["unmapped"]["openmoat"]["protection"]["tier"],
        "hook-only"
    );
    let machine = &events[1];
    assert_eq!(machine["class_uid"], 5002);
    assert_eq!(machine["severity_id"], 1);
    assert_eq!(machine["unmapped"]["openmoat"]["policy"]["source"], "team");

    let drifted = ocsf::events(&serde_json::to_value(sample(false)).unwrap());
    assert_eq!(drifted[1]["severity_id"], 4);
}

/// The person's home is `~` everywhere.
#[test]
fn the_home_is_written_as_a_tilde() {
    let doc = serde_json::to_value(sample(true)).unwrap();
    let homes = vec!["/home/someone".to_owned()];
    let shown = collect::tilde(doc, &homes).to_string();
    assert!(!shown.contains("/home/someone"), "{shown}");
    assert!(shown.contains("~/.config/agent/mcp.json"), "{shown}");
}

/// What a sink is sent is masked by the sink's own header value and the
/// policy's secrets, in every event and every nested text.
#[test]
fn delivered_events_are_masked() {
    // Made at run time, shaped like no known token.
    let header = format!("plain{}words{}", "-and-", 31_337);
    let brokered = format!("kept{}value{}", "-from-", 4_242);
    let mut inventory = sample(true);
    inventory.mcp_servers[0].name = format!("files {header}");
    inventory.policy.packs.push(brokered.clone());
    let doc = serde_json::to_value(inventory).unwrap();
    let events = ocsf::events(&doc);
    assert!(events.iter().any(|e| e.to_string().contains(&header)));
    let known = KnownSecrets::new([header.as_str(), brokered.as_str()]).unwrap();
    for event in deliver::mask(&known, &events) {
        let text = event.to_string();
        assert!(!text.contains(&header), "{text}");
        assert!(!text.contains(&brokered), "{text}");
    }
}

/// The audit log's own patterns apply before anything is printed.
#[test]
fn the_document_passes_the_audit_redaction() {
    let token = format!("gh{}_{}", "p", "Ab1".repeat(12));
    let doc = json!({ "agents": [{ "protection": { "reason": format!("token {token}") } }] });
    let shown = collect::redacted(doc).to_string();
    assert!(!shown.contains(&token), "{shown}");
}
