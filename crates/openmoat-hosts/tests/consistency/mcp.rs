//! One MCP tool call, sent the way each host sends it (`Host::bench_payload`,
//! the shapes `moat bench` sends), gets one verdict. A host whose payload drops
//! or renames the arguments shows up here: the path or URL in them is what the
//! deny names. GitHub Copilot CLI's payload does not name the server, so it
//! has no row.

use std::path::Path;

use openmoat_core::{Action, Verdict};
use openmoat_hosts::Host;
use openmoat_hosts::bench::{Call, Place};
use serde_json::{Value, json};

use super::{CWD, HOME, decide};

/// Every host that sends `server`'s `tool` with `args` gets `verdict` with
/// `rule` among the decision's rules.
fn check(server: &str, tool: &str, args: &Value, verdict: Verdict, rule: &str) {
    let call = Call::Mcp {
        server: server.to_owned(),
        tool: tool.to_owned(),
        args: args.clone(),
    };
    let place = Place {
        home: Path::new(HOME),
        project: Path::new(CWD),
        session: "s-1",
        call_id: "c-1",
    };
    let mut checked = Vec::new();
    let mut mismatches = Vec::new();
    for host in Host::ALL {
        let Some(payload) = host.bench_payload(&call, &place) else {
            continue;
        };
        match decide(host, &payload) {
            Err(error) => mismatches.push(format!("{host:?}: {error}")),
            Ok((action, _)) if !matches!(action, Action::McpTool { .. }) => {
                mismatches.push(format!("{host:?}: read as {action:?}, not an MCP call"));
            }
            Ok((_, got)) if got.verdict != verdict || !got.rules.iter().any(|r| r == rule) => {
                mismatches.push(format!(
                    "{host:?}: expected {verdict:?} [{rule}], got {:?} {:?}",
                    got.verdict, got.rules
                ));
            }
            Ok(_) => {}
        }
        checked.push(host);
    }
    assert!(checked.len() >= 5, "only {checked:?} send MCP calls");
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn mcp_read_of_a_secret_is_denied_on_every_host() {
    let args = json!({ "path": format!("{HOME}/.ssh/id_rsa") });
    check(
        "filesystem",
        "read_file",
        &args,
        Verdict::Deny,
        "secrets-paths",
    );
}

#[test]
fn mcp_write_of_the_policy_is_denied_on_every_host() {
    let args = json!({ "path": format!("{HOME}/.moat/policy.yaml"), "content": "version: 1\n" });
    check(
        "filesystem",
        "write_file",
        &args,
        Verdict::Deny,
        "kernel-self",
    );
}

#[test]
fn mcp_fetch_of_the_metadata_service_is_denied_on_every_host() {
    let args = json!({ "url": "http://169.254.169.254/latest/meta-data/" });
    check("fetch", "fetch", &args, Verdict::Deny, "cloud-metadata");
}
