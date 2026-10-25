//! Every host's own files beside the hook: MCP servers pinned at `init`, and
//! settings that turn OpenMoat's hook off.

use std::fs;

use openmoat_hosts::Host;
use serde_json::Value;

use super::{assert_reason, dir_of, guard, row};
use crate::common::{DENY, OK, Sandbox, json, text};

/// The `agents` entry of `moat status --format json` for the host `id`.
fn agent(sb: &Sandbox, id: &str) -> Value {
    let doc = json(&sb.moat(&["status", "--format", "json"]));
    doc["agents"]
        .as_array()
        .and_then(|agents| agents.iter().find(|a| a["host"] == id).cloned())
        .unwrap_or_else(|| panic!("{id} missing: {doc}"))
}

/// The servers in the host's MCP file are pinned at `init`; a changed one
/// holds back only its own tools until a person accepts it, and the other
/// servers and calls run: it is not drift of the whole file.
#[test]
fn a_changed_mcp_server_holds_back_only_its_tools() {
    for host in Host::ALL {
        let (id, row) = (host.id(), row(host.id()));
        let Some(mcp) = &row.mcp else { continue };
        let dir = dir_of(host);
        let dir = dir.as_str();
        let sb = Sandbox::bare(&[dir]);
        let file = sb.home.join(dir).join(mcp.file);
        fs::write(&file, (mcp.servers)(mcp.command)).unwrap();
        let out = sb.moat(&["init", "--yes", "--hosts", id]);
        assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
        assert!(text(&out).contains(mcp.pinned), "{id}: {}", text(&out));
        let call = |tool: &str| guard(&row, &sb, &(mcp.call)(&sb, tool));
        let out = call(mcp.tool);
        assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));

        let quoted = format!("\"{}\"", mcp.command);
        let now = fs::read_to_string(&file).unwrap();
        assert!(now.contains(&quoted), "{id}: {now}");
        fs::write(&file, now.replacen(&quoted, "\"sh\"", 1)).unwrap();
        let out = call(mcp.tool);
        assert_eq!(out.status.code(), Some(DENY), "{id}: {}", text(&out));
        assert_reason(&row, &out, "mcp-server-changed", "changed server");
        let accept = format!("openmoat mcp accept {}", mcp.server);
        assert_reason(&row, &out, &accept, "changed server");
        if let Some(other) = mcp.other_tool {
            let out = call(other);
            assert_eq!(out.status.code(), Some(OK), "{id}: other servers run");
        }
        if let Some(benign) = row.benign {
            let out = guard(&row, &sb, &benign(&sb));
            assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
        }

        let accepted = sb.moat_approving(&["mcp", "accept", mcp.server]);
        assert_eq!(
            accepted.status.code(),
            Some(OK),
            "{id}: {}",
            text(&accepted)
        );
        let out = call(mcp.tool);
        assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
    }
}

/// A setting in the host's own settings that turns its hooks off leaves the
/// hook installed and pinned, yet the agent is not protected.
#[test]
fn hooks_turned_off_in_user_settings_is_not_protected() {
    for host in Host::ALL {
        let (id, row) = (host.id(), row(host.id()));
        let Some(off) = &row.hooks_off else { continue };
        let dir = dir_of(host);
        let dir = dir.as_str();
        let sb = Sandbox::bare(&[dir]);
        let file = sb.home.join(dir).join(off.file);
        if off.before_init {
            fs::write(&file, (off.change)("")).unwrap();
        }
        let out = sb.moat(&["init", "--yes"]);
        assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
        if !off.before_init {
            let before = agent(&sb, id);
            assert_ne!(before["level"], "not-protected", "{id}: {before}");
            let now = fs::read_to_string(&file).unwrap_or_default();
            fs::write(&file, (off.change)(&now)).unwrap();
        }
        let after = agent(&sb, id);
        assert_eq!(after["level"], "not-protected", "{id}: {after}");
        assert!(
            after["reason"].to_string().contains(off.names),
            "{id}: {after}"
        );
    }
}
