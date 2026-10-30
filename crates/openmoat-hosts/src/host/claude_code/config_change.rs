//! Claude Code `ConfigChange` hook: fired when a settings file changes on disk.
//!
//! Blocking refuses to load the new settings into the running session; the
//! file itself is left as written. The kernel uses this to keep a tampered hook
//! file from taking effect even before the next tool call.
//!
//! Claude Code sends `source` (`user_settings`, `project_settings`,
//! `local_settings`, `policy_settings`, `skills`) and an optional `file_path`;
//! `change_type` came from earlier builds and is still accepted.

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;

use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) const EVENT: &str = "ConfigChange";

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    source: String,
    #[serde(default)]
    change_type: Option<String>,
    #[serde(default)]
    file_path: Option<String>,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    // An absent path is a change Claude Code did not attribute to one file; an
    // empty one is a malformed payload.
    if p.file_path.as_deref() == Some("") {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "file_path",
        });
    }
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: None,
        cwd: p.cwd,
        tool: EVENT.to_owned(),
        action: p.file_path.map(|path| Action::FsWrite { path }),
        content: None,
        edits: Vec::new(),
        mcp_arguments: None,
        event: HookEvent::ConfigChange {
            source: p.source,
            change_type: p.change_type,
        },
    })
}

/// Separates a settings file's name from the random suffix of its staged copy.
const PROPOSED: &str = ".proposed-";

/// The settings file a settings-review proposal will replace, when `path` is one.
///
/// When the owner accepts a staged change in `/settings-review`, Claude Code
/// writes the new contents to `<file>.proposed-<8 hex digits>` next to the
/// settings file and fires `ConfigChange` for that copy; only if no hook blocks
/// does it rename the copy over the file, after checking the copy's bytes did
/// not change. So the copy's contents are exactly what the file will hold.
#[must_use]
pub fn proposal_target(path: &str) -> Option<String> {
    let (target, suffix) = path.rsplit_once(PROPOSED)?;
    let named = !target.is_empty() && !target.ends_with(['/', '\\']);
    let random = suffix.len() == 8
        && suffix
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (named && random).then(|| target.to_owned())
}

/// `{}` lets the change load; anything else blocks it with a reason.
pub(crate) fn render(decision: &Decision) -> String {
    match decision.verdict {
        Verdict::Allow => "{}".to_owned(),
        // `Ask`, `Deny` and any verdict added to the core later block the
        // change. A `Value` always renders, unlike serializing a struct; its
        // keys sort, and these are already in order.
        _ => serde_json::json!({
            "decision": "block",
            "reason": crate::reason_line(decision),
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/host/claude_code/fixtures"
        );
        std::fs::read_to_string(format!("{dir}/{name}.json")).unwrap()
    }

    const PAYLOAD: &str = r#"{
        "session_id": "abc123", "cwd": "/p", "hook_event_name": "ConfigChange",
        "source": "user_settings", "change_type": "modified",
        "file_path": "/Users/me/.claude/settings.json"
    }"#;

    #[test]
    fn parses_into_a_file_write_with_event_details() {
        let req = Host::ClaudeCode.parse_request(PAYLOAD).unwrap();
        assert_eq!(req.tool, "ConfigChange");
        assert_eq!(
            req.action,
            Some(Action::FsWrite {
                path: "/Users/me/.claude/settings.json".into()
            })
        );
        assert!(matches!(
            req.event,
            HookEvent::ConfigChange { ref source, ref change_type }
                if source == "user_settings" && change_type.as_deref() == Some("modified")
        ));
    }

    #[test]
    fn current_payload_has_no_change_type() {
        let req = Host::ClaudeCode
            .parse_request(&fixture("config-change"))
            .unwrap();
        assert_eq!(
            req.action,
            Some(Action::FsWrite {
                path: "/Users/me/.claude/settings.json".into()
            })
        );
        assert_eq!(
            req.event,
            HookEvent::ConfigChange {
                source: "user_settings".into(),
                change_type: None,
            }
        );
    }

    #[test]
    fn a_settings_review_copy_names_its_target() {
        let req = Host::ClaudeCode
            .parse_request(&fixture("config-change-proposed"))
            .unwrap();
        let Some(Action::FsWrite { path }) = req.action else {
            panic!("{:?}", req.action);
        };
        assert_eq!(
            proposal_target(&path).as_deref(),
            Some("/Users/me/.claude/settings.json")
        );
        for other in [
            "/Users/me/.claude/settings.json",
            "/Users/me/.claude/settings.json.proposed-1234567",
            "/Users/me/.claude/settings.json.proposed-1234567G",
            "/Users/me/.claude/.proposed-0a1b2c3d",
        ] {
            assert_eq!(proposal_target(other), None, "{other}");
        }
    }

    #[test]
    fn a_change_without_a_file_has_no_action() {
        let req = Host::ClaudeCode
            .parse_request(&fixture("config-change-no-file"))
            .unwrap();
        assert_eq!(req.action, None);
        assert!(matches!(
            req.event,
            HookEvent::ConfigChange { ref source, .. } if source == "skills"
        ));
    }

    #[test]
    fn unreadable_payload_still_answers_in_config_change_shape() {
        let bad = r#"{"hook_event_name":"ConfigChange","source":7}"#;
        assert!(Host::ClaudeCode.parse_request(bad).is_err());
        let event = Host::ClaudeCode.event_of(bad);
        assert!(matches!(event, HookEvent::ConfigChange { .. }));
        let out: serde_json::Value = serde_json::from_str(
            &Host::ClaudeCode.render_response(&event, &Decision::new(Verdict::Deny)),
        )
        .unwrap();
        assert_eq!(out["decision"], "block");
    }

    #[test]
    fn block_bytes_are_exact_and_escaped() {
        let mut deny = Decision::new(Verdict::Deny);
        deny.reasons.push("say \"hi\"\n\\".into());
        assert_eq!(
            render(&deny),
            r#"{"decision":"block","reason":"moat: deny — say \"hi\"\n\\"}"#
        );
    }

    #[test]
    fn missing_path_is_an_error() {
        let bad = r#"{"hook_event_name":"ConfigChange","source":"user_settings","change_type":"deleted","file_path":""}"#;
        assert!(matches!(
            Host::ClaudeCode.parse_request(bad),
            Err(HostError::MissingField {
                field: "file_path",
                ..
            })
        ));
    }

    #[test]
    fn allow_is_empty_and_deny_blocks_with_reason() {
        let event = HookEvent::ConfigChange {
            source: "user_settings".into(),
            change_type: Some("modified".into()),
        };
        assert_eq!(
            Host::ClaudeCode.render_response(&event, &Decision::new(Verdict::Allow)),
            "{}"
        );
        let mut deny = Decision::new(Verdict::Deny);
        deny.rules.push("kernel-integrity".into());
        deny.reasons
            .push("settings.json changed outside OpenMoat".into());
        let out: serde_json::Value =
            serde_json::from_str(&Host::ClaudeCode.render_response(&event, &deny)).unwrap();
        assert_eq!(out["decision"], "block");
        assert!(out["reason"].as_str().unwrap().contains("kernel-integrity"));
    }
}
