//! The host contract, checked the same way for every host: what each spec
//! declares, and that a call the host sends comes back from the hook as what
//! the host must end up doing.

use std::path::Path;

use openmoat_core::{Decision, Verdict};
use openmoat_hosts::bench::{Call, Exit, Place};
use openmoat_hosts::{Host, HostError, reason_line};
use serde_json::json;

/// Every host, the installable ones and those that run another's hook.
const HOSTS: [Host; 5] = [
    Host::ClaudeCode,
    Host::Codex,
    Host::Cursor,
    Host::Continue,
    Host::OpenClaw,
];

fn calls() -> Vec<Call> {
    vec![
        Call::Shell("ls -la".to_owned()),
        Call::Read("src/main.rs".to_owned()),
        Call::Write("notes.txt".to_owned()),
        Call::Edit("src/main.rs".to_owned()),
        Call::Fetch("https://example.com/".to_owned()),
        Call::Mcp {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            args: json!({ "path": "/tmp/x" }),
        },
    ]
}

#[test]
fn every_spec_is_complete() {
    for (i, host) in HOSTS.into_iter().enumerate() {
        let spec = host.spec();
        assert!(HOSTS[..i].iter().all(|h| h.id() != spec.id), "{host:?}");
        assert!(!spec.display_name.is_empty(), "{host:?}");
        assert!(!spec.on_hook_failure.is_empty(), "{host:?}");
        assert!(!spec.gaps.is_empty(), "{host:?}");
        // a host with a hook of its own installs it; one that sends another's
        // format runs that host's hook
        assert_eq!(
            spec.install.is_some(),
            Host::ALL.contains(&host),
            "{host:?}"
        );
        assert_eq!(spec.speaks.is_some(), spec.install.is_none(), "{host:?}");
        if let Some(install) = &spec.install {
            assert!(install.dir_name.starts_with('.'), "{host:?}");
            assert!(!install.dir_variable.is_empty(), "{host:?}");
            assert!(!install.config_file.is_empty(), "{host:?}");
        }
    }
}

#[test]
fn malformed_payloads_and_unknown_events_are_errors() {
    for host in HOSTS {
        assert!(
            matches!(host.parse_request("{"), Err(HostError::Json(_))),
            "{host:?}"
        );
        let unknown = json!({ "hook_event_name": "NoSuchEvent" }).to_string();
        assert!(
            matches!(host.parse_request(&unknown), Err(HostError::WrongEvent(_))),
            "{host:?}"
        );
    }
}

/// What `moat guard` does with `verdict` on the payload `host` sends for
/// `call`: the decision it records, how the host receives it, and how the
/// hook process ends.
fn guard(host: Host, payload: &str, verdict: Verdict) -> (i32, String, String) {
    let request = host.parse_request(payload).unwrap();
    let recorded = host.decided(&request.event, Decision::new(verdict));
    let answer = host.answer(&request.event, &recorded);
    let stdout = host.render_response(&request.event, &answer);
    if answer.verdict == Verdict::Deny {
        (2, stdout, reason_line(&answer))
    } else {
        (0, stdout, String::new())
    }
}

/// Every call a host sends parses, and every verdict reaches the host as what
/// it must end up doing: a deny blocks everywhere, and an ask the host cannot
/// put to a person blocks too.
#[test]
fn every_verdict_reaches_the_host_as_it_must() {
    let home = Path::new("/home/u");
    let project = Path::new("/home/u/work/repo");
    let at = Place {
        home,
        project,
        session: "s-1",
        call_id: "c-1",
    };
    let mut checked = 0;
    for host in Host::ALL {
        for call in calls() {
            let Some(payload) = host.bench_payload(&call, &at) else {
                continue;
            };
            checked += 1;
            for verdict in [Verdict::Allow, Verdict::Defer, Verdict::Ask, Verdict::Deny] {
                let (code, stdout, stderr) = guard(host, &payload, verdict);
                let exit = Exit {
                    code: Some(code),
                    stdout: &stdout,
                    stderr: &stderr,
                };
                let got = host.read_reply(&call, &exit);
                let want = host.seen(&call, verdict);
                assert!(
                    got.meets(want),
                    "{host:?} {call:?} {verdict:?}: the host reads {got:?}, must see {want:?}"
                );
                if verdict == Verdict::Deny {
                    assert_eq!(got.word(), "deny", "{host:?} {call:?}");
                }
            }
        }
    }
    // Claude Code 6 calls, Codex 4 (no read or fetch tool), Cursor 5 (no
    // fetch), OpenClaw 6
    assert_eq!(checked, 21);
}
