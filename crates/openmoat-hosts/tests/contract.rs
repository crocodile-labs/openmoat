//! The host contract, checked the same way for every host: what each spec
//! declares, and that a call the host sends comes back from the hook as what
//! the host must end up doing.

use std::path::Path;

use openmoat_core::{Decision, Verdict};
use openmoat_hosts::bench::{Call, Exit, Place};
use openmoat_hosts::{
    Activity, GUARD_BUDGET_S, HEARTBEAT_FLAG, HOME_FLAG, HookLayout, Host, HostError, KeyShape,
    RelaxedCheck, RunFacts, Sessions, ToolToken, reason_line,
};
use serde_json::json;

/// Every host, the installable ones and those that run another's hook.
const HOSTS: [Host; Host::EVERY.len()] = Host::EVERY;

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
        // A deny exits 2 (invariant 5), or 0 with the deny on stdout for a
        // host that may ignore a non-zero exit; nothing else.
        assert!(matches!(spec.deny_exit, 0 | 2), "{host:?}");
        if let Some(install) = &spec.install {
            assert!(install.dir_name.starts_with('.'), "{host:?}");
            assert!(!install.dir_variable.is_empty(), "{host:?}");
            assert!(!install.config_file.is_empty(), "{host:?}");
        }
    }
}

/// Hosts whose tool commands do not receive `openmoat run`'s relay token
/// (ADR-075, which holds each host's source). Changing a row needs a new source
/// for that host, and an entry in docs/LIMITS.md for one that loses it.
const WITHHELD: [&str; 7] = [
    "claude-code",
    "opencode",
    "goose",
    "pi",
    "hermes",
    "openclaw",
    "continue",
];

#[test]
fn every_host_says_whether_tool_commands_get_the_relay_token() {
    for host in HOSTS {
        let token = host.spec().tool_token;
        assert_eq!(
            token.withheld(),
            WITHHELD.contains(&host.id()),
            "{host:?}: {token:?}"
        );
        match token {
            ToolToken::Wrapper { vars, .. } => assert!(!vars.is_empty(), "{host:?}"),
            ToolToken::NotWithheld { why } => assert!(
                why != "not checked for this host",
                "{host:?} needs a reason of its own"
            ),
            ToolToken::Integration => {}
            _ => panic!("{host:?}: a new kind needs a row here"),
        }
    }
}

/// A host with no OS sandbox of its own has a sourced answer for `openmoat
/// run`, and its program is one the run can tell is that host (ADR-076).
#[test]
fn every_hook_only_host_says_what_openmoat_run_needs() {
    for host in HOSTS.into_iter().filter(|h| h.spec().sandbox.is_none()) {
        let spec = host.spec();
        match spec.run {
            RunFacts::Known {
                program, writes, ..
            } => {
                assert!(spec.process.names.contains(&program), "{host:?}: {program}");
                assert!(!writes.is_empty(), "{host:?}");
            }
            RunFacts::Unknown { why } => assert!(
                why != "not checked for this host",
                "{host:?} needs a reason of its own"
            ),
        }
    }
}

/// A host that serves a port under `openmoat run` has a command, an
/// unprivileged default port, its port variable passed through the run's
/// allowlist, and a key in its hook file (ADR-108 §7). OpenClaw's Gateway is
/// the one such host, on the port its documentation names.
#[test]
fn a_host_that_listens_names_its_one_port() {
    let mut listening = Vec::new();
    for host in HOSTS {
        let spec = host.spec();
        let Some(listen) = spec.run_listen else {
            continue;
        };
        listening.push(host);
        assert!(matches!(spec.run, RunFacts::Known { .. }), "{host:?}");
        assert!(listen.default_port >= 1024, "{host:?}");
        assert!(spec.run_env.contains(&listen.variable), "{host:?}");
        assert!(!listen.key.is_empty(), "{host:?}");
        assert!(
            spec.install.is_some(),
            "{host:?}: the key is read from its hook file"
        );
    }
    assert_eq!(listening, [Host::OpenClaw]);
    let listen = Host::OpenClaw.spec().run_listen.unwrap();
    assert_eq!(listen.default_port, 18789);
    assert_eq!(listen.variable, "OPENCLAW_GATEWAY_PORT");
    assert_eq!(listen.key, ["gateway", "port"]);
}

/// What a host's spec lets through `openmoat run`'s allowlist are names, and
/// never a cloud provider's credentials, which it exists to withhold (ADR-077).
#[test]
fn a_hosts_run_environment_names_no_cloud_credentials() {
    const CLOUD: [&str; 5] = [
        "AWS_",
        "AZURE_CLIENT",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCP_",
        "CLOUDFLARE_",
    ];
    for host in HOSTS {
        for name in host.spec().run_env {
            assert_eq!(
                openmoat_core::env_name_problem(name),
                None,
                "{host:?}: {name}"
            );
            assert!(
                !CLOUD.iter().any(|prefix| name.starts_with(prefix)),
                "{host:?}: {name} is a cloud credential"
            );
        }
    }
}

/// Keys that run a program, change a hook, the sandbox, tools, MCP servers,
/// extensions, folder trust, what a session reads, the environment, updates
/// or telemetry: never a relaxed key, nor below one.
const NEVER_RELAXED: &[&str] = &[
    "hooks",
    "hooksConfig",
    "tools",
    "mcp",
    "mcpServers",
    "extensions",
    "context",
    "advanced",
    "env",
    "telemetry",
    "privacy",
    "security.folderTrust",
    "security.toolSandboxing",
    "security.environmentVariableRedaction",
    "security.auth.enforcedType",
    "security.auth.useExternal",
    "general.preferredEditor",
    "general.enableAutoUpdate",
    "ide.enabled",
    "ui.escapePastedAtSymbols",
    "ui.renderProcess",
];

/// A relaxed key is a dotted path of plain names (`$schema` too), listed
/// once, under none of [`NEVER_RELAXED`], and never names a command. Keys
/// compared one by one are at most one level deep, all in one object, and
/// only they may keep OpenMoat's rules; keys taken out of the file to compare
/// the rest are never that list, which the rest cannot tell from a removed rule.
#[test]
fn relaxed_keys_change_nothing_that_runs_or_decides() {
    for host in Host::ALL {
        let install = host.spec().install.as_ref().unwrap();
        let keys = install.relaxed_keys;
        if keys.is_empty() {
            continue;
        }
        let parent = RelaxedCheck::parent(keys);
        for (i, key) in keys.iter().enumerate() {
            let path = key.path;
            assert!(
                path.split('.').all(|n| {
                    let n = n.strip_prefix('$').unwrap_or(n);
                    !n.is_empty() && n.chars().all(char::is_alphanumeric)
                }),
                "{path}"
            );
            match install.relaxed_check {
                RelaxedCheck::ByKey => assert!(
                    path.split_once('.')
                        .is_none_or(|(p, rest)| Some(p) == parent && !rest.contains('.')),
                    "{host:?}: {path} is not one level under {parent:?}"
                ),
                _ => assert_ne!(key.shape, KeyShape::KeepsWrittenRules, "{host:?}: {path}"),
            }
            assert!(keys[..i].iter().all(|k| k.path != path), "{path} twice");
            for never in NEVER_RELAXED {
                assert!(
                    path != *never && !path.starts_with(&format!("{never}.")),
                    "{host:?}: {path} is under {never}"
                );
            }
            let lower = path.to_ascii_lowercase();
            for word in [
                "command", "editor", "sandbox", "hook", "mcp", "tool", "env", "path",
            ] {
                assert!(!lower.contains(word), "{host:?}: {path} names `{word}`");
            }
        }
    }
}

/// Every hook a host installs waits longer than `moat guard` may take, so the
/// host receives the guard's own deny rather than a timeout; and a failed hook
/// blocks the call wherever the host has a key for it: Claude Code's
/// `onFailure` on its tool hook, Cursor's `failClosed` and Hermes Agent's
/// `fail_closed` and goose's `on_failure: block` (set on every entry of their
/// layouts), OpenClaw's plugin, pi's extension, OpenCode's plugin, Cline's script.
/// Codex and Gemini CLI have no
/// such key, and GitHub Copilot CLI blocks a failed `preToolUse` hook on its own.
#[test]
fn every_hook_outlasts_the_guard_and_blocks_where_the_host_can() {
    let expected: [(Host, &str, &[&str]); 14] = [
        (Host::ClaudeCode, "Entries(Settings)", &["PreToolUse"]),
        (Host::Codex, "Entries(Codex)", &[]),
        (Host::Cursor, "Entries(Cursor)", &[]),
        (Host::OpenClaw, "Plugin(OwnedFile(OpenClaw plugin))", &[]),
        (Host::CopilotCli, "Entries(Copilot)", &[]),
        (Host::Pi, "Owned(OwnedFile(pi extension))", &[]),
        (Host::GeminiCli, "Entries(Gemini)", &[]),
        (Host::OpenCode, "Owned(OwnedFile(OpenCode plugin))", &[]),
        (Host::Hermes, "Yaml(Hermes)", &[]),
        (Host::Cline, "Script(OwnedFile(Cline hook script))", &[]),
        (Host::Goose, "Entries(Goose)", &[]),
        (Host::AntigravityCli, "Entries(Named)", &[]),
        (Host::QwenCode, "Entries(Qwen)", &[]),
        (Host::Crush, "Entries(Crush)", &[]),
    ];
    assert_eq!(expected.len(), Host::ALL.len());
    for (host, layout, blocking) in expected {
        let install = host.spec().install.as_ref().unwrap();
        assert!(!install.hooks.is_empty(), "{host:?}");
        for (i, hook) in install.hooks.iter().enumerate() {
            assert!(!hook.event.is_empty(), "{host:?}");
            assert!(
                install.hooks[..i].iter().all(|h| h.event != hook.event),
                "{host:?} {}: one entry per event",
                hook.event
            );
            assert!(
                hook.timeout > GUARD_BUDGET_S,
                "{host:?} {}: {} s does not outlast the guard's {GUARD_BUDGET_S} s",
                hook.event,
                hook.timeout
            );
        }
        assert_eq!(format!("{:?}", install.hook_file), layout, "{host:?}");
        let blocks: Vec<&str> = install
            .hooks
            .iter()
            .filter(|h| h.block_on_failure)
            .map(|h| h.event)
            .collect();
        assert_eq!(blocks, blocking, "{host:?}");
    }
}

fn assert_activity_shape(host: Host, activity: &Activity) {
    assert!(
        activity.dir.first().is_some_and(|d| *d != Activity::ANY),
        "{host:?}: an activity directory starts with a name"
    );
    assert!(
        activity
            .dir
            .iter()
            .all(|d| !d.is_empty() && !d.contains(['/', '\\'])),
        "{host:?}"
    );
    assert!(!activity.ending.contains(['/', '\\']), "{host:?}");
}

/// Every host that runs a hook command says how `status` and `doctor` tell
/// that it still runs it (ADR-104): where it writes its sessions, or why that
/// is unknown; a host that runs a plugin has its heartbeat instead.
#[test]
fn every_hook_host_declares_its_sessions_or_why_not() {
    for host in Host::ALL {
        let Some(install) = host.spec().install.as_ref() else {
            continue;
        };
        assert_ne!(
            install.heartbeat.is_some(),
            install.liveness.is_some(),
            "{host:?}: a heartbeat or a liveness, exactly one"
        );
        let Some(liveness) = &install.liveness else {
            continue;
        };
        // Its program on the search path is the first of its process names.
        assert!(
            host.spec()
                .process
                .names
                .first()
                .is_some_and(|n| !n.is_empty()),
            "{host:?}"
        );
        for file in liveness.settings {
            assert!(!file.is_empty() && !file.contains(['/', '\\']), "{host:?}");
        }
        match liveness.sessions {
            Sessions::Known(activity) => {
                assert!(!activity.is_empty(), "{host:?}: Known names a place");
                for one in activity {
                    assert_activity_shape(host, one);
                    // A session is a file of its own, told by its name.
                    assert!(!one.ending.is_empty(), "{host:?}");
                }
            }
            Sessions::Unknown(why) => {
                assert!(why.len() > 20, "{host:?}: say why");
                assert!(!why.ends_with('.'), "{host:?}");
            }
        }
    }
}

/// A host that runs OpenMoat through a plugin it loads says how the plugin
/// reports that it loaded, and the plugin runs `guard --heartbeat --host
/// <id> --home <state directory>` (ADR-042, ADR-071); a host that runs a hook
/// command has nothing to report.
#[test]
fn every_plugin_reports_that_it_loaded() {
    for host in Host::ALL {
        let install = host.spec().install.as_ref().unwrap();
        let plugin = match install.hook_file {
            HookLayout::Owned(file) => Some(file),
            HookLayout::Plugin(config) => Some(config.plugin()),
            HookLayout::Entries(_) | HookLayout::Yaml(_) | HookLayout::Script(_) => None,
        };
        assert_eq!(install.heartbeat.is_some(), plugin.is_some(), "{host:?}");
        let (Some(file), Some(heartbeat)) = (plugin, &install.heartbeat) else {
            continue;
        };
        // `WHERE` is the state directory `init` fills in, or in the package of
        // the host's own channel `--plugin` (ADR-099).
        let call = format!(
            r#"["guard", "{HEARTBEAT_FLAG}", "--host", "{}", ...WHERE]"#,
            host.id()
        );
        assert!(file.source.contains(&call), "{host:?} plugin has no {call}");
        let place = format!(
            r#"const WHERE = MOAT_HOME === "" ? ["{}"] : ["{HOME_FLAG}", MOAT_HOME];"#,
            openmoat_hosts::PLUGIN_FLAG
        );
        assert!(
            file.source.contains(&place),
            "{host:?} plugin has no {place}"
        );
        assert!(!heartbeat.program.is_empty(), "{host:?}");
        for activity in heartbeat.activity {
            assert_activity_shape(host, activity);
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
/// it must end up doing: a deny blocks everywhere, and a review the host cannot
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
            for verdict in [
                Verdict::Allow,
                Verdict::Defer,
                Verdict::Review,
                Verdict::Deny,
            ] {
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
    // fetch), OpenClaw 6, GitHub Copilot CLI 5 (its payload names no MCP
    // server), pi 5 (no fetch), Gemini CLI 6 (5 on Windows, whose PowerShell
    // commands OpenMoat leaves to Gemini CLI), OpenCode 6 (5 on Windows, whose
    // shell OpenMoat leaves to OpenCode), Hermes Agent 6, Cline 6 (5 on Windows,
    // whose PowerShell commands OpenMoat leaves to Cline), goose 4 (no read or fetch
    // tool; 3 on Windows, whose `cmd` OpenMoat leaves to goose), Antigravity CLI 6
    // (5 on Windows, whose shell OpenMoat does not classify), Qwen Code 6 (5 on
    // Windows, whose PowerShell commands OpenMoat leaves to Qwen Code), Crush 5
    // (no MCP call, whose `mcp_<server>_<tool>` name cannot be split back; 4 on
    // Windows, whose shell OpenMoat leaves to Crush)
    assert_eq!(checked, 76 - 7 * usize::from(cfg!(windows)));
}

/// ADR-025: `defer` writes nothing, so Claude Code, Codex and the Continue CLI
/// run their own permission flow; hosts that cannot prompt do not turn it into a deny.
#[test]
fn defer_is_no_decision_for_every_pre_tool_use_host() {
    use openmoat_hosts::HookEvent;

    let defer = Decision::new(Verdict::Defer);
    for host in [Host::ClaudeCode, Host::Codex, Host::Continue] {
        let answer = host.answer(&HookEvent::PreToolUse, &defer);
        assert_eq!(answer.verdict, Verdict::Defer, "{host:?}");
        assert_eq!(
            host.render_response(&HookEvent::PreToolUse, &answer),
            "",
            "{host:?}"
        );
    }
}

/// A host that can report a mode in which nobody is asked (a permission mode
/// the payload names, or what the guard reads, ADR-102) says why its review
/// becomes a deny there: `unattended: review` answers such a call with no prompt.
#[test]
fn every_unattended_mode_has_a_no_prompt_reason() {
    for host in Host::ALL {
        let reviews = &host.spec().reviews;
        if !reviews.unattended_modes.is_empty() || reviews.unseen.is_some() {
            assert!(
                reviews.on_no_prompt.is_some(),
                "{host}: an unattended mode with no `on_no_prompt` reason"
            );
        }
        for mode in reviews.unattended_modes {
            assert!(
                !mode.is_empty()
                    && reviews
                        .unattended_modes
                        .iter()
                        .filter(|m| *m == mode)
                        .count()
                        == 1,
                "{host}: `{mode}` listed empty or twice"
            );
        }
    }
}
