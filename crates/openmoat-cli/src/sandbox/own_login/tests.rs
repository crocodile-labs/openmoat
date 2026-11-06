use openmoat_core::ir::Effect;
use openmoat_core::{AtomicAction, DEFAULT_POLICY, EvalContext, Kind, Policy};
use openmoat_hosts::Host;

use super::{ALLOWANCE, Kept, Owner, RULE, for_session, own_patterns, report};
use crate::sandbox::Report;

const HOME: &str = "/Users/me";

fn ctx(moved_dirs: Vec<(String, String)>) -> EvalContext {
    EvalContext {
        home: HOME.into(),
        project: Some(format!("{HOME}/proj")),
        real_home: None,
        real_project: None,
        moved_dirs,
        cwd: format!("{HOME}/proj"),
        case_insensitive_paths: false,
    }
}

/// The default policy, with the whole home readable by an allow rule: what is
/// still denied there is denied by a deny rule, as inside a `--write` grant.
fn default_with_home_readable() -> Policy {
    let mut policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let extra = Policy::parse("version: 1\nallow:\n  - id: home\n    fs.read: ['~/**']\n").unwrap();
    policy.allow.extend(extra.allow);
    policy
}

fn read(path: &str) -> AtomicAction {
    AtomicAction::FsRead { path: path.into() }
}

/// A file `host`'s login is in, under the home: its first pattern without a glob.
fn login_file(host: Host) -> String {
    let pattern = own_patterns(host)
        .into_iter()
        .find(|p| !p.contains(['*', '?', '[', '{']))
        .unwrap();
    pattern.replacen('~', HOME, 1)
}

fn hosts_with_logins() -> Vec<Host> {
    Host::ALL
        .into_iter()
        .filter(|h| !own_patterns(*h).is_empty())
        .collect()
}

#[test]
fn the_agent_is_known_by_the_command_or_the_file_it_starts() {
    let id = |name: &str, program: &str| match Owner::of(name, program) {
        Owner::Agent(host) => Some(host.id()),
        Owner::Unknown => None,
    };
    assert_eq!(
        id("claude", "/Users/me/.local/share/claude/versions/2.1.300"),
        Some("claude-code")
    );
    assert_eq!(
        id(
            "c",
            "/usr/local/lib/node_modules/@openai/codex/bin/codex.js"
        ),
        Some("codex")
    );
    assert_eq!(
        id("goose", "/opt/homebrew/Cellar/goose/1.0/bin/goose"),
        Some("goose")
    );
    assert_eq!(id("npx", "/usr/local/bin/npx"), None);
    assert_eq!(id("bash", "/bin/bash"), None);
}

/// Under `openmoat run -- <agent>` that agent reads its own login; a command
/// it runs still cannot read any other agent's (ADR-054).
#[test]
fn a_session_keeps_its_agents_login_and_denies_every_other() {
    let policy = default_with_home_readable();
    let ctx = ctx(Vec::new());
    let hosts = hosts_with_logins();
    assert!(hosts.len() >= 10, "{hosts:?}");
    for host in &hosts {
        let (sandboxed, kept) = for_session(&policy, &ctx, Owner::Agent(*host), &[]);
        assert!(!kept.patterns.is_empty(), "{host:?}");
        let ir = openmoat_core::ir::lower(&sandboxed, &ctx).unwrap();
        let check = ir.checker().unwrap();
        let own = login_file(*host);
        assert_eq!(
            check.check_os(&read(&own)),
            Some(Effect::Allow),
            "{host:?} {own}"
        );
        for other in hosts.iter().filter(|h| *h != host) {
            let file = login_file(*other);
            if own_patterns(*host)
                .iter()
                .any(|p| p.replacen('~', HOME, 1) == file)
            {
                continue;
            }
            assert_eq!(
                check.check_os(&read(&file)),
                Some(Effect::Deny),
                "{host:?} reads {other:?}'s {file}"
            );
        }
    }
}

/// Without `for_session` every login is denied: what the host sandboxes get.
#[test]
fn every_login_is_denied_to_the_host_sandboxes() {
    let policy = default_with_home_readable();
    let ctx = ctx(Vec::new());
    let ir = crate::sandbox::lower_for_hosts(&policy, HOME, None, Vec::new(), false).unwrap();
    let check = ir.checker().unwrap();
    for host in hosts_with_logins() {
        let file = login_file(host);
        assert_eq!(check.check_os(&read(&file)), Some(Effect::Deny), "{file}");
    }
    // `for_session` changes only the sandbox's copy.
    let (_, _) = for_session(&policy, &ctx, Owner::Unknown, &[]);
    let group = policy.deny.iter().find(|g| g.id == RULE).unwrap();
    assert!(group.fs_read.iter().any(|p| p.contains('{')), "untouched");
}

/// A moved agent directory (`CLAUDE_CONFIG_DIR`) is followed: the agent keeps
/// its login there, and another agent's session still cannot read it.
#[test]
fn a_moved_agent_directory_is_followed() {
    let policy = default_with_home_readable();
    // Inside the home, which the test policy lets the sandbox read.
    let moved = vec![("~/.claude".to_owned(), format!("{HOME}/state/claude"))];
    let ctx = ctx(moved);
    let file = &format!("{HOME}/state/claude/.credentials.json");
    let claude = Owner::of("claude", "/usr/local/bin/claude");
    let codex = Owner::of("codex", "/usr/local/bin/codex");
    for (owner, want) in [(claude, Effect::Allow), (codex, Effect::Deny)] {
        let (sandboxed, _) = for_session(&policy, &ctx, owner, &[]);
        let ir = openmoat_core::ir::lower(&sandboxed, &ctx).unwrap();
        let check = ir.checker().unwrap();
        assert_eq!(check.check_os(&read(file)), Some(want), "{owner:?}");
    }
}

/// Another program keeps the logins inside its `--write` paths, which the
/// person granted it, and no other.
#[test]
fn another_program_keeps_the_logins_in_its_write_paths() {
    let policy = default_with_home_readable();
    let ctx = ctx(Vec::new());
    let writes = [format!("{HOME}/.config/goose")];
    let (sandboxed, kept) = for_session(&policy, &ctx, Owner::Unknown, &writes);
    assert_eq!(kept.patterns, ["~/.config/goose/secrets.yaml"]);
    let ir = openmoat_core::ir::lower(&sandboxed, &ctx).unwrap();
    let check = ir.checker().unwrap();
    let goose = format!("{HOME}/.config/goose/secrets.yaml");
    let anthropic = format!("{HOME}/.config/anthropic/x.json");
    assert_eq!(check.check_os(&read(&goose)), Some(Effect::Allow));
    assert_eq!(check.check_os(&read(&anthropic)), Some(Effect::Deny));
    let (_, none) = for_session(&policy, &ctx, Owner::Unknown, &[]);
    assert_eq!(none.patterns, Vec::<String>::new());
}

/// A policy that keeps the group `hook_only` (an older default, or a person
/// who runs one agent's CLI from inside another) reaches no sandbox, and the
/// session does not touch it.
#[test]
fn a_hook_only_group_is_left_as_it_is() {
    let yaml = "version: 1\ndeny:\n  - id: agent-credentials\n    hook_only: true\n    \
                fs.read: ['~/.codex/{auth.json,.credentials.json}']\n";
    let policy = Policy::parse(yaml).unwrap();
    let codex = Owner::of("codex", "/usr/local/bin/codex");
    let (sandboxed, kept) = for_session(&policy, &ctx(Vec::new()), codex, &[]);
    assert_eq!(kept.patterns, Vec::<String>::new());
    assert_eq!(sandboxed.deny[0].fs_read, policy.deny[0].fs_read);
}

/// The settings OpenMoat writes for each host deny another agent's token to
/// the commands the agent runs, and the agent's own too: the host process
/// signs in outside its sandbox, which confines only those commands.
#[test]
fn the_host_settings_deny_every_agents_login_to_commands() {
    use crate::sandbox::{claude, codex, cursor};
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let ir = crate::sandbox::lower_for_hosts(&policy, HOME, None, Vec::new(), false).unwrap();
    let logins = [
        format!("{HOME}/.claude/.credentials.json"),
        format!("{HOME}/.config/anthropic"),
        format!("{HOME}/.local/share/opencode/auth.json"),
        format!("{HOME}/.gemini/oauth_creds.json"),
    ];
    for linux in [false, true] {
        let settings = claude::generate(&ir, None, linux).unwrap();
        let fs = &settings.sandbox["filesystem"];
        for key in ["denyRead", "denyWrite"] {
            let list: Vec<&str> = fs[key]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            for login in &logins {
                assert!(list.contains(&login.as_str()), "{key} {login}: {list:?}");
            }
            assert!(list.iter().all(|p| !p.contains('{')), "{list:?}");
        }
        let read = format!("Read(/{HOME}/.claude/.credentials.json)");
        assert!(
            settings.deny_rules.contains(&read),
            "{:?}",
            settings.deny_rules
        );
    }
    let profile = codex::generate(&ir, &[HOME.into()], None).unwrap().profile;
    let fs = profile["filesystem"].as_table().unwrap();
    for login in &logins {
        assert_eq!(
            fs.get(login).and_then(|v| v.as_str()),
            Some("deny"),
            "{login}"
        );
    }
    // Codex's own home is denied whole, its login with it.
    assert_eq!(
        fs.get(&format!("{HOME}/.codex")).and_then(|v| v.as_str()),
        Some("deny")
    );
    // Cursor has no deny key: it grants no read path that holds a login.
    let cursor = cursor::generate(&ir, None).unwrap().settings;
    let reads = cursor["additionalReadPaths"].as_array().unwrap();
    for read in reads.iter().filter_map(|v| v.as_str()) {
        for login in &logins {
            assert!(!login.starts_with(read), "{read} holds {login}");
        }
    }
}

#[test]
fn what_a_session_keeps_is_reported_as_wider() {
    let ctx = ctx(Vec::new());
    let codex = Owner::of("codex", "/usr/local/bin/codex");
    let kept = Kept {
        owner: codex,
        patterns: vec!["~/.codex/auth.json".into()],
    };
    let mut out = Report::default();
    report(&mut out, &kept, &ctx);
    let kinds: Vec<Kind> = out.allowances.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, [Kind::FsRead, Kind::FsWrite]);
    let allowance = &out.allowances[0];
    assert_eq!(allowance.rule, ALLOWANCE);
    assert_eq!(allowance.patterns, [format!("{HOME}/.codex/auth.json")]);
    assert!(allowance.message.contains("Codex"), "{}", allowance.message);
    let mut empty = Report::default();
    let nothing = Kept {
        owner: Owner::Unknown,
        patterns: Vec::new(),
    };
    report(&mut empty, &nothing, &ctx);
    assert_eq!(empty.allowances, Vec::new());
}
