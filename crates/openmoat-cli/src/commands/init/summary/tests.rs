use openmoat_hosts::Host;

use super::super::ask::{INTRO, Widths};
use super::*;
use crate::protection::Level;

fn agent(id: &str, level: Level) -> Protection {
    let host = Host::ALL.into_iter().find(|h| h.id() == id).unwrap();
    Protection {
        host: host.id(),
        name: host.display_name(),
        level,
        reason: None,
        gaps: "",
        limit: None,
        required: None,
        os_sandbox: None,
        hook_failure: None,
    }
}

fn rendered(done: &Done<'_>) -> String {
    let mut text = Vec::new();
    let paths = report::Paths::under(Some(Path::new("/Users/you")));
    done.render(Style::new(false, None), &paths, &mut text)
        .unwrap();
    String::from_utf8(text).unwrap()
}

#[test]
fn init_ends_with_the_agents_protected_and_only_the_steps_left() {
    let widths = Widths {
        name: "Claude Code".len(),
        dir: "~/.openclaw".len(),
        what: "adds hook + sandbox settings".len(),
    };
    let style = Style::new(false, None);
    let mut shown = format!("{INTRO}\n\n");
    for (name, dir, what) in [
        (
            "Claude Code",
            "~/.claude",
            Some("adds hook + sandbox settings"),
        ),
        ("Codex", "~/.codex", Some("adds hook + sandbox settings")),
        ("OpenClaw", "~/.openclaw", None),
    ] {
        shown.push_str(&widths.line(name, dir, what, style));
        shown.push_str(if what.is_some() { "y\n" } else { "\n" });
    }
    let agents = [
        agent("claude-code", Level::HookAndOsSandbox),
        agent("codex", Level::HookAndOsSandbox),
        agent("openclaw", Level::HookOnly),
    ];
    let steps = Steps {
        trust: vec![("Codex", "open Codex and trust OpenMoat's hook in /hooks")],
        update: None,
        changed: true,
    };
    let done = Done {
        agents: &agents,
        steps: &steps,
        backups: 2,
        verbose: false,
    };
    shown.push_str(&rendered(&done));
    println!("{shown}");
    assert!(
        shown.contains("  OpenClaw     ~/.openclaw  already set up                ✔\n"),
        "{shown}"
    );
    assert!(
        shown.contains(
            "  Codex        ~/.codex     adds hook + sandbox settings  Protect? [Y/n/d] y"
        ),
        "{shown}"
    );
    assert!(shown.contains("\n✔ 3 agents protected\n"), "{shown}");
    assert!(
        shown.contains("  Claude Code  ✔ hook + OS sandbox\n"),
        "{shown}"
    );
    assert!(shown.contains("  OpenClaw     ✔ hook only\n"), "{shown}");
    assert!(
        shown.contains("  1. Codex: open Codex and trust OpenMoat's hook in /hooks\n  2. Restart"),
        "{shown}"
    );
    assert!(
        shown.contains("  3. Try it: openmoat policy check"),
        "{shown}"
    );
    assert!(shown.ends_with(
        "Backups saved · undo everything: openmoat uninstall · check any time: openmoat status · \
         details: openmoat init --verbose\n"
    ));
}

#[test]
fn nothing_changed_needs_no_restart_and_names_no_trust_step() {
    let agents = [agent("claude-code", Level::HookAndOsSandbox)];
    let steps = Steps::default();
    let done = Done {
        agents: &agents,
        steps: &steps,
        backups: 0,
        verbose: true,
    };
    let shown = rendered(&done);
    assert!(!shown.contains("Restart"), "{shown}");
    assert!(!shown.contains("Backups saved"), "{shown}");
    assert!(!shown.contains("--verbose"), "{shown}");
    assert!(shown.contains("  1. Try it:"), "{shown}");
}

#[test]
fn an_agent_left_unprotected_is_counted_and_marked() {
    let mut broken = agent("gemini-cli", Level::NotProtected);
    broken.reason = Some("hook missing".to_owned());
    let agents = [agent("claude-code", Level::HookAndOsSandbox), broken];
    let steps = Steps::default();
    let done = Done {
        agents: &agents,
        steps: &steps,
        backups: 0,
        verbose: false,
    };
    let shown = rendered(&done);
    assert!(shown.contains("! 1 of 2 agents protected"), "{shown}");
    assert!(
        shown.contains("Gemini CLI   ✗ not protected (hook missing)"),
        "{shown}"
    );
}
