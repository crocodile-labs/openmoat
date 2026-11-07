use openmoat_audit::{Event, NewEvent, Store};
use openmoat_core::{Action, Decision, Policy, Verdict};

use super::row::{self, NARROW, View};
use super::{Filter, earlier};
use crate::cli::{Only, WatchArgs};
use crate::report::{Paths, Style};

const POLICY: &str = "version: 1\n\
    deny:\n  - id: secrets-paths\n    title: reading your keys\n    fs.read: ['~/.ssh/**']\n\
    review:\n  - id: git-push\n    title: pushing to a remote\n    shell: ['git push']\n";

/// A fixture log: an allow, a review, a deny, a defer and an untitled deny,
/// across two agents and sessions, recorded at 10:42:01 and on.
fn log() -> Store {
    let store = Store::open_in_memory().unwrap();
    let shell = |command: &str| Action::Shell {
        command: command.into(),
    };
    let calls: [(&str, &str, &str, Action, Verdict, &str, &str); 5] = [
        (
            "claude-code",
            "s1",
            "Bash",
            shell("cargo test -p openmoat-core"),
            Verdict::Allow,
            "dev-shell",
            "ok",
        ),
        (
            "claude-code",
            "s1",
            "Bash",
            shell("git push origin main"),
            Verdict::Review,
            "git-push",
            "push",
        ),
        (
            "claude-code",
            "s1",
            "Read",
            Action::FsRead {
                path: "/Users/u/.ssh/id_ed25519".into(),
            },
            Verdict::Deny,
            "secrets-paths",
            "secret material",
        ),
        (
            "codex",
            "k1",
            "Bash",
            shell("make deploy"),
            Verdict::Defer,
            "default",
            "no rule matched",
        ),
        (
            "codex",
            "k1",
            "Bash",
            shell("env"),
            Verdict::Deny,
            "env-dump",
            "prints every environment variable",
        ),
    ];
    for (n, (host, session, tool, action, verdict, rule, reason)) in calls.into_iter().enumerate() {
        let decision = Decision::single(verdict, rule, reason);
        let event = NewEvent {
            host,
            session_id: session,
            call_id: None,
            cwd: Some("/p"),
            tool,
            action: Some(&action),
            decision: &decision,
            latency_us: 1,
        };
        let at = 10 * 3_600_000 + 42 * 60_000 + 1_000 + i64::try_from(n).unwrap() * 6_000;
        store.record_at(&event, at).unwrap();
    }
    store
}

fn events() -> Vec<Event> {
    log().after(None, 100).unwrap()
}

fn view(policy: Option<&Policy>, width: Option<usize>, colour: bool) -> View<'_> {
    View {
        style: Style::new(colour, None),
        width,
        paths: Paths::under(Some(std::path::Path::new("/Users/u"))),
        policy,
    }
}

fn shown(policy: Option<&Policy>, width: Option<usize>) -> Vec<String> {
    let view = view(policy, width, false);
    events().iter().flat_map(|e| row::rows(e, &view)).collect()
}

/// Piped (no terminal): one line per call with the verdict after it, and a
/// second line under each deny and review saying what was stopped.
#[test]
fn piped_rows_are_plain_whole_lines() {
    let policy = Policy::parse(POLICY).unwrap();
    assert_eq!(
        shown(Some(&policy), None),
        [
            "10:42:01  claude-code  ✓ Bash   cargo test -p openmoat-core  allow · dev-shell",
            "10:42:07  claude-code  ? Bash   git push origin main  review · git-push",
            "                         ↳ pushing to a remote · approve: openmoat allow --last",
            "10:42:13  claude-code  ✕ Read   ~/.ssh/id_ed25519  deny · secrets-paths",
            "                         ↳ reading your keys",
            "10:42:19  codex        → Bash   make deploy  defer · agent asks",
            "10:42:25  codex        ✕ Bash   env  deny · env-dump",
            "                         ↳ prints every environment variable",
        ]
    );
}

/// On a terminal the verdict column is right-aligned to the width; a narrow
/// terminal drops it, and no line is wider than the terminal.
#[test]
fn terminal_rows_fit_the_width() {
    for width in [100, 120] {
        for line in shown(None, Some(width)) {
            assert!(line.chars().count() <= width, "{width}: {line}");
        }
        let first = &shown(None, Some(width))[0];
        assert_eq!(first.chars().count(), width, "{first}");
        assert!(first.ends_with("allow · dev-shell"), "{first}");
    }
    let narrow = shown(None, Some(NARROW - 1));
    assert!(
        narrow.iter().all(|l| !l.contains(" · dev-shell")),
        "{narrow:?}"
    );
    assert!(narrow[0].contains("✓ Bash   cargo test"), "{narrow:?}");
}

/// Colour only with a style that colours; the same text either way.
#[test]
fn colour_is_only_on_a_terminal_style() {
    let events = events();
    let plain = view(None, None, false);
    let colour = view(None, None, true);
    for event in &events {
        let lines = row::rows(event, &plain);
        assert!(lines.iter().all(|l| !l.contains('\x1b')), "{lines:?}");
        let tinted = row::rows(event, &colour).join("\n");
        assert!(tinted.contains("\x1b["), "{tinted}");
    }
    let deny = row::rows(&events[2], &colour).join("\n");
    assert!(deny.contains("\x1b[31m✕\x1b[0m"), "{deny}");
}

fn args(
    only: Option<Only>,
    host: Option<openmoat_hosts::Host>,
    session: Option<&str>,
) -> WatchArgs {
    WatchArgs {
        host,
        only,
        session: session.map(str::to_owned),
        recent: 10,
        no_follow: true,
    }
}

#[test]
fn filters_keep_one_verdict_host_or_session() {
    let events = events();
    let kept = |a: &WatchArgs| {
        let filter = Filter::of(a);
        events.iter().filter(|e| filter.keeps(e)).count()
    };
    assert_eq!(kept(&args(None, None, None)), 5);
    assert_eq!(kept(&args(Some(Only::Deny), None, None)), 2);
    assert_eq!(kept(&args(Some(Only::Review), None, None)), 1);
    assert_eq!(
        kept(&args(None, Some(openmoat_hosts::Host::Codex), None)),
        2
    );
    assert_eq!(kept(&args(None, None, Some("s1"))), 3);
}

/// The earlier calls shown first are the newest the filter keeps, oldest first.
#[test]
fn earlier_calls_are_the_newest_kept_in_order() {
    let store = log();
    let filter = Filter::of(&args(Some(Only::Deny), None, None));
    let shown: Vec<String> = earlier(&store, &filter, 10)
        .unwrap()
        .into_iter()
        .map(|e| e.rules[0].clone())
        .collect();
    assert_eq!(shown, ["secrets-paths", "env-dump"]);
    let all = Filter::of(&args(None, None, None));
    let last_two = earlier(&store, &all, 2).unwrap();
    assert_eq!(last_two[0].rules, ["default"]);
    assert_eq!(earlier(&store, &all, 0).unwrap(), Vec::<Event>::new());
}
