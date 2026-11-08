use std::path::Path;

use openmoat_core::{Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, Policy, Verdict};

use super::super::{Entry, Overlay};
use super::*;

/// 2026-10-03 00:00:00 UTC; tests pass time in, they never read the clock.
const NOW: i64 = 1_790_985_600_000;
const HOUR: i64 = 3_600_000;

fn path() -> &'static Path {
    Path::new("approved.yaml")
}

fn window(from: &str, until: &str) -> Window {
    Window {
        from: from.to_owned(),
        until: until.to_owned(),
    }
}

#[test]
fn a_window_holds_from_its_start_until_its_end() {
    let w = Window::starting(NOW, 2 * HOUR);
    assert_eq!(w.from, "2026-10-03T00:00:00Z");
    assert_eq!(w.until, "2026-10-03T02:00:00Z");
    assert!(w.holds(NOW) && w.holds(NOW + 2 * HOUR - 1));
    assert_eq!(
        w.state(NOW + 2 * HOUR),
        State::Ended {
            until_ms: NOW + 2 * HOUR
        }
    );
    // A clock set back before the grant was made does not stretch it.
    assert_eq!(w.state(NOW - 1), State::Early);
    assert!(!w.holds(NOW - 365 * 24 * HOUR));
}

#[test]
fn a_window_lasts_at_least_as_long_as_asked() {
    // The start rounds down to the second and the end up.
    let w = Window::starting(NOW + 999, 1000);
    assert_eq!(w.from, "2026-10-03T00:00:00Z");
    assert_eq!(w.until, "2026-10-03T00:00:02Z");
    assert!(w.holds(NOW + 999 + 999));
    let exact = Window::starting(NOW, 1000);
    assert_eq!(exact.until, "2026-10-03T00:00:01Z");
}

#[test]
fn an_unreadable_window_never_holds() {
    for w in [
        window("", ""),
        window("2026-10-03T00:00:00Z", ""),
        window("", "2026-10-04T00:00:00Z"),
        window("2026-10-03T00:00:00Z", "tomorrow"),
        window("2026-10-03T00:00:00Z", "2026-10-04"),
        window("2026-10-03T00:00:00Z", "2026-10-04T00:00:00+00:00"),
        // ends before it starts
        window("2026-10-04T00:00:00Z", "2026-10-03T00:00:00Z"),
        window("2026-10-03T00:00:00Z", "2026-10-03T00:00:00Z"),
    ] {
        assert_eq!(w.state(NOW + HOUR), State::Unreadable, "{w:?}");
        assert!(!w.holds(NOW + HOUR), "{w:?}");
    }
}

#[test]
fn for_takes_spans_up_to_a_year() {
    assert_eq!(parse_for("2h").unwrap(), 2 * HOUR);
    assert_eq!(parse_for("366d").unwrap(), MAX_SPAN_MS);
    for bad in ["0h", "367d", "53w", "forever", "", "2", "-1d"] {
        let error = parse_for(bad).unwrap_err().to_string();
        assert!(error.contains("leave out --for"), "{bad}: {error}");
    }
}

/// An overlay with a site `docs.rs` (approved-1) ending at `until`, a site
/// with no end (approved-2) and a directory (approved-3) ending an hour after
/// [`NOW`].
fn overlay(until: &str) -> Overlay {
    let mut o = Overlay::default();
    o.allow_site("docs.rs").unwrap();
    o.set_window("approved-1", Some(window("2026-10-02T00:00:00Z", until)));
    o.allow_site("crates.io").unwrap();
    o.allow_dir(&["/w/a".to_owned()]);
    o.set_window("approved-3", Some(Window::starting(NOW, HOUR)));
    o
}

#[test]
fn an_ended_or_unreadable_grant_is_left_out_of_the_policy() {
    let o = overlay("2026-10-02T12:00:00Z");
    let ids = |o: &Overlay| o.ids().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(
        ids(&o.clone().in_force(NOW)),
        ["approved-2", "approved-3"],
        "the ended site is left out; the one without an end and the directory stay"
    );
    assert_eq!(ids(&o.clone().in_force(NOW + HOUR)), ["approved-2"]);
    assert_eq!(
        ids(&o.clone().in_force(NOW - 2 * 24 * HOUR)),
        ["approved-2"],
        "before they were granted, neither holds"
    );
    let unreadable = overlay("next week");
    assert_eq!(ids(&unreadable.in_force(NOW)), ["approved-2", "approved-3"]);

    let site = Action::Net {
        url: "https://docs.rs/serde".to_owned(),
    };
    let merged = |o: Overlay| {
        let mut policy = Policy::parse(DEFAULT_POLICY).unwrap();
        policy.allow.extend(o.in_force(NOW).allow);
        let ctx = EvalContext {
            home: "/h".to_owned(),
            project: Some("/p".to_owned()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".to_owned(),
            case_insensitive_paths: false,
        };
        CompiledPolicy::compile(&policy, &ctx)
            .unwrap()
            .decide(&site)
            .verdict
    };
    assert_eq!(merged(overlay("2026-10-03T01:00:00Z")), Verdict::Allow);
    assert_eq!(
        merged(overlay("2026-10-02T12:00:00Z")),
        Verdict::Deny,
        "back to the policy's own decision"
    );
}

#[test]
fn a_hand_broken_window_reads_as_ended_not_as_an_error() {
    let text = "version: 2\nallow:\n  - id: approved-1\n    net: [docs.rs]\n  - id: approved-2\n    \
                net: [crates.io]\n  - id: approved-3\n    net: [pypi.org]\nexpires:\n  approved-1: \
                tomorrow\n  approved-2: {until: 2026-10-04T00:00:00Z}\n  approved-3: {from: 1, \
                until: [2]}\n";
    let o = Overlay::parse(text, path()).unwrap();
    assert_eq!(o.expires.len(), 3);
    assert!(o.ids().all(|id| !o.holds(id, NOW)), "{o:?}");
    assert_eq!(o.in_force(NOW).ids().count(), 0);
}

#[test]
fn granting_again_replaces_the_end_and_never_extends_it() {
    let mut o = Overlay::default();
    let id = o.allow_site("docs.rs").unwrap().id.clone();
    o.set_window(&id, Some(Window::starting(NOW, 24 * HOUR)));
    // The same site again, for an hour: the same entry, with the shorter end.
    let again = o.allow_site("Docs.rs").unwrap().id.clone();
    assert_eq!(again, id);
    o.set_window(&again, Some(Window::starting(NOW, HOUR)));
    assert_eq!(o.allow.len(), 1, "one rule, not a second one still holding");
    assert!(!o.clone().in_force(NOW + 2 * HOUR).ids().any(|i| i == id));
    // Again without --for: no end, as asked.
    o.allow_site("docs.rs").unwrap();
    o.set_window(&id, None);
    assert!(o.expires.is_empty() && o.holds(&id, NOW + 1000 * HOUR));

    // The same for a directory and a command; a different one is a new entry.
    let dir = o.allow_dir(&["/w/a".to_owned()]).id.clone();
    assert_eq!(o.allow_dir(&["/w/a".to_owned()]).id, dir);
    assert_ne!(o.allow_dir(&["/w/b".to_owned()]).id, dir);
    let cmd = o.allow_command("make test").unwrap().id.clone();
    assert_eq!(o.allow_command("make test").unwrap().id, cmd);
    assert_ne!(o.allow_command("make lint").unwrap().id, cmd);
    assert_eq!(o.ids().count(), 5);
}

#[test]
fn the_file_is_version_2_only_while_an_entry_ends() {
    let mut o = overlay("2026-10-03T01:00:00Z");
    let text = o.text().unwrap();
    assert!(text.contains("version: 2"), "{text}");
    assert_eq!(Overlay::parse(&text, path()).unwrap().expires, o.expires);
    // An older release refuses version 2, failing closed, rather than reading
    // every entry as lasting until removed.
    o.set_window("approved-1", None);
    o.set_window("approved-3", None);
    let text = o.text().unwrap();
    assert!(
        text.contains("version: 1") && !text.contains("expires"),
        "{text}"
    );
    let newer = "version: 3\n";
    let error = Overlay::parse(newer, path()).unwrap_err().to_string();
    assert!(error.contains("version 3"), "{error}");
}

#[test]
fn remove_and_prune_take_the_windows_with_them() {
    let mut o = overlay("2026-10-02T12:00:00Z");
    o.expires
        .insert("approved-9".to_owned(), Window::starting(NOW, HOUR));
    let removed = o.prune(NOW);
    assert!(
        matches!(removed.as_slice(), [Entry::Rule(r)] if r.id == "approved-1"),
        "{removed:?}"
    );
    assert_eq!(
        o.expires.keys().collect::<Vec<_>>(),
        ["approved-3"],
        "the window naming no entry goes too"
    );
    assert_eq!(o.prune(NOW).len(), 0);
    o.remove("approved-3");
    assert!(o.expires.is_empty());
    // A window left behind by a hand edit never lands on a new entry.
    o.expires
        .insert("approved-7".to_owned(), Window::starting(NOW, HOUR));
    assert_eq!(o.allow_site("pypi.org").unwrap().id, "approved-8");
}

#[test]
fn the_summary_names_ended_and_soon_ending_grants() {
    assert_eq!(summary(&Overlay::default(), NOW), None);
    let o = overlay("2026-10-02T12:00:00Z");
    let text = summary(&o, NOW).unwrap();
    assert!(
        text.contains("1 standing grant(s) expired")
            && text.contains("approved-1")
            && text.contains("allow --prune")
            && text.contains("ending soon: approved-3 in 1h"),
        "{text}"
    );
    let far = overlay("2027-10-02T12:00:00Z");
    let text = summary(&far, NOW).unwrap();
    assert!(
        !text.contains("expired") && text.contains("approved-3"),
        "{text}"
    );
}
