use std::ffi::OsString;
use std::path::PathBuf;

use openmoat_core::ProjectHookOff;
use openmoat_hosts::{Host, SessionOverride};

use super::{Off, Preflight, clashing, decide, notice};

/// A host with a session override, and its override.
fn with_override() -> (Host, &'static SessionOverride) {
    Host::ALL
        .into_iter()
        .find_map(|h| Some((h, h.spec().hook_off.session_override.as_ref()?)))
        .unwrap()
}

/// A host with none.
fn without_override() -> Host {
    Host::ALL
        .into_iter()
        .find(|h| {
            h.spec().hook_off.session_override.is_none() && h.spec().project_settings.is_some()
        })
        .unwrap()
}

fn off(overridden: bool) -> Off {
    Off {
        path: PathBuf::from("/p/settings.json"),
        what: vec!["`x` turns every hook off".to_owned()],
        overridden,
    }
}

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn message(found: &Preflight) -> String {
    match found {
        Preflight::Refused { message, .. } => message.clone(),
        other => panic!("not refused: {other:?}"),
    }
}

#[test]
fn nothing_found_is_clear_for_a_host_without_an_override() {
    let host = without_override();
    let found = decide(host, &[], None, &[], ProjectHookOff::Refuse);
    assert_eq!(found, Preflight::Clear);
    assert_eq!(notice(Some(host), &found), None);
}

#[test]
fn a_file_that_turns_the_hook_off_is_refused_with_the_way_out() {
    let host = without_override();
    let shown = message(&decide(
        host,
        &[off(false)],
        None,
        &[],
        ProjectHookOff::Refuse,
    ));
    assert!(shown.contains("does not start"), "{shown}");
    assert!(
        shown.contains("/p/settings.json: `x` turns every hook off"),
        "{shown}"
    );
    assert!(shown.contains("sandbox.project_hook_off: start"), "{shown}");
}

/// Only the person's own policy starts the agent anyway, and says so.
#[test]
fn the_persons_policy_starts_it_anyway_and_says_so() {
    let host = without_override();
    let found = decide(host, &[off(false)], None, &[], ProjectHookOff::Start);
    assert!(matches!(found, Preflight::Started { .. }), "{found:?}");
    let said = notice(Some(host), &found).unwrap();
    assert!(said.contains("without OpenMoat's hook"), "{said}");
}

/// The host's own option goes on every run, whatever the project holds
/// now: the host may reload the project's files mid-session.
#[test]
fn the_hosts_own_option_goes_on_every_run() {
    let (host, over) = with_override();
    for files in [vec![], vec![off(true)]] {
        let found = decide(host, &files, Some(over), &[], ProjectHookOff::Refuse);
        let Preflight::Override { args, .. } = &found else {
            panic!("{found:?}");
        };
        assert_eq!(*args, over.args);
        assert!(notice(Some(host), &found).is_some());
    }
    // A file it does not cover is refused.
    let refused = decide(
        host,
        &[off(true), off(false)],
        Some(over),
        &[],
        ProjectHookOff::Refuse,
    );
    assert!(matches!(refused, Preflight::Refused { .. }), "{refused:?}");
}

/// The person's own option of the same name would replace the override's,
/// so it is not added; over a file that turns the hook off the run is
/// refused, and without one it starts as the person asked.
#[test]
fn a_persons_own_clashing_option_is_never_overridden() {
    let (host, over) = with_override();
    let clash = over.clashes[0];
    for given in [
        args(&[clash, "{}"]),
        args(&[&format!("{clash}=x.json"), "-p", "hi"]),
    ] {
        let shown = message(&decide(
            host,
            &[off(true)],
            Some(over),
            &given,
            ProjectHookOff::Refuse,
        ));
        assert!(shown.contains(&format!("your own `{clash}`")), "{shown}");
        let clear = decide(host, &[], Some(over), &given, ProjectHookOff::Refuse);
        assert_eq!(clear, Preflight::Clear);
    }
    let started = decide(
        host,
        &[off(true)],
        Some(over),
        &args(&[clash, "{}"]),
        ProjectHookOff::Start,
    );
    assert!(matches!(started, Preflight::Started { .. }), "{started:?}");
}

/// A prompt that mentions the option, or the option after `--`, is not
/// the person's option.
#[test]
fn only_option_words_before_a_double_dash_clash() {
    let (_, over) = with_override();
    let clash = over.clashes[0];
    assert_eq!(
        clashing(over, &args(&[&format!("explain {clash} please")])),
        None
    );
    assert_eq!(clashing(over, &args(&["-p", "--", clash, "{}"])), None);
    assert_eq!(
        clashing(over, &args(&["-p", clash, "{}"])),
        Some(clash.to_owned())
    );
}
