use std::ffi::OsString;
use std::path::PathBuf;

use openmoat_core::ProjectHookOff;
use openmoat_hosts::{Host, SessionOverride};

use super::{Off, Preflight, decide, notice};

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

#[test]
fn nothing_found_is_clear() {
    let host = without_override();
    let found = decide(host, &[], None, &[], ProjectHookOff::Refuse).unwrap();
    assert_eq!(found, Preflight::Clear);
    assert_eq!(notice(Some(host), &found), None);
}

#[test]
fn a_file_that_turns_the_hook_off_is_refused_with_the_way_out() {
    let host = without_override();
    let refused = decide(host, &[off(false)], None, &[], ProjectHookOff::Refuse).unwrap_err();
    let shown = format!("{refused:#}");
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
    let found = decide(host, &[off(false)], None, &[], ProjectHookOff::Start).unwrap();
    assert!(matches!(found, Preflight::Started { .. }), "{found:?}");
    let said = notice(Some(host), &found).unwrap();
    assert!(said.contains("without OpenMoat's hook"), "{said}");
}

#[test]
fn the_hosts_own_option_keeps_the_hook_on_where_it_covers_every_file() {
    let (host, over) = with_override();
    let found = decide(host, &[off(true)], Some(over), &[], ProjectHookOff::Refuse).unwrap();
    assert_eq!(
        found,
        Preflight::Override {
            args: over.args,
            files: vec![PathBuf::from("/p/settings.json")]
        }
    );
    // A file it does not cover is refused.
    let refused = decide(
        host,
        &[off(true), off(false)],
        Some(over),
        &[],
        ProjectHookOff::Refuse,
    );
    assert!(refused.is_err());
}

/// The person's own option of the same name would replace the override's,
/// so it is not added and the run is refused.
#[test]
fn a_persons_own_clashing_option_is_never_overridden() {
    let (host, over) = with_override();
    let clash = over.clashes[0];
    for given in [
        args(&[clash, "{}"]),
        args(&[&format!("{clash}=x.json"), "-p", "hi"]),
    ] {
        let refused = decide(
            host,
            &[off(true)],
            Some(over),
            &given,
            ProjectHookOff::Refuse,
        )
        .unwrap_err();
        let shown = format!("{refused:#}");
        assert!(shown.contains(&format!("your own `{clash}`")), "{shown}");
    }
    let started = decide(
        host,
        &[off(true)],
        Some(over),
        &args(&[clash, "{}"]),
        ProjectHookOff::Start,
    )
    .unwrap();
    assert!(matches!(started, Preflight::Started { .. }), "{started:?}");
}
