use super::*;

const WHY: &str = "bubblewrap is not installed";

fn unavailable() -> Offered {
    Offered::Unavailable(WHY.to_owned())
}

#[test]
fn linux_isolates_by_default_where_bubblewrap_works() {
    let tier = choose(Asked::Default, &Offered::Available, None).unwrap();
    assert_eq!(tier, Tier::Isolated { asked: false });
    assert!(tier.isolated());
    assert_eq!(row(&tier), None, "the default writes no row");
    assert_eq!(notice(&tier), None);
    // A failure to build it names the way out, unless a policy forbids that way.
    assert!(
        failed_default(&tier, false)
            .unwrap()
            .contains("--no-isolate")
    );
    assert_eq!(failed_default(&tier, true), None);
}

#[test]
fn without_bubblewrap_the_default_warns_records_and_starts_the_lightweight_tier() {
    let tier = choose(Asked::Default, &unavailable(), None).unwrap();
    assert_eq!(
        tier,
        Tier::Lightweight(Lightweight::Unavailable(WHY.to_owned()))
    );
    assert!(!tier.isolated());
    let shown = notice(&tier).unwrap();
    for expected in [
        WHY,
        "Lightweight tier",
        "--no-isolate",
        "--isolate",
        "audit log",
    ] {
        assert!(shown.contains(expected), "{expected}: {shown}");
    }
    let (rule, reason) = row(&tier).unwrap();
    assert_eq!(rule, UNAVAILABLE_RULE);
    assert!(reason.contains(WHY), "{reason}");
}

#[test]
fn no_isolate_is_the_lightweight_tier_on_record() {
    for offered in [Offered::Available, unavailable()] {
        let tier = choose(Asked::NoIsolate, &offered, None).unwrap();
        assert_eq!(tier, Tier::Lightweight(Lightweight::OptedOut));
        assert_eq!(notice(&tier), None, "chosen on purpose: no warning");
        let (rule, reason) = row(&tier).unwrap();
        assert_eq!(rule, OPTED_OUT_RULE);
        assert!(reason.contains("--no-isolate"), "{reason}");
    }
}

#[test]
fn isolate_is_the_isolated_tier_or_the_platforms_refusal() {
    for offered in [Offered::Available, unavailable(), Offered::Not] {
        for strict in [None, Some("your policy")] {
            let tier = choose(Asked::Isolate, &offered, strict).unwrap();
            assert_eq!(tier, Tier::Isolated { asked: true });
            assert_eq!(failed_default(&tier, false), None);
        }
    }
}

/// The attack: a flag or a missing bubblewrap lowering what a policy requires.
#[test]
fn the_full_boundary_refuses_the_lightweight_tier_on_linux() {
    let refused = choose(Asked::NoIsolate, &Offered::Available, Some("your policy"));
    let shown = format!("{:#}", refused.unwrap_err());
    for expected in ["your policy", "require.run: full-boundary", "--no-isolate"] {
        assert!(shown.contains(expected), "{expected}: {shown}");
    }
    let refused = choose(
        Asked::Default,
        &unavailable(),
        Some("the repository policy"),
    );
    let shown = format!("{:#}", refused.unwrap_err());
    for expected in ["the repository policy", "Isolated tier", WHY] {
        assert!(shown.contains(expected), "{expected}: {shown}");
    }
    let refused = choose(Asked::NoIsolate, &unavailable(), Some("a pack"));
    assert!(refused.is_err());
    // Where it can isolate, the requirement changes nothing.
    let tier = choose(Asked::Default, &Offered::Available, Some("your policy")).unwrap();
    assert_eq!(tier, Tier::Isolated { asked: false });
}

#[test]
fn platforms_without_the_isolated_tier_keep_the_lightweight_tier_quietly() {
    for asked in [Asked::Default, Asked::NoIsolate] {
        for strict in [None, Some("your policy")] {
            let tier = choose(asked, &Offered::Not, strict).unwrap();
            assert_eq!(tier, Tier::Lightweight(Lightweight::Platform));
            assert_eq!(row(&tier), None);
            assert_eq!(notice(&tier), None);
        }
    }
}

#[test]
fn doctor_says_which_tier_applies() {
    assert_eq!(doctor_row(&Offered::Not, None), None);
    let (warn, text) = doctor_row(&Offered::Available, None).unwrap();
    assert!(!warn);
    assert!(
        text.starts_with("openmoat run     starts the Isolated tier"),
        "{text}"
    );
    let (warn, text) = doctor_row(&unavailable(), None).unwrap();
    assert!(warn);
    assert!(text.contains("warns and starts the Lightweight tier") && text.contains(WHY));
    let (warn, text) = doctor_row(&unavailable(), Some("your policy")).unwrap();
    assert!(warn);
    assert!(text.contains("refuses to start: your policy"), "{text}");
}

#[test]
fn the_rows_are_never_read_as_a_link() {
    // The run's taint reads a link row's tool as a host id (`taint/run.rs`).
    assert!(TOOL.parse::<openmoat_hosts::Host>().is_err());
}
