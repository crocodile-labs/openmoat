use super::*;

fn entry(path: &str, allows: bool, mask: u32) -> AclEntry {
    AclEntry {
        path: path.to_owned(),
        allows,
        mask,
        inherit: true,
    }
}

fn record() -> Record {
    Record {
        version: VERSION,
        account: "openmoat-dana".to_owned(),
        sid: "S-1-5-21-1-2-3-1005".to_owned(),
        person_sid: "S-1-5-21-1-2-3-1001".to_owned(),
        profile: "C:/Users/dana".to_owned(),
        rights: vec![INTERACTIVE_RIGHT.to_owned()],
        denied_rights: DENIED_RIGHTS.iter().map(|r| (*r).to_owned()).collect(),
        hidden: true,
        relay_registered: true,
        profile_entry: entry("C:/Users/dana", true, PROFILE_MASK),
        wfp: None,
        write_entries: Vec::new(),
        read_entries: Vec::new(),
    }
}

fn clean() -> Observed {
    Observed {
        sid: Some("S-1-5-21-1-2-3-1005".to_owned()),
        groups: Some(Vec::new()),
        rights: Some(
            std::iter::once(INTERACTIVE_RIGHT)
                .chain(DENIED_RIGHTS)
                .map(str::to_owned)
                .collect(),
        ),
        hidden: true,
        relay: Some("s-1-5-21-1-2-3-1001".to_owned()),
        profile_entry: true,
        password: true,
    }
}

#[test]
fn the_name_is_the_prefix_and_the_person_cut_to_twenty_characters() {
    assert_eq!(account_name("Dana"), "openmoat-dana");
    assert_eq!(account_name("Jordan Alexander"), "openmoat-jordanalexa");
    assert_eq!(account_name("a/b\\c:d*e"), "openmoat-abcde");
    assert_eq!(account_name("\"?*"), "openmoat-agent");
    for person in ["Éloïse", "x".repeat(40).as_str(), "日本語の名前です"] {
        let name = account_name(person);
        assert!(name.len() <= MAX_NAME, "{name}");
        assert!(name.starts_with(PREFIX), "{name}");
    }
}

#[test]
fn the_password_keeps_the_random_hex_and_adds_three_kinds() {
    let hex = "ab".repeat(32);
    let password = password(&hex);
    assert!(password.starts_with(&hex));
    assert!(password.chars().any(|c| c.is_ascii_uppercase()));
    assert!(password.chars().any(|c| c.is_ascii_punctuation()));
    assert_eq!(password.len(), 67);
}

/// The record round-trips, says `"wfp": null` while the network filters are
/// not built, and a record setup does not write is refused.
#[test]
fn the_record_round_trips_and_names_the_network_filters_absent() {
    let mut record = record();
    record.add_writes(&[entry("C:/src/app", true, 0x13_01BF)]);
    record.add_writes(&[entry("c:/SRC/app", true, 0x13_01BF)]);
    assert_eq!(record.write_entries.len(), 1);
    let json = record.to_json().unwrap();
    assert!(json.contains("\"wfp\": null"), "{json}");
    assert_eq!(Record::parse(&json).unwrap(), record);
    assert_eq!(record.entries().count(), 2);

    let other = json.replace("openmoat-dana", "dana");
    assert!(Record::parse(&other).is_err());
    let builtin = json.replace("S-1-5-21-1-2-3-1005", "S-1-5-32-544");
    assert!(Record::parse(&builtin).is_err());
    let newer = json.replace("\"version\": 1", "\"version\": 2");
    assert!(Record::parse(&newer).is_err());
}

#[test]
fn a_record_without_run_entries_reads_as_none_set() {
    let mut value = serde_json::to_value(record()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("write_entries");
    object.remove("read_entries");
    let parsed = Record::parse(&value.to_string()).unwrap();
    assert!(parsed.write_entries.is_empty() && parsed.read_entries.is_empty());
}

#[test]
fn a_system_that_matches_the_record_has_no_drift() {
    assert_eq!(drift(&record(), &clean()), Vec::<String>::new());
    assert_eq!(unread(&clean()), Vec::<&str>::new());
}

/// A standard user may not read the account's groups or rights: those are
/// named as unread, not judged, and the rest still is.
#[test]
fn what_cannot_be_read_is_named_not_judged() {
    let seen = Observed {
        groups: None,
        rights: None,
        ..clean()
    };
    assert_eq!(drift(&record(), &seen), Vec::<String>::new());
    assert_eq!(unread(&seen), ["its local groups", "its logon rights"]);
    let gone = Observed {
        password: false,
        ..seen
    };
    assert_eq!(drift(&record(), &gone).len(), 1);
}

#[test]
fn every_change_to_the_account_is_drift() {
    let record = record();
    let cases: Vec<(Observed, &str)> = vec![
        (
            Observed {
                sid: None,
                ..clean()
            },
            "is gone",
        ),
        (
            Observed {
                sid: Some("S-1-5-21-9-9-9-1005".to_owned()),
                ..clean()
            },
            "not the recorded",
        ),
        (
            Observed {
                groups: Some(vec!["Administrators".to_owned()]),
                ..clean()
            },
            "in local groups (Administrators)",
        ),
        (
            Observed {
                rights: Some(vec![INTERACTIVE_RIGHT.to_owned()]),
                ..clean()
            },
            "logon rights missing: SeDenyNetworkLogonRight",
        ),
        (
            Observed {
                rights: clean().rights.map(|r| {
                    r.into_iter()
                        .chain(["SeBatchLogonRight".to_owned()])
                        .collect()
                }),
                ..clean()
            },
            "did not give: SeBatchLogonRight",
        ),
        (
            Observed {
                hidden: false,
                ..clean()
            },
            "sign-in screen",
        ),
        (
            Observed {
                relay: Some("S-1-5-21-1-2-3-1002".to_owned()),
                ..clean()
            },
            "hook relay",
        ),
        (
            Observed {
                profile_entry: false,
                ..clean()
            },
            "read entry on C:/Users/dana",
        ),
        (
            Observed {
                password: false,
                ..clean()
            },
            "encrypted password",
        ),
    ];
    for (seen, says) in cases {
        let found = drift(&record, &seen);
        assert_eq!(found.len(), 1, "{seen:?}: {found:?}");
        assert!(found[0].contains(says), "{found:?} should say {says}");
    }
}

/// A run for another agent takes out the last run's denies it does not set
/// itself, whatever the case of the path.
#[test]
fn stale_read_denies_are_the_ones_this_run_does_not_set() {
    let ssh = entry("C:/Users/dana/.ssh", false, READ_DENY_MASK);
    let claude = entry("C:/Users/dana/.claude", false, READ_DENY_MASK);
    let codex = entry("C:/Users/dana/.codex", false, READ_DENY_MASK);
    let previous = [ssh.clone(), codex.clone()];
    let wanted = [entry("c:/users/dana/.SSH", false, READ_DENY_MASK), claude];
    assert_eq!(stale(&previous, &wanted), [codex]);
    assert_eq!(stale(&previous, &previous), Vec::<AclEntry>::new());
    assert_eq!(stale(&[], &wanted), Vec::<AclEntry>::new());
}

#[test]
fn a_command_line_windows_would_cut_is_refused() {
    assert!(command_line_fits(COMMAND_LINE_MAX).is_ok());
    let error = command_line_fits(COMMAND_LINE_MAX + 1)
        .unwrap_err()
        .to_string();
    assert!(error.contains("1024"), "{error}");
}
