use std::ffi::OsStr;
use std::path::Path;

use super::*;

const ME: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
const OTHER: &str = "S-1-5-21-9-9-9-1002";

fn os(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn the_sid_is_the_last_field_of_whoami() {
    let line = format!("\"desktop-1\\me\",\"{ME}\"\r\n");
    assert_eq!(parse_sid(&line).as_deref(), Some(ME));
    assert_eq!(
        parse_sid("\n\"pc\\me\",\"S-1-5-18\"\n").as_deref(),
        Some(SYSTEM)
    );
    assert_eq!(parse_sid("\"pc\\me\",\"not a sid\""), None);
    assert_eq!(parse_sid("\"pc\\me\",\"S-1-\""), None);
    assert_eq!(parse_sid(""), None);
}

#[test]
fn the_read_prints_the_account_then_the_list() {
    let printed = format!("{ME}\r\nO:{ME}D:PAI(A;OICI;FA;;;SY)\r\n");
    let (me, sddl) = parse_read(&printed).unwrap();
    assert_eq!(me, ME);
    assert!(sddl.starts_with("O:"), "{sddl}");
    assert_eq!(parse_read("oops\r\nO:BAD:P"), None);
    assert_eq!(parse_read(&format!("{ME}\r\n")), None);
}

#[test]
fn init_sets_two_entries_and_takes_the_others_out() {
    let dir = OsStr::new(r"C:\Users\me\.moat");
    assert_eq!(
        os(&grant_args(dir, ME)),
        [
            r"C:\Users\me\.moat",
            "/inheritance:r",
            "/grant:r",
            &format!("*{ME}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
            "/q",
        ]
    );
    assert_eq!(
        os(&remove_args(dir, "S-1-1-0", false)),
        [r"C:\Users\me\.moat", "/remove", "*S-1-1-0", "/q"]
    );
    assert_eq!(os(&remove_args(dir, ME, true))[1], "/remove:d");
}

#[test]
fn the_plan_removes_every_other_account_and_own_denies() {
    let sddl = format!(
        "O:{ME}D:AI(A;OICI;0x1301bf;;;WD)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{ME})\
         (D;;FA;;;{ME})(A;OICIIO;FA;;;CO)(A;;FR;;;{OTHER})(A;;FR;;;WD)"
    );
    let plan = plan(&sddl, ME).unwrap();
    assert_eq!(plan.remove, ["S-1-1-0", "S-1-3-0", OTHER], "{plan:?}");
    assert_eq!(plan.remove_denies, [ME]);
    // inherited entries go with `/inheritance:r`
    assert_eq!(
        super::plan("D:AI(A;OICIID;FA;;;WD)", ME),
        Ok(Plan::default())
    );
    // an alias no SID is known for cannot be named to icacls
    assert_eq!(plan_err("D:P(A;;FA;;;DA)"), "DA");
}

fn plan_err(sddl: &str) -> String {
    plan(sddl, ME).unwrap_err()
}

#[test]
fn the_fix_is_every_icacls_call_with_quoted_words() {
    let plan = Plan {
        remove: vec!["S-1-1-0".to_owned()],
        remove_denies: vec![],
    };
    let icacls = Path::new(r"D:\Windows\System32\icacls.exe");
    let fix = fix_commands(icacls, Path::new(r"C:\Users\Jo Doe\.moat"), ME, &plan);
    assert_eq!(fix.len(), 2, "{fix:?}");
    assert!(
        fix[0].starts_with(
            r#"D:\Windows\System32\icacls.exe "C:\Users\Jo Doe\.moat" /inheritance:r"#
        ),
        "{}",
        fix[0]
    );
    assert!(
        fix[0].contains(&format!("\"*{ME}:(OI)(CI)F\"")),
        "{}",
        fix[0]
    );
    assert!(fix[1].ends_with("/remove *S-1-1-0 /q"), "{}", fix[1]);
}

#[test]
fn the_list_init_sets_has_no_other_account() {
    let sddl = format!("O:{ME}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{ME})");
    assert_eq!(
        judge(&sddl, ME),
        Judged {
            protected: true,
            ..Judged::default()
        }
    );
    assert_eq!(plan(&sddl, ME), Ok(Plan::default()));
}

#[test]
fn another_owner_is_named() {
    let sddl = format!("O:{OTHER}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{ME})");
    assert_eq!(judge(&sddl, ME).foreign_owner.as_deref(), Some(OTHER));
    for trusted in ["BA", "SY", ME] {
        let sddl = format!("O:{trusted}D:PAI(A;OICI;FA;;;{ME})");
        assert_eq!(judge(&sddl, ME).foreign_owner, None, "{trusted}");
    }
    let unread = judge(&format!("D:PAI(A;OICI;FA;;;{ME})"), ME);
    assert!(unread.foreign_owner.is_some());
}

#[test]
fn a_profile_folder_inherits_and_lets_administrators_in() {
    let sddl = format!("O:{ME}D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{ME})");
    let judged = judge(&sddl, ME);
    assert!(!judged.protected);
    assert_eq!(judged.writers, ["Administrators"]);
    assert!(verify(&sddl, ME).is_err());
}

#[test]
fn other_accounts_that_may_change_or_read_it_are_named() {
    // a second drive's root: Authenticated Users may modify, Users read
    let sddl = format!(
        "O:{ME}D:AI(A;OICIID;FA;;;SY)(A;OICIID;0x1301bf;;;AU)(A;OICIID;0x1200a9;;;BU)\
         (A;OICIID;FA;;;{ME})(A;OICIID;GRGW;;;{OTHER})(A;;FR;;;WD)"
    );
    let judged = judge(&sddl, ME);
    assert_eq!(judged.writers, ["Authenticated Users", OTHER]);
    assert_eq!(judged.readers, ["Users", "Everyone"]);
}

#[test]
fn an_entry_for_what_is_created_inside_counts_and_denies_do_not() {
    // what Everyone may do to files created inside: the state files
    let judged = judge(
        &format!("O:{ME}D:P(A;OICI;FA;;;{ME})(A;OICIIO;GA;;;WD)"),
        ME,
    );
    assert_eq!(judged.writers, ["Everyone"]);
    let sddl = format!("O:{ME}D:P(A;OICI;FA;;;{ME})(D;;FA;;;WD)(A;OICIIO;FA;;;CO)");
    let judged = judge(&sddl, ME);
    assert!(
        judged.writers.is_empty() && judged.readers.is_empty(),
        "{judged:?}"
    );
}

#[test]
fn rights_not_read_here_count_as_every_right() {
    let judged = judge(&format!("O:{ME}D:P(A;;ZZ;;;{OTHER})(A;;0xnope;;;BU)"), ME);
    assert_eq!(judged.writers, [OTHER, "Users"]);
    for none in [format!("O:{ME}"), format!("O:{ME}D:NO_ACCESS_CONTROL")] {
        assert_eq!(judge(&none, ME).writers.len(), 1, "{none}");
    }
}

/// The built-in Administrator's and Guest's SIDs end in 500 and 501; SDDL
/// writes them `LA` and `LG`.
const ADMIN: &str = "S-1-5-21-1004336348-1177238915-682003330-500";
const GUEST: &str = "S-1-5-21-1004336348-1177238915-682003330-501";

#[test]
fn the_windows_runner_list_after_the_grant_needs_only_administrators_removed() {
    // what windows-latest, as the built-in Administrator, showed after
    // `/inheritance:r /grant:r`
    let sddl = "O:LAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)";
    let judged = judge(sddl, ADMIN);
    assert_eq!(judged.foreign_owner, None);
    assert_eq!(judged.writers, ["Administrators"]);
    assert_eq!(
        plan(sddl, ADMIN),
        Ok(Plan {
            remove: vec!["S-1-5-32-544".to_owned()],
            remove_denies: vec![],
        })
    );
    let err = verify(sddl, ADMIN).unwrap_err();
    assert!(err.contains("S-1-5-32-544"), "{err}");
    // after the removal
    assert_eq!(
        verify("O:LAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)", ADMIN),
        Ok(())
    );
}

#[test]
fn machine_relative_aliases_are_the_person_only_by_their_rid() {
    // the person is the built-in Guest
    let sddl = "O:LGD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LG)";
    assert_eq!(verify(sddl, GUEST), Ok(()));
    // for another account, LA is the built-in Administrator beside it
    let sddl = format!("O:LAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{ME})(A;OICI;FA;;;LA)");
    let judged = judge(&sddl, ME);
    assert_eq!(
        judged.foreign_owner.as_deref(),
        Some("the built-in Administrator")
    );
    assert_eq!(judged.writers, ["the built-in Administrator"]);
    assert_eq!(plan(&sddl, ME).unwrap().remove, [ADMIN]);
    // the same in full form, as the Windows read prints it
    let full = format!("O:{ADMIN}D:P(A;OICI;0x1f01ff;;;{SYSTEM})(A;OICI;0x1f01ff;;;{ME})");
    assert_eq!(judge(&full, ME).foreign_owner.as_deref(), Some(ADMIN));
    assert_eq!(
        verify(
            &format!("O:{ME}D:P(A;OICI;0x1f01ff;;;{SYSTEM})(A;OICI;0x1f01ff;;;{ME})"),
            ME
        ),
        Ok(())
    );
    // a domain account's `LA` is the RID 500 beside it: if that is not the
    // machine's, the removal leaves the entry and `protect`'s check refuses
    assert_eq!(
        plan("D:P(A;;FA;;;LA)", "S-1-5-21-9-9-9-1104")
            .unwrap()
            .remove,
        ["S-1-5-21-9-9-9-500"]
    );
    // with no SID beside it to name (an Entra ID account), it is the error
    assert_eq!(
        plan("D:P(A;;FA;;;LA)", "S-1-12-1-2-3"),
        Err("LA".to_owned())
    );
    assert_eq!(
        judge("D:P(A;;FA;;;LA)", "S-1-12-1-2-3").writers,
        ["the built-in Administrator"]
    );
}

#[test]
fn verify_names_what_stayed() {
    let sddl = format!("O:{OTHER}D:AI(A;OICI;FA;;;{ME})(A;;FR;;;WD)(D;;FA;;;{ME})");
    let err = verify(&sddl, ME).unwrap_err();
    for part in [
        "the owner",
        "inherited",
        "Everyone, who may read it",
        "a deny entry",
    ] {
        assert!(err.contains(part), "{part}: {err}");
    }
}
