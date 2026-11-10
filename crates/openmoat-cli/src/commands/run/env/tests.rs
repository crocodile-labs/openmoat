use super::*;

const SECRET_NAME: &str = "AWS_SECRET_ACCESS_KEY";

fn names(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn policy(section: &str) -> Policy {
    Policy::parse(&format!("version: 1\n{section}")).unwrap()
}

fn allowed(host: Option<Host>, policy: &Policy, flags: &[&str]) -> Allowed {
    let flags: Vec<String> = flags.iter().map(ToString::to_string).collect();
    Allowed::new(&["PLATFORM_ONE"], host, policy, &flags)
}

fn nothing_set(_: &OsStr) -> bool {
    false
}

#[test]
fn a_cloud_credential_is_withheld_and_the_base_is_not() {
    let list = allowed(None, &policy(""), &[]);
    let withheld = withheld(
        names(&[SECRET_NAME, "PATH", "HOME", "LANG", "PLATFORM_ONE", "OTHER"]),
        &list,
        &nothing_set,
    );
    assert_eq!(withheld, names(&["AWS_SECRET_ACCESS_KEY", "OTHER"]));
}

#[test]
fn a_person_adds_names_in_the_policy_or_for_one_run() {
    let by_policy = policy("sandbox:\n  read_roots: []\n  env_allow: [MY_VAR]\n");
    let list = allowed(None, &by_policy, &["FLAG_VAR"]);
    let left = withheld(names(&["MY_VAR", "FLAG_VAR", "NOPE"]), &list, &nothing_set);
    assert_eq!(left, names(&["NOPE"]));
}

/// A name the host documents reaches it; the same name for another program
/// does not, and a host's facts never let a cloud credential through.
#[test]
fn a_hosts_own_names_reach_only_that_host() {
    let key = "ANTHROPIC_API_KEY";
    let claude = allowed(Some(Host::ClaudeCode), &policy(""), &[]);
    assert_eq!(withheld(names(&[key]), &claude, &nothing_set), names(&[]));
    let bare = allowed(None, &policy(""), &[]);
    assert_eq!(withheld(names(&[key]), &bare, &nothing_set), names(&[key]));
    assert_eq!(
        withheld(names(&[SECRET_NAME]), &claude, &nothing_set),
        names(&[SECRET_NAME])
    );
}

#[test]
fn the_config_directory_variable_comes_from_the_spec() {
    let claude = allowed(Some(Host::ClaudeCode), &policy(""), &[]);
    assert!(claude.holds(OsStr::new("CLAUDE_CONFIG_DIR")));
    assert!(host_names(Host::ClaudeCode).contains(&"CLAUDE_CONFIG_DIR"));
}

/// The run's own values stay; a brokered secret it removed is not reported
/// as something it withheld.
#[test]
fn what_the_run_sets_or_removes_is_not_reported() {
    let list = allowed(None, &policy(""), &[]);
    let set = |name: &OsStr| name == "HTTPS_PROXY" || name == "BROKERED";
    let left = withheld(names(&["HTTPS_PROXY", "BROKERED", "OTHER"]), &list, &set);
    assert_eq!(left, names(&["OTHER"]));
}

#[cfg(unix)]
#[test]
fn a_name_that_is_not_text_is_withheld() {
    use std::os::unix::ffi::OsStringExt as _;
    let odd = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
    let list = allowed(None, &policy(""), &[]);
    let left = withheld(vec![odd.clone()], &list, &nothing_set);
    assert_eq!(left, vec![odd]);
}

#[test]
fn only_whole_words_look_like_credentials() {
    for name in [
        SECRET_NAME,
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "MY_API_KEY",
        "DB_PASSWORD",
        "SSH_AUTH_SOCK",
        "AWS_PROFILE",
    ] {
        assert!(looks_like_credential(name), "{name}");
    }
    for name in [
        "KEYBOARD_LAYOUT",
        "MONKEY",
        "TOKENIZERS_PARALLELISM",
        "PATH",
        "PWD",
    ] {
        assert!(!looks_like_credential(name), "{name}");
    }
}

#[test]
fn the_warning_names_credentials_and_never_a_value() {
    let found = names(&[
        "AWS_SECRET_ACCESS_KEY",
        "BENIGN",
        "DB_PASSWORD",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
    ]);
    let line = notice(&found, false).unwrap();
    assert!(line.contains("4 inherited variables"), "{line}");
    assert!(line.contains("AWS_SECRET_ACCESS_KEY"), "{line}");
    assert!(line.contains("and 1 more"), "{line}");
    assert!(!line.contains("BENIGN"), "{line}");
    assert!(!line.contains('='), "{line}");
}

#[test]
fn nothing_that_looks_like_a_credential_means_no_warning() {
    assert_eq!(notice(&names(&["BENIGN", "OTHER"]), false), None);
    assert_eq!(notice(&names(&[]), false), None);
}

#[test]
fn under_the_requirement_the_run_says_how_many_and_how_to_pass_one_on() {
    let line = notice(&names(&["A", "B"]), true).unwrap();
    assert!(line.contains("2 inherited variables withheld"), "{line}");
    assert!(line.contains("--env NAME"), "{line}");
    assert_eq!(notice(&names(&[]), true), None);
}

#[test]
fn the_names_are_listed_when_asked_and_cleaned() {
    let line = list(&names(&["A\u{1b}[31m", "B"]), true).unwrap();
    assert!(line.contains("withheld (names only)"), "{line}");
    assert!(!line.contains('\u{1b}'), "{line}");
    assert_eq!(list(&names(&[]), true), None);
    assert!(
        list(&names(&["A"]), false)
            .unwrap()
            .contains("would be withheld")
    );
}

#[test]
fn doctor_names_what_is_withheld() {
    let line = doctor_line(&names(&[SECRET_NAME]), true);
    assert!(line.contains(SECRET_NAME), "{line}");
    assert!(line.contains("withholds"), "{line}");
    let off = doctor_line(&names(&[]), false);
    assert!(off.contains("nothing here"), "{off}");
    assert!(off.contains("would withhold"), "{off}");
}
