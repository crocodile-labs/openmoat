//! The possession gate (ADR-117): once a secret is enrolled, every command
//! that widens or re-pins asks for a code after the terminal check; commands
//! that only narrow do not; without enrolment nothing changes, and each
//! loosening is a row of the `policy-changes` session either way.
//!
//! The tests type the code on stdin (`MOAT_ASSUME_TTY=1`) and fix the clock
//! with `MOAT_GATE_NOW`, both read by debug builds only, over RFC 6238's SHA-1
//! secret: at 59 seconds its code is 287082, at 89 seconds (the next step but
//! one) 359152, RFC 4226's values for counters 1 and 3.

use std::process::Output;

use crate::common::{OK, Sandbox, USAGE, output, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

/// RFC 6238 Appendix B's SHA-1 secret, base32.
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const AT_59: &str = "287082";
const AT_89: &str = "359152";

/// An installed sandbox with the RFC secret enrolled as `gate setup` writes it.
fn enrolled() -> Sandbox {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let path = sb.home.join(".moat/audit.key.gate");
    std::fs::write(&path, format!("openmoat-gate-totp-v1\n{RFC_SECRET}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    sb
}

/// `args` as a person at `now` seconds, typing `input`.
fn at(sb: &Sandbox, now: u64, args: &[&str], input: Option<&str>) -> Output {
    output(
        sb.command()
            .args(args)
            .env("MOAT_ASSUME_TTY", "1")
            .env("MOAT_GATE_NOW", now.to_string()),
        input,
    )
}

/// The ledger's rows as JSON: the table `show` prints has no reasons.
fn ledger(sb: &Sandbox) -> String {
    text(&sb.moat(&["show", "--session", "policy-changes", "--format", "json"]))
}

#[test]
fn without_enrolment_a_loosening_runs_as_before_and_is_recorded() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let out = sb.moat_as_person(&["allow", "--site", "docs.rs"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!text(&out).contains("authenticator"), "{}", text(&out));
    let rows = ledger(&sb);
    assert!(
        rows.contains("policy-change") && rows.contains("not enrolled"),
        "{rows}"
    );
}

#[test]
fn with_enrolment_every_loosening_refuses_without_a_code() {
    let sb = enrolled();
    for args in [
        vec!["allow", "--site", "docs.rs"],
        vec!["gate", "remove"],
        vec!["audit", "checkpoint", "--new-key"],
        vec!["mcp", "unwrap"],
        vec!["uninstall"],
    ] {
        let out = at(&sb, 59, &args, None);
        assert_eq!(out.status.code(), Some(USAGE), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains("no code was typed") && text(&out).contains("nothing was changed"),
            "{args:?}: {}",
            text(&out)
        );
    }
    assert!(sb.home.join(".moat/audit.key.gate").exists());
    assert!(ledger(&sb).contains("gate-refused"));
}

#[test]
fn a_good_code_passes_once_and_its_replay_is_refused() {
    let sb = enrolled();
    let input = format!("{AT_59}\n");
    let out = at(&sb, 59, &["allow", "--site", "docs.rs"], Some(&input));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let out = at(&sb, 60, &["allow", "--site", "crates.io"], Some(&input));
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("already used"), "{}", text(&out));
    let next = format!("{AT_89}\n");
    let out = at(&sb, 89, &["allow", "--site", "crates.io"], Some(&next));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        ledger(&sb).contains("authenticator code"),
        "{}",
        ledger(&sb)
    );
}

#[test]
fn wrong_codes_are_refused_and_then_rate_limited() {
    let sb = enrolled();
    for _ in 0..5 {
        let out = at(&sb, 59, &["allow", "--site", "docs.rs"], Some("000000\n"));
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(text(&out).contains("the code is wrong"), "{}", text(&out));
    }
    let input = format!("{AT_59}\n");
    let out = at(&sb, 59, &["allow", "--site", "docs.rs"], Some(&input));
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("wrong codes"), "{}", text(&out));
}

#[test]
fn narrowing_asks_no_code() {
    let sb = enrolled();
    let input = format!("{AT_59}\n");
    let out = at(&sb, 59, &["allow", "--site", "docs.rs"], Some(&input));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    // Taking the rule out again only narrows: no code, nothing typed.
    let out = at(&sb, 120, &["allow", "--remove", "approved-1"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let out = sb.moat(&["gate", "status"]);
    assert!(text(&out).contains("gate on"), "{}", text(&out));
}

#[test]
fn gate_setup_and_remove_are_person_only() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    for args in [["gate", "setup"], ["gate", "remove"]] {
        let out = sb.moat(&args);
        assert_eq!(out.status.code(), Some(USAGE), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains("must be run by a person"),
            "{}",
            text(&out)
        );
    }
    // A wrong code at setup writes nothing.
    let out = sb.moat_stdin(&["gate", "setup"], "000000\n");
    assert_eq!(out.status.code(), Some(USAGE));
    let out = output(
        sb.command()
            .args(["gate", "setup"])
            .env("MOAT_ASSUME_TTY", "1"),
        Some("000000\n"),
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("otpauth://totp/OpenMoat:"),
        "{}",
        text(&out)
    );
    assert!(!sb.home.join(".moat/audit.key.gate").exists());
}
