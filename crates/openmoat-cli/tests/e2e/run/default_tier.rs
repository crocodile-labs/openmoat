//! The tier a plain `openmoat run` starts (ADR-080): on Linux the Isolated
//! tier where bubblewrap works, which closes what the Lightweight tier leaves
//! open inside the project; `--no-isolate` starts the Lightweight tier and is
//! recorded in the audit log. macOS has no Isolated tier yet, so there the
//! flag changes nothing and writes nothing. The `stock linux` job's half is in
//! `stock_linux.rs`, the policy's half in `strict.rs`.

#[cfg(target_os = "linux")]
use std::process::Output;

use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags};
#[cfg(target_os = "linux")]
use super::{netns_required, stock_linux};
use crate::common::{OK, Sandbox, stderr, stdout, text};

/// The fake secret a project's `.env` holds.
#[cfg(target_os = "linux")]
const DOTENV: &str = "OPENMOAT-DEFAULT-TIER-FAKE-DOTENV";

/// The rules of the rows `openmoat run` wrote about its tier.
pub(super) fn tier_rows(sb: &Sandbox) -> Vec<String> {
    let store = openmoat_audit::Store::open_read_only(&sb.home.join(".moat/audit.db")).unwrap();
    store
        .since(0, Some("moat-run"))
        .unwrap()
        .into_iter()
        .filter(|event| event.tool == "isolation")
        .flat_map(|event| event.rules)
        .collect()
}

/// False, saying so, where the default could not isolate (no bubblewrap):
/// CI's Linux jobs install it, so there it must isolate, except the `stock
/// linux` job, which `stock_linux.rs` covers.
#[cfg(target_os = "linux")]
fn isolated_by_default(out: &Output) -> bool {
    let fell_back = stderr(out).contains("cannot start here");
    assert!(
        !(fell_back && netns_required()),
        "CI must start the Isolated tier by default: {}",
        text(out)
    );
    if fell_back {
        eprintln!("skipped: the Isolated tier cannot start here");
    }
    !fell_back
}

/// The attack the default closes: a project script reads the project's `.env`
/// and writes `.git/hooks`, which the Lightweight tier's Landlock grants
/// cannot deny. Under the default both fail, and no row says the run was weaker.
#[cfg(target_os = "linux")]
#[test]
fn linux_starts_the_isolated_tier_by_default() {
    if stock_linux() {
        eprintln!("skipped: the `stock linux` job has no bubblewrap (stock_linux.rs)");
        return;
    }
    let (sb, project) = installed_with_secret();
    std::fs::write(project.join(".env"), DOTENV).unwrap();
    std::fs::create_dir_all(project.join(".git/hooks")).unwrap();
    let script = "cat .env; echo \"dotenv=$?\"
         echo planted > .git/hooks/pre-commit; echo \"hook=$?\"
         echo started";
    let out = run_sh_flags(&sb, &project, &[], script, &[]);
    if !ran(&out) || !isolated_by_default(&out) {
        return;
    }
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(stdout(&out).contains("started"), "{shown}");
    assert!(stderr(&out).contains("it sees only the project"), "{shown}");
    assert!(!shown.contains(DOTENV), "{shown}");
    assert!(!stdout(&out).contains("dotenv=0"), "{shown}");
    assert!(!stdout(&out).contains("hook=0"), "{shown}");
    assert!(!project.join(".git/hooks/pre-commit").exists(), "{shown}");
    // What the Lightweight tier says it leaves open is not said here.
    assert!(!stderr(&out).contains("closes this"), "{shown}");
    assert_eq!(tier_rows(&sb), [] as [String; 0]);
    let doctor = sb.moat(&["doctor"]);
    assert!(
        text(&doctor).contains("starts the Isolated tier"),
        "{}",
        text(&doctor)
    );
}

/// `--no-isolate` starts the Lightweight tier: on Linux it says what that
/// leaves open and writes a row; on macOS, with no Isolated tier to leave,
/// it writes none.
#[test]
fn no_isolate_starts_the_lightweight_tier_on_record() {
    let (sb, project) = installed_with_secret();
    let out = run_sh_flags(&sb, &project, &[LIGHTWEIGHT], "echo started", &[]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    assert!(stdout(&out).contains("started"), "{shown}");
    assert!(!stderr(&out).contains("cannot start here"), "{shown}");
    let linux = cfg!(target_os = "linux");
    assert_eq!(stderr(&out).contains("closes this"), linux, "{shown}");
    let expected: &[&str] = if linux { &["run-no-isolate"] } else { &[] };
    assert_eq!(tier_rows(&sb), expected, "{shown}");
}

/// `--isolate` and `--no-isolate` together are a usage error, not a choice.
#[test]
fn isolate_and_no_isolate_conflict() {
    let (sb, project) = installed_with_secret();
    let out = run_sh_flags(
        &sb,
        &project,
        &["--isolate", LIGHTWEIGHT],
        "echo started",
        &[],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!stdout(&out).contains("started"), "{}", text(&out));
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        text(&out)
    );
}
