//! `openmoat run`'s temp directories: its own, removed when it ends, and the
//! shared one neither writable nor readable by a command.

use std::process::Command;

use super::confined::ran;
use super::{installed_with_secret, run_sh};
use crate::common::{stdout, text};

/// The agent gets a temp directory of the run's own as `TMPDIR`, removed
/// afterwards; the shared one is neither writable nor readable, on every
/// Linux path too, so a Kerberos ticket cache where Kerberos keeps it by
/// default (`/tmp/krb5cc_<uid>`) cannot be read by a command.
#[test]
fn the_run_has_its_own_temp_directory_and_ticket_caches_stay_closed() {
    let (sb, project) = installed_with_secret();
    // As `openmoat run` resolves it (`/private/var/…` on macOS).
    let shared = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&shared).unwrap();
    let shared = std::fs::canonicalize(&shared).unwrap();
    // A fake cache under a name of this test's own, never a real one.
    let id = Command::new("id").arg("-u").output().unwrap();
    let uid = String::from_utf8_lossy(&id.stdout).trim().to_owned();
    let cache = format!("/tmp/krb5cc_{uid}_openmoat_e2e_{}", std::process::id());
    let planted = std::fs::File::create_new(&cache)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"FAKE-TICKET"))
        .is_ok();
    // Another program's file in the shared temp directory.
    let left = format!("/tmp/openmoat_e2e_left_{uid}_{}", std::process::id());
    let left_planted = std::fs::File::create_new(&left)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"FAKE-LEFT"))
        .is_ok();
    let script = format!(
        "case \"$TMPDIR\" in \"{shared}\"/openmoat-run-*) echo private=0;; esac
         echo x > \"$TMPDIR/f\" && cat \"$TMPDIR/f\" >/dev/null; echo own=$?
         echo \"$TMPDIR\" > \"{shared}/where\"; echo shared=$?
         cat \"{cache}\"; echo krb=$?
         cat \"{left}\"; echo left=$?",
        shared = shared.display()
    );
    let out = run_sh(&sb, &project, &script);
    if planted {
        let _ = std::fs::remove_file(&cache);
    }
    if left_planted {
        let _ = std::fs::remove_file(&left);
    }
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    for expected in ["private=0\n", "own=0\n"] {
        assert!(stdout(&out).contains(expected), "{expected}: {shown}");
    }
    assert!(!stdout(&out).contains("shared=0\n"), "{shown}");
    assert!(!shared.join("where").exists(), "{shown}");
    let leftovers = std::fs::read_dir(&shared)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("openmoat-run-"))
        .count();
    assert_eq!(leftovers, 0, "removed when the run ends: {shown}");
    if planted {
        assert!(!stdout(&out).contains("krb=0\n"), "{shown}");
        assert!(!shown.contains("FAKE-TICKET"), "{shown}");
    }
    if left_planted {
        assert!(!stdout(&out).contains("left=0\n"), "{shown}");
        assert!(!shown.contains("FAKE-LEFT"), "{shown}");
    }
}
