use std::fmt::Write as _;
use std::path::Path;

use openmoat_core::Policy;
use openmoat_proxy::{Roots, Tls, new_ca};

use super::*;
use crate::home::write_private;

fn policy(hosts: &[&str]) -> Policy {
    let mut yaml = String::from("version: 1\nsecrets:\n");
    for (n, host) in hosts.iter().enumerate() {
        let _ = write!(
            yaml,
            "  - id: s{n}\n    host: {host}\n    header: X-K{n}\n    source: {{ env: T{n} }}\n    \
             tls: terminate\n"
        );
    }
    yaml.push_str("  - id: plain\n    host: plain.test\n    header: X-P\n    source: { env: P }\n");
    Policy::parse(&yaml).unwrap()
}

/// A state directory holding a CA for `covers`, pinned when `pinned`.
fn home_with_ca(covers: &[&str], pinned: bool) -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let hosts: Vec<String> = covers.iter().map(|h| (*h).to_owned()).collect();
    let ca = new_ca(&hosts).unwrap();
    write_private(&key_path(&home), ca.key_pem.as_bytes()).unwrap();
    write_private(
        &cert_path(&home),
        cert_text(&ca, &hosts, crate::time::now_ms()).as_bytes(),
    )
    .unwrap();
    let pins = if pinned { files(&home) } else { Vec::new() };
    Lock::pin(Path::new("/usr/local/bin/openmoat"), &pins)
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    (dir, home)
}

#[test]
fn terminated_hosts_are_sorted_once_each_and_plain_secrets_left_out() {
    assert_eq!(
        terminated_hosts(&policy(&["b.test", "a.test", "b.test"])),
        ["a.test", "b.test"]
    );
    assert!(terminated_hosts(&policy(&[])).is_empty());
}

#[test]
fn the_certificate_file_says_what_it_is_and_still_parses() {
    let hosts = vec!["a.test".to_owned()];
    let ca = new_ca(&hosts).unwrap();
    let text = cert_text(&ca, &hosts, 0);
    assert!(
        text.starts_with("# OpenMoat proxy CA, made by `openmoat proxy ca init` on 1970-01-01\n")
    );
    assert_eq!(valid_until(&text), Some("1971-01-01"));
    assert!(text.contains("only for: a.test"));
    let roots = Roots::Pem(ca.cert_pem.clone());
    assert!(
        Tls::new(&text, &ca.key_pem, &roots, &hosts).is_ok(),
        "PEM readers skip the comment"
    );
    assert_eq!(valid_until("no header"), None);
}

#[test]
fn a_run_without_terminated_secrets_needs_no_ca() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().to_path_buf());
    assert!(load(&home, &policy(&[])).unwrap().is_none());
}

#[test]
fn a_missing_or_unpinned_ca_stops_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    Lock::pin(Path::new("/usr/local/bin/openmoat"), &[])
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    let missing = load(&home, &policy(&["a.test"])).err().unwrap();
    assert!(
        format!("{missing:#}").contains("no pinned proxy CA yet"),
        "{missing:#}"
    );
    let (_dir, unpinned) = home_with_ca(&["a.test"], false);
    let refused = load(&unpinned, &policy(&["a.test"])).err().unwrap();
    assert!(
        format!("{refused:#}").contains("openmoat proxy ca init"),
        "{refused:#}"
    );
}

#[test]
fn a_pinned_ca_is_used_only_for_the_hosts_it_covers() {
    let (_dir, home) = home_with_ca(&["a.test"], true);
    let loaded = load(&home, &policy(&["a.test"])).unwrap().unwrap();
    assert!(loaded.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(loaded.notice.is_none(), "a new CA does not expire soon");
    let other = load(&home, &policy(&["a.test", "b.test"])).err().unwrap();
    let text = format!("{other:#}");
    assert!(
        text.contains("does not cover b.test") && text.contains("ca init"),
        "{text}"
    );
}

#[test]
fn trust_files_hold_the_ca_and_go_with_the_run() {
    let hosts = vec!["a.test".to_owned()];
    let ca = new_ca(&hosts).unwrap();
    let trust = Trust::write(&ca.cert_pem).unwrap();
    let dir = trust.dir().to_path_buf();
    let vars = trust.env();
    let node = vars
        .iter()
        .find(|(v, _)| *v == "NODE_EXTRA_CA_CERTS")
        .unwrap();
    assert_eq!(std::fs::read_to_string(node.1).unwrap(), ca.cert_pem);
    if let Some((_, bundle)) = vars.iter().find(|(v, _)| *v == "SSL_CERT_FILE") {
        let text = std::fs::read_to_string(bundle).unwrap();
        assert!(text.ends_with(&ca.cert_pem) && text.len() > ca.cert_pem.len());
        assert!(trust.notice().is_none());
    }
    drop(trust);
    assert!(!dir.exists(), "removed when the run ends");
}
