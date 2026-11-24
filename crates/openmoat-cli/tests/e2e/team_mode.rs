//! Team mode (ADR-119): a signed team bundle joined, updated and left by a
//! person, its layer deciding the guard's calls, and `openmoat inventory`
//! with `--check` and `--format ocsf`. Keys are made by `ssh-keygen` at run
//! time in the test's home: no key is committed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};

use crate::common::{FAILED, OK, Sandbox, USAGE, json, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

const NAMESPACE: &str = "openmoat-team-bundle";

const RULES: &str = "version: 1\n\
    deny:\n  - id: no-deploy\n    shell: ['make deploy*']\n";

const MORE_RULES: &str = "version: 1\n\
    deny:\n  - id: no-deploy\n    shell: ['make deploy*']\n\
    review:\n  - id: release\n    shell: ['make release*']\n";

/// A fresh ed25519 key pair `<dir>/<name>`, or `None` where `ssh-keygen` is
/// missing (CI runners have it).
fn keypair(dir: &Path, name: &str) -> Option<PathBuf> {
    let key = dir.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&key)
        .stdin(Stdio::null())
        .status();
    match status {
        Ok(status) => {
            assert!(status.success());
            Some(key)
        }
        Err(error) => {
            eprintln!("skipped: ssh-keygen cannot run ({error})");
            None
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// A bundle folder `<parent>/<name>` holding `rules` at `serial`, its
/// manifest signed by `key` in `namespace`.
fn publish(parent: &Path, name: &str, serial: u64, rules: &str, key: &Path) -> PathBuf {
    publish_in(parent, name, serial, rules, key, NAMESPACE)
}

fn publish_in(
    parent: &Path,
    name: &str,
    serial: u64,
    rules: &str,
    key: &Path,
    namespace: &str,
) -> PathBuf {
    let folder = parent.join(name);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("policy.yaml"), rules).unwrap();
    let manifest = folder.join("openmoat-team.yaml");
    std::fs::write(
        &manifest,
        format!(
            "format: openmoat-team-bundle-v1\nname: acme\nserial: {serial}\n\
             policy: {{ path: policy.yaml, sha256: {} }}\n\
             settings:\n  hooks.foreign: hold\n",
            hex(rules.as_bytes())
        ),
    )
    .unwrap();
    let _ = std::fs::remove_file(folder.join("openmoat-team.yaml.sig"));
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(&manifest)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    folder
}

/// The allowed-signers entry a team publishes for `key`.
fn signer(key: &Path) -> String {
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    format!("security@acme.example {}", public.trim())
}

/// An installed sandbox and the team's key; `None` without ssh-keygen.
fn team_key() -> Option<(Sandbox, PathBuf)> {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let keys = sb.home.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let key = keypair(&keys, "acme")?;
    Some((sb, key))
}

fn join(sb: &Sandbox, folder: &Path, key: &Path) -> std::process::Output {
    sb.moat_as_person(&[
        "team",
        "join",
        folder.to_str().unwrap(),
        "--signer",
        &signer(key),
    ])
}

#[test]
fn a_joined_bundle_narrows_the_guard_and_is_pinned() {
    let Some((sb, key)) = team_key() else {
        return;
    };
    let project = sb.project();
    assert_eq!(sb.guard_bash("s1", &project, "make deploy prod").0, "defer");
    let folder = publish(&sb.home, "bundle", 1, RULES, &key);
    let out = join(&sb, &folder, &key);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("signed by security@acme.example"),
        "{}",
        text(&out)
    );

    let (verdict, reason) = sb.guard_bash("s1", &project, "make deploy prod");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("team:acme:policy:no-deploy"), "{reason}");

    let check = sb.moat(&["inventory", "--check", folder.to_str().unwrap()]);
    assert_eq!(check.status.code(), Some(OK), "{}", text(&check));
    let events = json(&sb.moat(&["inventory", "--format", "ocsf"]));
    let machine = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["class_uid"] == 5002)
        .unwrap();
    assert_eq!(
        machine["unmapped"]["openmoat"]["policy"]["team"]["name"],
        "acme"
    );

    // The installed copy is pinned: a change to it is drift, and drift denies.
    let installed = sb.home.join(".moat/team/rules/policy.yaml");
    std::fs::write(&installed, "version: 1\n").unwrap();
    let (verdict, reason) = sb.guard_bash("s1", &project, "make deploy prod");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("kernel-integrity"), "{reason}");
}

#[test]
fn a_bundle_not_signed_by_the_team_key_is_refused() {
    let Some((sb, key)) = team_key() else {
        return;
    };
    let mallory = keypair(&sb.home.join("keys"), "mallory").unwrap();
    let forged = publish(&sb.home, "forged", 1, RULES, &mallory);
    let out = join(&sb, &forged, &key);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("does not verify"), "{}", text(&out));
    assert!(!sb.home.join(".moat/team.json").exists());

    // The team's key, but a pack's namespace.
    let pack_signed = publish_in(&sb.home, "pack", 1, RULES, &key, "openmoat-pack");
    let out = join(&sb, &pack_signed, &key);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(!sb.home.join(".moat/team.json").exists());

    // Changed after signing.
    let changed = publish(&sb.home, "changed", 1, RULES, &key);
    std::fs::write(changed.join("policy.yaml"), "version: 1\n").unwrap();
    let out = join(&sb, &changed, &key);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(!sb.home.join(".moat/team.json").exists());

    // Not a person at a terminal.
    let good = publish(&sb.home, "good", 1, RULES, &key);
    let scripted = sb.moat(&[
        "team",
        "join",
        good.to_str().unwrap(),
        "--signer",
        &signer(&key),
    ]);
    assert_eq!(scripted.status.code(), Some(USAGE), "{}", text(&scripted));
    assert!(
        text(&scripted).contains("must be run by a person"),
        "{}",
        text(&scripted)
    );
    assert!(!sb.home.join(".moat/team.json").exists());
}

#[test]
fn updates_refuse_a_replay_and_wait_for_a_person_to_widen() {
    let Some((sb, key)) = team_key() else {
        return;
    };
    let project = sb.project();
    let v1 = publish(&sb.home, "v1", 1, RULES, &key);
    let out = join(&sb, &v1, &key);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    // A newer bundle that only narrows installs at once.
    let v2 = publish(&sb.home, "v2", 2, MORE_RULES, &key);
    let out = sb.moat_as_person(&["team", "update", v2.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (verdict, reason) = sb.guard_bash("s1", &project, "make release");
    // Claude Code's answer for a review.
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("team:acme:policy:release"), "{reason}");

    // The older bundle cannot be put back.
    let out = sb.moat_as_person(&["team", "update", v1.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("not above"), "{}", text(&out));

    // A newer bundle that drops a rule widens: drift until a person accepts.
    let v3 = publish(&sb.home, "v3", 3, RULES, &key);
    let check = sb.moat(&["inventory", "--check", v3.to_str().unwrap()]);
    assert_eq!(check.status.code(), Some(FAILED), "{}", text(&check));
    assert!(
        text(&check).contains("serial 3 is published"),
        "{}",
        text(&check)
    );
    let declined = sb.moat_as_person(&["team", "update", v3.to_str().unwrap()]);
    assert_eq!(declined.status.code(), Some(USAGE), "{}", text(&declined));
    assert_eq!(sb.guard_bash("s1", &project, "make release").0, "ask");
    let accepted = sb.moat_approving(&["team", "update", v3.to_str().unwrap()]);
    assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
    assert_eq!(sb.guard_bash("s1", &project, "make release").0, "defer");
    let check = sb.moat(&["inventory", "--check", v3.to_str().unwrap()]);
    assert_eq!(check.status.code(), Some(OK), "{}", text(&check));

    // Leaving asks, and takes the layer away.
    let left = sb.moat_approving(&["team", "leave"]);
    assert_eq!(left.status.code(), Some(OK), "{}", text(&left));
    assert_eq!(sb.guard_bash("s1", &project, "make deploy prod").0, "defer");
    let check = sb.moat(&["inventory", "--check", v3.to_str().unwrap()]);
    assert_eq!(check.status.code(), Some(FAILED), "{}", text(&check));
}
