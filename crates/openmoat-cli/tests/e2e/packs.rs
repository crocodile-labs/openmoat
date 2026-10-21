//! Signed policy packs and signed repository policies (ADR-031), with keys
//! `ssh-keygen` makes at run time in the test's home: no key is committed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::common::{OK, Sandbox, USAGE, stdout, text};

const PACK: &str = "version: 1\n\
    deny:\n  - id: no-deploy\n    shell: ['make deploy*']\n\
    allow:\n  - id: bundle\n    shell: ['make bundle']\n";

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

/// Sign `file` with `key` in `namespace`; the signature is `<file>.sig`.
fn sign(key: &Path, namespace: &str, file: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(file)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

/// An installed sandbox that trusts `alice`'s key; `None` without ssh-keygen.
fn trusting_alice() -> Option<(Sandbox, PathBuf)> {
    let sb = Sandbox::installed(&[".claude"]);
    let keys = sb.home.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let alice = keypair(&keys, "alice")?;
    let public = alice.with_extension("pub");
    let out = sb.moat_as_person(&[
        "policy",
        "trust-key",
        public.to_str().unwrap(),
        "--name",
        "alice@example.com",
    ]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = stdout(&out);
    assert!(shown.contains("SHA256:"), "{}", text(&out));
    assert!(shown.contains("as alice@example.com"), "{}", text(&out));
    Some((sb, alice))
}

fn install(sb: &Sandbox, pack: &Path) -> std::process::Output {
    sb.moat_as_person(&["policy", "install", pack.to_str().unwrap()])
}

#[test]
fn a_pack_signed_by_a_trusted_key_applies_and_is_pinned() {
    let Some((sb, alice)) = trusting_alice() else {
        return;
    };
    let project = sb.project();
    let pack = sb.home.join("team.yaml");
    std::fs::write(&pack, PACK).unwrap();
    sign(&alice, "openmoat-pack", &pack);
    let out = install(&sb, &pack);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stdout(&out).contains("signed by alice@example.com"),
        "{}",
        text(&out)
    );

    let (verdict, reason) = sb.guard_bash("s1", &project, "make deploy prod");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("pack:team:no-deploy"), "{reason}");
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "allow");

    // The installed copy is pinned: a change to it is drift, and drift denies.
    let installed = sb.home.join(".moat/policy.d/packs/team.yaml");
    std::fs::write(
        &installed,
        format!("{PACK}  - id: more\n    shell: ['curl *']\n"),
    )
    .unwrap();
    let (verdict, reason) = sb.guard_bash("s1", &project, "make bundle");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("kernel-integrity"), "{reason}");
}

#[test]
fn a_pack_without_a_trusted_signature_is_refused() {
    let Some((sb, _alice)) = trusting_alice() else {
        return;
    };
    let mallory = keypair(&sb.home.join("keys"), "mallory").unwrap();
    let pack = sb.home.join("team.yaml");
    std::fs::write(&pack, PACK).unwrap();
    sign(&mallory, "openmoat-pack", &pack);
    let out = install(&sb, &pack);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("does not verify"), "{}", text(&out));
    assert!(!sb.home.join(".moat/packs.json").exists());

    let unsigned = sb.home.join("other.yaml");
    std::fs::write(&unsigned, PACK).unwrap();
    let out = install(&sb, &unsigned);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let scripted = sb.moat(&["policy", "install", pack.to_str().unwrap()]);
    assert_eq!(scripted.status.code(), Some(USAGE), "{}", text(&scripted));
    assert!(
        text(&scripted).contains("must be run by a person"),
        "{}",
        text(&scripted)
    );
}

/// A repository policy signed by a trusted key allows only where the user
/// policy says `require_signed_repo_policy: true`.
#[test]
fn a_signed_repository_policy_is_trusted_only_when_the_policy_asks() {
    let Some((sb, alice)) = trusting_alice() else {
        return;
    };
    let project = sb.project();
    let repo_policy = project.join(".moat/policy.yaml");
    std::fs::create_dir_all(repo_policy.parent().unwrap()).unwrap();
    std::fs::write(
        &repo_policy,
        "version: 1\nallow:\n  - id: bundle\n    shell: ['make bundle']\n",
    )
    .unwrap();
    sign(&alice, "openmoat-policy", &repo_policy);
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "defer");

    require_signed(&sb);
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "allow");

    // Changed after signing: the signature no longer covers it.
    std::fs::write(
        &repo_policy,
        "version: 1\nallow:\n  - id: bundle\n    shell: ['make bundle', 'make all']\n",
    )
    .unwrap();
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "defer");
}

/// Set `require_signed_repo_policy: true` in the user policy and re-pin it.
fn require_signed(sb: &Sandbox) {
    let user = sb.home.join(".moat/policy.yaml");
    let text_now = std::fs::read_to_string(&user).unwrap();
    std::fs::write(
        &user,
        text_now.replacen(
            "version: 1\n",
            "version: 1\nrequire_signed_repo_policy: true\n",
            1,
        ),
    )
    .unwrap();
    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accepted).contains("re-pinned"), "{}", text(&accepted));
}

/// T9: with `require_signed_repo_policy: true`, `moat trust` alone does not let
/// a repository policy allow: unsigned, or signed by a key nobody trusted, its
/// allow rules are ignored; only a trusted key's signature counts.
#[test]
fn requiring_signatures_ignores_moat_trust_without_one() {
    let Some((sb, alice)) = trusting_alice() else {
        return;
    };
    let project = sb.project();
    let repo_policy = project.join(".moat/policy.yaml");
    std::fs::create_dir_all(repo_policy.parent().unwrap()).unwrap();
    std::fs::write(
        &repo_policy,
        "version: 1\nallow:\n  - id: bundle\n    shell: ['make bundle']\n",
    )
    .unwrap();
    let dir = project.to_string_lossy().into_owned();
    let trusted = sb.moat_approving(&["trust", &dir]);
    assert_eq!(trusted.status.code(), Some(OK), "{}", text(&trusted));
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "allow");

    require_signed(&sb);
    let (verdict, reason) = sb.guard_bash("s1", &project, "make bundle");
    assert_eq!(verdict, "defer", "trusted but unsigned: {reason}");
    let again = sb.moat_approving(&["trust", &dir]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert!(
        text(&again).contains("require_signed_repo_policy"),
        "{}",
        text(&again)
    );
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "defer");

    let mallory = keypair(&sb.home.join("keys"), "mallory").unwrap();
    sign(&mallory, "openmoat-policy", &repo_policy);
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "defer");

    std::fs::remove_file(project.join(".moat/policy.yaml.sig")).unwrap();
    sign(&alice, "openmoat-policy", &repo_policy);
    assert_eq!(sb.guard_bash("s1", &project, "make bundle").0, "allow");
}

/// T9: a pack and a repository policy have the same shape, so each kind's
/// signature is made in its own namespace: a signed pack copied into a
/// project is no signed repository policy, and a signed repository policy is
/// no pack to install.
#[test]
fn a_pack_signature_never_signs_a_repository_policy_and_the_reverse() {
    let Some((sb, alice)) = trusting_alice() else {
        return;
    };
    let project = sb.project();
    let repo_policy = project.join(".moat/policy.yaml");
    std::fs::create_dir_all(repo_policy.parent().unwrap()).unwrap();
    std::fs::write(&repo_policy, PACK).unwrap();
    sign(&alice, "openmoat-pack", &repo_policy);
    require_signed(&sb);
    let (verdict, reason) = sb.guard_bash("s1", &project, "make bundle");
    assert_eq!(verdict, "defer", "a pack's signature: {reason}");

    let pack = sb.home.join("team.yaml");
    std::fs::write(&pack, PACK).unwrap();
    sign(&alice, "openmoat-policy", &pack);
    let out = install(&sb, &pack);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("openmoat-pack"), "{}", text(&out));
    assert!(!sb.home.join(".moat/packs.json").exists());
}
