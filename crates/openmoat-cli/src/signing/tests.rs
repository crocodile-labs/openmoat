use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::*;

/// `ssh-keygen` from this process's search path; `None` where OpenSSH is
/// missing, and those tests stop early (CI runners have it).
fn program() -> Option<PathBuf> {
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let found = crate::environment::find_in(&path, &[], PROGRAM);
    if found.is_none() {
        eprintln!("ssh-keygen not found; skipping");
    }
    found
}

/// A fresh ed25519 key pair in `dir`, made at run time: no key is committed.
fn keypair(program: &Path, dir: &Path, name: &str) -> PathBuf {
    let key = dir.join(name);
    let status = Command::new(program)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&key)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    key
}

/// Sign `file` with `key` in `namespace`; the signature is `<file>.sig`.
fn sign(program: &Path, key: &Path, namespace: &str, file: &Path) -> PathBuf {
    let status = Command::new(program)
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(file)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let mut sig = file.as_os_str().to_owned();
    sig.push(".sig");
    PathBuf::from(sig)
}

fn signers_for(dir: &Path, entries: &[(&str, &Path)]) -> PathBuf {
    let mut text = String::new();
    for (name, key) in entries {
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        text.push_str(&signer_line(name, &public).unwrap());
        text.push('\n');
    }
    let path = dir.join("allowed_signers");
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn a_signature_from_a_trusted_key_names_its_signer() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alice = keypair(&program, dir.path(), "alice");
    let bob = keypair(&program, dir.path(), "bob");
    let pack = dir.path().join("pack.yaml");
    fs::write(&pack, "version: 1\n").unwrap();
    let sig = sign(&program, &alice, NAMESPACE, &pack);
    let data = fs::read(&pack).unwrap();

    let both = signers_for(dir.path(), &[("bob@x", &bob), ("alice@x", &alice)]);
    assert_eq!(
        verify(&program, &both, &data, &sig, Signed::RepoPolicy)
            .unwrap()
            .as_deref(),
        Some("alice@x")
    );
    let only_bob = signers_for(dir.path(), &[("bob@x", &bob)]);
    assert_eq!(
        verify(&program, &only_bob, &data, &sig, Signed::RepoPolicy).unwrap(),
        None
    );
    assert!(
        fingerprint(&program, &alice.with_extension("pub"))
            .unwrap()
            .contains("SHA256:")
    );
}

#[test]
fn changed_data_and_another_namespace_do_not_verify() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alice = keypair(&program, dir.path(), "alice");
    let signers = signers_for(dir.path(), &[("alice@x", &alice)]);
    let pack = dir.path().join("pack.yaml");
    fs::write(&pack, "version: 1\n").unwrap();
    let sig = sign(&program, &alice, NAMESPACE, &pack);
    let changed = b"version: 1\nallow: []\n";
    assert_eq!(
        verify(&program, &signers, changed, &sig, Signed::RepoPolicy).unwrap(),
        None
    );

    let commit = dir.path().join("commit.txt");
    fs::write(&commit, "version: 1\n").unwrap();
    let git_sig = sign(&program, &alice, "git", &commit);
    let data = fs::read(&commit).unwrap();
    assert_eq!(
        verify(&program, &signers, &data, &git_sig, Signed::RepoPolicy).unwrap(),
        None
    );
}

#[test]
fn a_signature_that_is_not_a_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let signers = dir.path().join("allowed_signers");
    fs::write(&signers, "").unwrap();
    let error = verify(
        Path::new("ssh-keygen"),
        &signers,
        b"",
        dir.path(),
        Signed::Pack,
    )
    .unwrap_err();
    assert!(error.to_string().contains("not a regular file"), "{error}");
}

#[test]
fn signer_lines_are_limited_to_the_policy_namespace() {
    let line = signer_line("alice@example.com", "ssh-ed25519 AAAAC3Nza+/= alice\n").unwrap();
    assert_eq!(
        line,
        "alice@example.com namespaces=\"openmoat-repo-policy,openmoat-pack\" ssh-ed25519 AAAAC3Nza+/="
    );
    for bad in ["", "a b", "a\"b", "x,y"] {
        assert!(signer_line(bad, "ssh-ed25519 AAAA").is_err(), "{bad:?}");
    }
    for bad in ["", "not a key", "rsa AAAA", "ssh-ed25519 AA\"AA"] {
        assert!(signer_line("a", bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        principals("# c\nb x\na y\nb z\n\n"),
        ["b".to_owned(), "a".to_owned()]
    );
}

#[test]
fn a_pack_signature_is_no_repository_policy_signature_and_the_reverse() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alice = keypair(&program, dir.path(), "alice");
    let signers = signers_for(dir.path(), &[("alice@x", &alice)]);
    let file = dir.path().join("policy.yaml");
    fs::write(
        &file,
        "version: 1\nallow:\n  - id: a\n    shell: ['make deploy']\n",
    )
    .unwrap();
    let data = fs::read(&file).unwrap();

    let pack_sig = sign(&program, &alice, PACK_NAMESPACE, &file);
    let as_pack = verify(&program, &signers, &data, &pack_sig, Signed::Pack).unwrap();
    assert_eq!(as_pack.as_deref(), Some("alice@x"));
    let as_repo = verify(&program, &signers, &data, &pack_sig, Signed::RepoPolicy).unwrap();
    assert_eq!(as_repo, None, "a pack's signature over a repository policy");

    // ssh-keygen does not replace an existing signature file.
    fs::remove_file(&pack_sig).unwrap();
    let repo_sig = sign(&program, &alice, NAMESPACE, &file);
    let as_repo = verify(&program, &signers, &data, &repo_sig, Signed::RepoPolicy).unwrap();
    assert_eq!(as_repo.as_deref(), Some("alice@x"));
    let as_pack = verify(&program, &signers, &data, &repo_sig, Signed::Pack).unwrap();
    assert_eq!(as_pack, None, "a repository policy's signature over a pack");
}

/// A pack signed by an earlier release, in the namespace repository policies
/// shared then, copied into a project with its signature: no longer a signed
/// repository policy, whichever allowed-signers line trusts its key.
#[test]
fn a_signature_in_the_earlier_shared_namespace_verifies_as_nothing() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alice = keypair(&program, dir.path(), "alice");
    let public = fs::read_to_string(alice.with_extension("pub")).unwrap();
    let words: Vec<&str> = public.split_whitespace().collect();
    let earlier = format!(
        "alice@x namespaces=\"{EARLIER_NAMESPACE}\" {} {}\n",
        words[0], words[1]
    );
    let now = signer_line("alice@x", &public).unwrap();
    let file = dir.path().join("policy.yaml");
    fs::write(
        &file,
        "version: 1\nallow:\n  - id: a\n    shell: ['make *']\n",
    )
    .unwrap();
    let data = fs::read(&file).unwrap();
    let old_sig = sign(&program, &alice, EARLIER_NAMESPACE, &file);
    let signers = dir.path().join("allowed_signers");
    for line in [&earlier, &format!("{now}\n")] {
        fs::write(&signers, line).unwrap();
        for what in [Signed::RepoPolicy, Signed::Pack] {
            assert_eq!(
                verify(&program, &signers, &data, &old_sig, what).unwrap(),
                None,
                "{line}"
            );
        }
    }
}

#[test]
fn a_key_trusted_by_an_earlier_release_is_trusted_again_by_trust_key() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alice = keypair(&program, dir.path(), "alice");
    let public = fs::read_to_string(alice.with_extension("pub")).unwrap();
    let words: Vec<&str> = public.split_whitespace().collect();
    let earlier = format!(
        "alice@x namespaces=\"{EARLIER_NAMESPACE}\" {} {}\n",
        words[0], words[1]
    );
    let signers = dir.path().join("allowed_signers");
    fs::write(&signers, &earlier).unwrap();
    let file = dir.path().join("policy.yaml");
    fs::write(&file, "version: 1\n").unwrap();
    let data = fs::read(&file).unwrap();
    let repo_sig = sign(&program, &alice, NAMESPACE, &file);
    assert_eq!(
        verify(&program, &signers, &data, &repo_sig, Signed::RepoPolicy).unwrap(),
        None,
        "the earlier line does not trust the key for the new namespace"
    );
    // ssh-keygen does not replace an existing signature file: sign a copy.
    let pack = dir.path().join("pack.yaml");
    fs::write(&pack, &data).unwrap();
    let pack_sig = sign(&program, &alice, PACK_NAMESPACE, &pack);
    assert_eq!(
        verify(&program, &signers, &data, &pack_sig, Signed::Pack).unwrap(),
        None
    );

    // `moat policy trust-key` again replaces that line, and both verify.
    let now = signer_line("alice@x", &public).unwrap();
    assert!(same_signer(earlier.trim(), &now));
    fs::write(&signers, format!("{now}\n")).unwrap();
    let found = verify(&program, &signers, &data, &repo_sig, Signed::RepoPolicy).unwrap();
    assert_eq!(found.as_deref(), Some("alice@x"));
    let found = verify(&program, &signers, &data, &pack_sig, Signed::Pack).unwrap();
    assert_eq!(found.as_deref(), Some("alice@x"));
    assert!(!same_signer(
        "bob@x namespaces=\"x\" ssh-ed25519 AAAA",
        &now
    ));
    assert!(!same_signer("", &now));
}
