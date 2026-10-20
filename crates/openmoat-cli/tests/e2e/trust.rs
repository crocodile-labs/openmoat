//! `moat trust` (ADR-022): a repository policy's allow rules apply only to the
//! exact file a person trusted, in the checkout they trusted it in.

use std::path::{Path, PathBuf};

use crate::common::{OK, Sandbox, USAGE, output, stdout, text};

const DEPLOY: &str = "version: 1\nallow:\n  - id: deploy\n    shell: ['make deploy']\n";

/// An installed sandbox whose project allows `make deploy` in its repository policy.
fn repo() -> (Sandbox, PathBuf) {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    write_policy(&project, DEPLOY);
    (sb, project)
}

fn write_policy(project: &Path, yaml: &str) {
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(project.join(".moat/policy.yaml"), yaml).unwrap();
}

/// The hook's verdict and reason for `make deploy` in `project`.
fn deploy(sb: &Sandbox, project: &Path) -> (String, String) {
    sb.guard_bash("s1", project, "make deploy")
}

fn trust(sb: &Sandbox, args: &[&str]) -> std::process::Output {
    sb.moat_as_person(&[&["trust"], args].concat())
}

#[test]
fn trust_applies_allow_rules_until_the_file_changes() {
    let (sb, project) = repo();
    let dir = project.to_string_lossy().into_owned();
    assert_eq!(deploy(&sb, &project).0, "defer");

    let out = trust(&sb, &[&dir]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("allow repo:deploy: shell: make deploy"));
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    let (verdict, reason) = deploy(&sb, &project);
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("repo:deploy"), "{reason}");

    write_policy(&project, &format!("{DEPLOY}# edited\n"));
    assert_eq!(
        deploy(&sb, &project).0,
        "defer",
        "a changed file is untrusted"
    );

    let out = trust(&sb, &[&dir]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(deploy(&sb, &project).0, "allow");
    let out = trust(&sb, &[&dir, "--revoke"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(deploy(&sb, &project).0, "defer", "revoked");
}

/// T9: the same trusted file in another checkout is not trusted there.
#[test]
fn trust_is_bound_to_the_checkout() {
    let (sb, project) = repo();
    let out = trust(&sb, &[&project.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let fork = sb.home.join("fork");
    std::fs::create_dir_all(fork.join(".git")).unwrap();
    write_policy(&fork, DEPLOY);
    assert_eq!(deploy(&sb, &fork).0, "defer");
    assert_eq!(deploy(&sb, &project).0, "allow");
}

/// T9: an agent, a script or a drifted lock cannot trust anything.
#[test]
fn trust_is_person_only_and_refused_over_drift() {
    let (sb, project) = repo();
    let dir = project.to_string_lossy().into_owned();
    let out = sb.moat(&["trust", &dir]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("must be run by a person"),
        "{}",
        text(&out)
    );

    let policy = sb.home.join(".moat/policy.yaml");
    let edited = std::fs::read_to_string(&policy).unwrap() + "# edited\n";
    std::fs::write(&policy, edited).unwrap();
    let out = trust(&sb, &[&dir]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("refusing to change trust"),
        "{}",
        text(&out)
    );
    assert!(!sb.home.join(".moat/trust.json").exists());
}

/// T9: a trust record nobody pinned (written past `moat trust`) is ignored.
#[test]
fn an_unpinned_trust_record_is_ignored() {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let (sb, project) = repo();
    let digest = Sha256::digest(DEPLOY.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
    // The key OpenMoat records: symlinks resolved, slash-separated without the
    // Windows verbatim prefix.
    let root = std::fs::canonicalize(&project).unwrap();
    let root = root
        .to_string_lossy()
        .replace(r"\\?\", "")
        .replace('\\', "/");
    let record = serde_json::json!({"version": 1, "repos": {root: digest}});
    std::fs::write(sb.home.join(".moat/trust.json"), record.to_string()).unwrap();
    assert_eq!(deploy(&sb, &project).0, "defer");

    // The record itself is right: once a person pins it, it applies.
    let out = sb.moat_as_person(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(deploy(&sb, &project).0, "allow");
}

#[test]
fn trust_refuses_a_repo_policy_that_does_not_parse() {
    let (sb, project) = repo();
    write_policy(&project, "version: 1\ndefaults: allow\n");
    let out = trust(&sb, &[&project.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("invalid repository policy"),
        "{}",
        text(&out)
    );
}

/// `moat status` and `moat doctor`, run inside `project`.
fn reports(sb: &Sandbox, project: &Path) -> [(Option<i32>, String); 2] {
    ["status", "doctor"].map(|command| {
        let out = output(sb.command().arg(command).current_dir(project), None);
        (out.status.code(), stdout(&out))
    })
}

#[test]
fn status_and_doctor_say_which_form_applies() {
    let (sb, project) = repo();
    let dir = project.to_string_lossy().into_owned();
    for (_, out) in reports(&sb, &project) {
        assert!(out.contains("repo policy"), "{out}");
        assert!(out.contains("not trusted: tightening only"), "{out}");
    }
    assert_eq!(trust(&sb, &[&dir]).status.code(), Some(OK));
    for (_, out) in reports(&sb, &project) {
        assert!(out.contains("trusted (0 deny, 0 ask, 1 allow)"), "{out}");
    }
    write_policy(&project, &format!("{DEPLOY}# edited\n"));
    for (_, out) in reports(&sb, &project) {
        assert!(out.contains("changed since `openmoat trust`"), "{out}");
    }
    write_policy(&project, "version: 1\ndeny: [\n");
    for (code, out) in reports(&sb, &project) {
        assert_eq!(code, Some(USAGE), "{out}");
        assert!(
            out.contains("every call in this project is denied"),
            "{out}"
        );
    }
}
