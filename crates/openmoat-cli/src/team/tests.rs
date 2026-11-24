use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use openmoat_core::{Action, CompiledPolicy, EvalContext, ForeignHooks, Unattended, Verdict};

use super::bundle::{MANIFEST, SIGNATURE};
use super::settings::Settings;
use super::*;

/// A person's policy that allows what the team holds, and turns settings off.
const USER: &str = "version: 1\ndefaults: { '*': defer }\n\
    allow:\n  - id: dev\n    shell: ['npm *', 'terraform *']\n\
    mcp: { trust_first_sight: true, allow_sampling: true }\n\
    sandbox: { package_min_release_age_days: 0 }\n";

const RULES: &str = "version: 1\n\
    deny:\n  - id: no-publish\n    shell: ['npm publish*']\n\
    review:\n  - id: infra\n    shell: ['terraform apply*']\n";

const PACK: &str = "version: 1\n\
    review:\n  - id: kube\n    shell: ['kubectl delete*']\n";

fn manifest_text(serial: u64, rules: &str, extra: &str) -> String {
    format!(
        "format: openmoat-team-bundle-v1\nname: acme\nserial: {serial}\n\
         policy: {{ path: policy.yaml, sha256: {} }}\n\
         packs:\n  - {{ name: kube, path: packs/kube.yaml, sha256: {} }}\n\
         settings:\n  sandbox.strict: true\n  hooks.foreign: hold\n  unattended: review\n  \
         mcp.trust_first_sight: false\n  mcp.allow_sampling: false\n  \
         sandbox.package_min_release_age_days: 3\n\
         require_hooks: [{}]\n{extra}",
        sha256_hex(rules.as_bytes()),
        sha256_hex(PACK.as_bytes()),
        Host::ALL[0].id(),
    )
}

fn files(rules: &str) -> Vec<RuleFile> {
    [("policy", rules), ("kube", PACK)]
        .into_iter()
        .map(|(name, text)| RuleFile {
            name: name.into(),
            text: text.into(),
            rules: bundle::parse_rules(name, text).unwrap(),
        })
        .collect()
}

fn decide(policy: &Policy, command: &str) -> (Verdict, Vec<String>) {
    let ctx = EvalContext {
        home: "/h".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let d = CompiledPolicy::compile(policy, &ctx)
        .unwrap()
        .decide(&Action::Shell {
            command: command.into(),
        });
    (d.verdict, d.rules)
}

use openmoat_hosts::Host;

#[test]
fn the_team_layer_holds_what_the_persons_own_allow_rules_allow() {
    let manifest = Manifest::parse(&manifest_text(1, RULES, "")).unwrap();
    let mut policy = Policy::parse(USER).unwrap();
    apply(&mut policy, &manifest, &files(RULES)).unwrap();
    assert_eq!(
        decide(&policy, "npm publish"),
        (Verdict::Deny, vec!["team:acme:policy:no-publish".into()])
    );
    assert_eq!(
        decide(&policy, "terraform apply"),
        (Verdict::Review, vec!["team:acme:policy:infra".into()])
    );
    assert_eq!(decide(&policy, "kubectl delete pod x").0, Verdict::Review);
    // What the team says nothing about stays the person's.
    assert_eq!(decide(&policy, "npm test").0, Verdict::Allow);
}

#[test]
fn the_team_settings_raise_the_persons_and_never_lower_them() {
    let manifest = Manifest::parse(&manifest_text(1, RULES, "")).unwrap();
    let mut policy = Policy::parse(USER).unwrap();
    assert_eq!(manifest.settings.unmet(&policy).len(), 6);
    apply(&mut policy, &manifest, &files(RULES)).unwrap();
    assert!(policy.sandbox_strict());
    assert_eq!(policy.foreign_hooks(), ForeignHooks::Hold);
    assert_eq!(policy.unattended(), Unattended::Review);
    assert!(!policy.trust_mcp_first_sight());
    assert!(!policy.allow_mcp_sampling());
    assert_eq!(policy.package_min_release_age_days(), 3);
    assert_eq!(manifest.settings.unmet(&policy), Vec::<String>::new());

    // A person's stricter value stays.
    let stricter = "version: 1\nsandbox: { package_min_release_age_days: 30 }\n";
    let mut policy = Policy::parse(stricter).unwrap();
    manifest.settings.apply(&mut policy);
    assert_eq!(policy.package_min_release_age_days(), 30);
}

/// The never-widen check (ADR-111) over the bundled cases: the default
/// policy and the person's own, each with the team's layer merged, widen
/// nothing.
#[test]
fn merging_the_team_layer_widens_nothing() {
    let manifest = Manifest::parse(&manifest_text(1, RULES, "")).unwrap();
    for base in [openmoat_core::DEFAULT_POLICY, USER] {
        let before = Policy::parse(base).unwrap();
        let mut after = before.clone();
        apply(&mut after, &manifest, &files(RULES)).unwrap();
        let report = crate::widen::compare(&before, &after, &[]).unwrap();
        assert!(!report.widens(), "{:?}", report.widenings);
        assert!(!report.unchecked(), "{:?}", report.settings);
    }
}

#[test]
fn a_manifest_that_could_widen_or_escape_its_folder_is_refused() {
    let ok = manifest_text(1, RULES, "");
    Manifest::parse(&ok).unwrap();
    for (bad, why) in [
        (ok.replace("bundle-v1", "bundle-v9"), "format"),
        (ok.replace("serial: 1", "serial: 0"), "serial"),
        (ok.replace("name: acme", "name: Acme"), "name"),
        (ok.replace("policy.yaml", "../policy.yaml"), "path"),
        (ok.replace("policy.yaml", "/etc/policy.yaml"), "path"),
        (ok.replace("packs/kube.yaml", "packs/kube.txt"), "path"),
        (ok.replace("name: kube", "name: policy"), "name"),
        (
            ok.replace("sandbox.strict: true", "sandbox.strict: false"),
            "weaker",
        ),
        (
            ok.replace("hooks.foreign: hold", "hooks.foreign: warn"),
            "weaker",
        ),
        (
            ok.replace("mcp.allow_sampling: false", "mcp.allow_sampling: true"),
            "weaker",
        ),
        (
            ok.replace(Host::ALL[0].id(), "not-an-agent"),
            "require_hooks",
        ),
        (ok.clone() + "defaults: allow\n", "unknown key"),
    ] {
        assert!(Manifest::parse(&bad).is_err(), "{why}: {bad}");
    }
    let allow = "version: 1\nallow:\n  - id: open\n    shell: ['curl *']\n";
    let error = bundle::parse_rules("policy", allow).unwrap_err();
    assert!(format!("{error:#}").contains("only narrows"), "{error:#}");
    assert!(bundle::parse_rules("policy", "version: 1\ndefaults: allow\n").is_err());
    assert!(
        Settings {
            unattended: Some(Unattended::Defer),
            ..Settings::default()
        }
        .check()
        .is_err()
    );
}

/// `ssh-keygen` from this process's search path; `None` where OpenSSH is
/// missing, and those tests stop early (CI runners have it).
fn program() -> Option<PathBuf> {
    let found = crate::environment::find_on_path("ssh-keygen");
    if found.is_none() {
        eprintln!("ssh-keygen not found; skipping");
    }
    found
}

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

fn sign(program: &Path, key: &Path, namespace: &str, file: &Path) {
    let status = Command::new(program)
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(file)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

/// A bundle folder signed by `key` in `namespace`.
fn bundle_dir(program: &Path, dir: &Path, key: &Path, namespace: &str) -> PathBuf {
    let folder = dir.join("bundle");
    std::fs::create_dir_all(folder.join("packs")).unwrap();
    std::fs::write(folder.join("policy.yaml"), RULES).unwrap();
    std::fs::write(folder.join("packs/kube.yaml"), PACK).unwrap();
    std::fs::write(folder.join(MANIFEST), manifest_text(2, RULES, "")).unwrap();
    sign(program, key, namespace, &folder.join(MANIFEST));
    folder
}

/// A state directory whose environment snapshot finds `ssh-keygen`, and the
/// allowed-signers file trusting `key` for team bundles.
fn home_trusting(dir: &Path, key: &Path) -> (Home, PathBuf) {
    let home = Home::at(dir.join("state"));
    crate::environment::Snapshot::capture()
        .save(&home.environment_path())
        .unwrap();
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let line =
        crate::signing::team_signer_line(&format!("security@acme.example {public}")).unwrap();
    let signers = dir.join("team_signers");
    std::fs::write(&signers, format!("{line}\n")).unwrap();
    (home, signers)
}

#[test]
fn a_bundle_verifies_only_with_the_team_key_in_the_team_namespace() {
    let Some(program) = program() else { return };
    let dir = tempfile::tempdir().unwrap();
    let team = keypair(&program, dir.path(), "team");
    let other = keypair(&program, dir.path(), "other");
    let (home, signers) = home_trusting(dir.path(), &team);

    let folder = bundle_dir(&program, dir.path(), &team, crate::signing::TEAM_NAMESPACE);
    let bundle = bundle::verify(&home, &signers, &folder).unwrap();
    assert_eq!(bundle.signer, "security@acme.example");
    assert_eq!(bundle.manifest.serial, 2);
    assert_eq!(bundle.files.len(), 2);

    // A rule file changed after signing.
    std::fs::write(folder.join("packs/kube.yaml"), "version: 1\n").unwrap();
    let error = bundle::verify(&home, &signers, &folder).unwrap_err();
    assert!(format!("{error:#}").contains("changed after"), "{error:#}");

    for (key, namespace) in [
        (&other, crate::signing::TEAM_NAMESPACE),
        (&team, crate::signing::PACK_NAMESPACE),
    ] {
        let elsewhere = tempfile::tempdir().unwrap();
        let folder = bundle_dir(&program, elsewhere.path(), key, namespace);
        let error = bundle::verify(&home, &signers, &folder).unwrap_err();
        assert!(
            format!("{error:#}").contains("does not verify"),
            "{error:#}"
        );
    }
    let no_sig = tempfile::tempdir().unwrap();
    let folder = bundle_dir(
        &program,
        no_sig.path(),
        &team,
        crate::signing::TEAM_NAMESPACE,
    );
    std::fs::remove_file(folder.join(SIGNATURE)).unwrap();
    assert!(bundle::verify(&home, &signers, &folder).is_err());
}

#[test]
fn a_team_signer_is_trusted_for_team_bundles_only() {
    let line = crate::signing::team_signer_line(
        "sec@acme.example namespaces=\"openmoat-pack\" ssh-ed25519 AAAAC3Nza comment",
    )
    .unwrap();
    assert_eq!(
        line,
        "sec@acme.example namespaces=\"openmoat-team-bundle\" ssh-ed25519 AAAAC3Nza"
    );
    for bad in [
        "",
        "sec@acme",
        "b/d ssh-ed25519 AAAA",
        "x rsa AAAA",
        "x ssh-ed25519",
    ] {
        assert!(crate::signing::team_signer_line(bad).is_err(), "{bad:?}");
    }
}

/// The installed layer merges only from a pinned record of unchanged files.
#[test]
fn only_a_pinned_record_of_unchanged_team_files_is_merged() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let manifest = manifest_text(1, RULES, "");
    write_private(&manifest_path(&home), manifest.as_bytes()).unwrap();
    write_private(&rule_path(&home, "policy"), RULES.as_bytes()).unwrap();
    write_private(&rule_path(&home, "kube"), PACK.as_bytes()).unwrap();
    let joined = Joined {
        version: 1,
        name: "acme".into(),
        serial: 1,
        signer: "sec@acme".into(),
        manifest_sha256: sha256_hex(manifest.as_bytes()),
        source: "/src/bundle".into(),
        at_ms: 1,
    };
    joined.save(&home.team_path()).unwrap();
    let pin = |pins: &[PathBuf]| {
        Lock::pin(Path::new("/bin/moat"), pins)
            .unwrap()
            .save(&home.lock_path())
            .unwrap();
    };
    pin(&[]);
    let mut policy = Policy::parse(USER).unwrap();
    merge(&home, &mut policy, Layer::Joined).unwrap();
    assert_eq!(policy, Policy::parse(USER).unwrap(), "an unpinned record");

    let mut pins = vec![home.team_path()];
    pins.extend(installed_files(&home));
    pin(&pins);
    assert!(installed_files(&home).contains(&rule_path(&home, "kube")));
    let mut policy = Policy::parse(USER).unwrap();
    merge(&home, &mut policy, Layer::Joined).unwrap();
    assert!(
        policy
            .deny
            .iter()
            .any(|g| g.id == "team:acme:policy:no-publish")
    );
    let mut none = Policy::parse(USER).unwrap();
    merge(&home, &mut none, Layer::None).unwrap();
    assert_eq!(none, Policy::parse(USER).unwrap());

    std::fs::write(rule_path(&home, "kube"), "version: 1\n").unwrap();
    let error = merge(&home, &mut Policy::parse(USER).unwrap(), Layer::Joined).unwrap_err();
    assert!(format!("{error:#}").contains("changed since"), "{error:#}");
}
