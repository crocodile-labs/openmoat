//! `hook_only` deny groups (ADR-034) reach no generated sandbox: the default
//! `build-credentials` files stay readable for `mvn` and `gradle` there.

use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy, SandboxSettings};

use super::backend::Input;
use super::{Enforcement, Grants, install, landlock, lower_for_hosts, seatbelt};

const FILES: [&str; 3] = [
    ".m2/settings.xml",
    ".m2/settings-security.xml",
    ".gradle/gradle.properties",
];

/// The default policy, and the same with the build tools' homes as read roots,
/// which is how a person lets sandboxed builds read them.
fn policies(home: &str) -> [Policy; 2] {
    let default = Policy::parse(DEFAULT_POLICY).expect("default policy");
    let mut roots = default.clone();
    let sandbox = roots.sandbox.get_or_insert_with(SandboxSettings::default);
    for dir in [".m2", ".gradle"] {
        sandbox.read_roots.push(format!("{home}/{dir}"));
    }
    [default, roots]
}

fn session(policy: &Policy, home: &str) -> Enforcement {
    let project = format!("{home}/proj");
    let ctx = EvalContext {
        home: home.to_owned(),
        project: Some(project.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project,
        case_insensitive_paths: false,
    };
    openmoat_core::ir::lower(policy, &ctx).expect("lowers")
}

fn grants() -> Grants {
    Grants {
        proxy_port: Some(18080),
        tmpdir: Some("/private/var/folders/xy/T".into()),
        program: Some("/usr/bin/agent".into()),
        writes: Vec::new(),
        terminals: Vec::new(),
        trust: None,
        tool_shell: None,
    }
}

/// Every host's and tier's output for `policy`, as text: each sandboxed
/// host's settings as on macOS and as on Linux.
fn outputs(policy: &Policy) -> Vec<(String, String)> {
    let home = "/Users/me";
    let hosts = lower_for_hosts(policy, home, None, Vec::new(), false).expect("lowers");
    let ir = session(policy, home);
    let homes = [home.to_owned()];
    let mut out = Vec::new();
    for host in install::hosts() {
        let backend = install::backend(host).expect("a sandboxed host has a backend");
        let settings = std::path::Path::new(home).join(host.id()).join("settings");
        for linux in [false, true] {
            let input = Input {
                ir: &hosts,
                proxy_port: None,
                homes: &homes,
                binary_paths: &[],
                linux,
            };
            let generated = backend.generate(&input, &settings).unwrap();
            out.push((
                format!("{} linux={linux}", host.id()),
                format!("{generated:?}"),
            ));
        }
    }
    out.push((
        "seatbelt".into(),
        format!("{:?}", seatbelt::generate(&ir, &grants())),
    ));
    out.push((
        "landlock".into(),
        format!("{:?}", landlock::generate(&ir, &grants()).unwrap()),
    ));
    out
}

#[test]
fn build_credentials_are_in_no_generated_sandbox() {
    for (i, policy) in policies("/Users/me").iter().enumerate() {
        for (backend, text) in outputs(policy) {
            for file in FILES {
                assert!(
                    !text.contains(file),
                    "{backend} names {file} (policy {i}): {text}"
                );
            }
            // The outputs do carry `secrets-paths`, so the check above can fail.
            assert!(text.contains(".cargo/credentials"), "{backend}: {text}");
        }
    }
    // With the read roots, the sandboxes let builds read the homes themselves.
    let [_, roots] = policies("/Users/me");
    for (backend, text) in outputs(&roots) {
        assert!(text.contains("/Users/me/.m2"), "{backend}: {text}");
    }
}

#[cfg(unix)]
#[test]
fn bubblewrap_leaves_existing_build_credentials_readable() {
    use super::bwrap::{self, Mount};
    let dir = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(dir.path()).unwrap();
    for rel in ["proj/src", ".m2/repository", ".gradle/caches", ".cargo"] {
        std::fs::create_dir_all(home.join(rel)).unwrap();
    }
    for rel in FILES.iter().chain(&[".cargo/credentials.toml"]) {
        std::fs::write(home.join(rel), "x").unwrap();
    }
    let home = home.to_string_lossy().into_owned();
    let [_, mut policy] = policies(&home);
    policy.sandbox = Some(SandboxSettings {
        read_roots: [".m2", ".gradle", ".cargo"]
            .map(|d| format!("{home}/{d}"))
            .to_vec(),
        ..SandboxSettings::default()
    });
    let project = format!("{home}/proj");
    let out = bwrap::generate(&session(&policy, &home), &grants(), &[project]).unwrap();
    let text = format!("{out:?}");
    for file in FILES {
        assert!(!text.contains(file), "bwrap names {file}: {text}");
    }
    let cargo = Mount::Hide {
        path: format!("{home}/.cargo/credentials.toml"),
        dir: false,
    };
    assert!(out.mounts.contains(&cargo), "{:#?}", out.mounts);
    assert!(
        out.mounts.contains(&Mount::ReadOnly(format!("{home}/.m2"))),
        "{:#?}",
        out.mounts
    );
}
