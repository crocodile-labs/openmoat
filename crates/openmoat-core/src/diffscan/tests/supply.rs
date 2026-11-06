//! Manifests and lockfiles.

use super::{File, found, quiet};
use crate::diffscan::{INSTALL_SCRIPT, LOCK_INTEGRITY, Level, PACKAGE_NEAR_MISS, PACKAGE_SOURCE};

const NEAR: (&str, Level) = (PACKAGE_NEAR_MISS, Level::Review);
const SOURCE: (&str, Level) = (PACKAGE_SOURCE, Level::Review);
const INTEGRITY: (&str, Level) = (LOCK_INTEGRITY, Level::Deny);

#[test]
fn a_near_miss_dependency_is_found_in_every_manifest() {
    for (path, line) in [
        ("package.json", r#"    "lodahs": "^4.17.21","#),
        ("web/package.json", r#"    "expresss": "4.19.2""#),
        ("requirements.txt", "reqeusts==2.31.0"),
        ("requirements-dev.txt", "python-dateutils>=2.8"),
        ("pyproject.toml", r#"    "reqeusts>=2.31","#),
        (
            "pyproject.toml",
            r#"dependencies = ["rich", "reqeusts>=2"]"#,
        ),
        ("pyproject.toml", r#"reqeusts = "^2.31""#),
        ("Cargo.toml", r#"serde_jsno = "1.0""#),
        (
            "Cargo.toml",
            r#"tokioo = { version = "1", features = ["full"] }"#,
        ),
        ("Gemfile", r#"gem "railss", "~> 7.1""#),
    ] {
        assert_eq!(
            found(&File::edit(path, &[], &[line])),
            [NEAR],
            "{path}: {line}"
        );
    }
}

#[test]
fn a_normal_dependency_and_the_other_keys_of_a_manifest_are_quiet() {
    quiet(&File::edit(
        "package.json",
        &[r#"    "lodash": "^4.17.20","#],
        &[
            r#"    "lodash": "^4.17.21","#,
            r#"    "@types/node": "^20.11.0","#,
            r#"    "my-internal-lib": "workspace:*","#,
            r#"    "local": "file:../local","#,
            r#"  "version": "1.2.4","#,
            r#"    "build": "tsc -p .","#,
            r#"    "node": ">=18""#,
        ],
    ));
    quiet(&File::new(
        "pyproject.toml",
        &[
            "[project]",
            r#"name = "reqeusts-helper""#,
            r#"version = "0.1.0""#,
            r#"requires-python = ">=3.10""#,
            r#"dependencies = ["requests>=2.31", "rich"]"#,
            r#"keywords = ["cli", "parsr"]"#,
            r#"    "Programming Language :: Python :: 3","#,
        ],
    ));
    quiet(&File::new(
        "Cargo.toml",
        &[
            "[package]",
            r#"name = "my-crate""#,
            r#"edition = "2024""#,
            r#"rust-version = "1.85""#,
            "[dependencies]",
            r#"serde = { version = "1", features = ["derive"] }"#,
            "serde_json = { workspace = true }",
            r#"anyhow = "1""#,
            "[profile.release]",
            "opt-level = 3",
        ],
    ));
    quiet(&File::new(
        "requirements.txt",
        &[
            "requests==2.31.0",
            "-r base.txt",
            "# pinned",
            "--hash=sha256:abc",
        ],
    ));
    quiet(&File::new(
        "go.mod",
        &[
            "module example.com/me",
            "go 1.22",
            "require github.com/stretchr/testify v1.9.0",
        ],
    ));
    quiet(&File::new(
        "Gemfile",
        &[
            "source \"https://rubygems.org\"",
            "gem \"rails\", \"~> 7.1\"",
        ],
    ));
}

#[test]
fn install_scripts_are_reported_with_their_command() {
    for key in ["preinstall", "install", "postinstall", "prepare"] {
        let line = format!(r#"    "{key}": "node scripts/setup.js","#);
        let file = File::edit("package.json", &[], &[&line]);
        assert_eq!(found(&file), [(INSTALL_SCRIPT, Level::Review)], "{key}");
        assert!(file.hits()[0].reason.contains("node scripts/setup.js"));
    }
    quiet(&File::edit(
        "package.json",
        &[],
        &[r#"    "test": "vitest run","#],
    ));
    // only package.json runs them
    quiet(&File::edit(
        "tsconfig.json",
        &[],
        &[r#"    "postinstall": "x","#],
    ));
}

#[test]
fn a_dependency_from_outside_its_registry_is_reported() {
    for (path, line) in [
        (
            "package.json",
            r#"    "left-pad": "git+https://evil.example.net/left-pad.git","#,
        ),
        (
            "package.json",
            r#"    "left-pad": "github:someone/left-pad","#,
        ),
        (
            "package.json",
            r#"    "left-pad": "someone/left-pad#main","#,
        ),
        (
            "package.json",
            r#"    "left-pad": "https://evil.example.net/left-pad.tgz","#,
        ),
        (
            "requirements.txt",
            "git+https://github.com/someone/requests.git#egg=requests",
        ),
        (
            "requirements.txt",
            "requests @ https://evil.example.net/requests-2.31.tar.gz",
        ),
        (
            "Cargo.toml",
            r#"serde = { git = "https://github.com/someone/serde" }"#,
        ),
        (
            "go.mod",
            "replace github.com/sirupsen/logrus => github.com/someone/logrus v1.9.3",
        ),
        (
            "Gemfile",
            r#"gem "rails", git: "https://github.com/someone/rails""#,
        ),
        ("Gemfile", r#"source "https://gems.evil.example.net""#),
    ] {
        assert!(
            found(&File::edit(path, &[], &[line])).contains(&SOURCE),
            "{path}: {line}"
        );
    }
}

/// A `package-lock.json` entry.
fn npm_entry(version: &str, host: &str, integrity: &str) -> Vec<String> {
    vec![
        format!(r#"      "version": "{version}","#),
        format!(r#"      "resolved": "https://{host}/lodash/-/lodash-{version}.tgz","#),
        format!(r#"      "integrity": "sha512-{integrity}","#),
    ]
}

fn refs(lines: &[String]) -> Vec<&str> {
    lines.iter().map(String::as_str).collect()
}

#[test]
fn a_lockfile_hash_swapped_for_the_same_version_is_denied() {
    let old = r#"      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#;
    let new = r#"      "integrity": "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","#;
    assert_eq!(
        found(&File::edit("package-lock.json", &[old], &[new])),
        [INTEGRITY]
    );
    // removed without a new one
    assert_eq!(
        found(&File::edit("package-lock.json", &[old], &[])),
        [INTEGRITY]
    );
    let yarn_old = "  integrity sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let yarn_new = "  integrity sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    assert_eq!(
        found(&File::edit("yarn.lock", &[yarn_old], &[yarn_new])),
        [INTEGRITY]
    );
    let cargo_old = r#"checksum = "0123456789abcdef0123456789abcdef""#;
    let cargo_new = r#"checksum = "fedcba9876543210fedcba9876543210""#;
    assert_eq!(
        found(&File::edit("Cargo.lock", &[cargo_old], &[cargo_new])),
        [INTEGRITY]
    );
    let pnpm_old = "    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}";
    let pnpm_new = "    resolution: {integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB}";
    assert_eq!(
        found(&File::edit("pnpm-lock.yaml", &[pnpm_old], &[pnpm_new])),
        [INTEGRITY]
    );
    // poetry: the same file name with another hash, whatever else the block changes
    let poetry_old =
        r#"    {file = "requests-2.31.0.tar.gz", hash = "sha256:AAAAAAAAAAAAAAAAAAAAAAAA"},"#;
    let poetry_new =
        r#"    {file = "requests-2.31.0.tar.gz", hash = "sha256:BBBBBBBBBBBBBBBBBBBBBBBB"},"#;
    assert_eq!(
        found(&File::edit("poetry.lock", &[poetry_old], &[poetry_new])),
        [INTEGRITY]
    );
}

#[test]
fn an_upgrade_a_new_package_and_a_removed_one_keep_the_lockfile_quiet() {
    let old = npm_entry(
        "4.17.20",
        "registry.npmjs.org",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    let new = npm_entry(
        "4.17.21",
        "registry.npmjs.org",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );
    quiet(&File::edit("package-lock.json", &refs(&old), &refs(&new)));
    quiet(&File::edit("package-lock.json", &[], &refs(&new)));
    quiet(&File::edit("package-lock.json", &refs(&old), &[]));
    // the same lines moved within the block
    quiet(&File::edit("package-lock.json", &refs(&old), &refs(&old)));
    // poetry: a version bump renames the files; the hashes of the old names go
    let poetry_old =
        r#"    {file = "requests-2.31.0.tar.gz", hash = "sha256:AAAAAAAAAAAAAAAAAAAAAAAA"},"#;
    let poetry_new =
        r#"    {file = "requests-2.32.0.tar.gz", hash = "sha256:BBBBBBBBBBBBBBBBBBBBBBBB"},"#;
    quiet(&File::edit("poetry.lock", &[poetry_old], &[poetry_new]));
    quiet(&File::edit(
        "poetry.lock",
        &[r#"content-hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#],
        &[r#"content-hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#],
    ));
    // Cargo.lock: `source` sits between `version` and `checksum`, two blocks
    let mut upgrade = File::edit(
        "Cargo.lock",
        &[r#"version = "1.0.228""#],
        &[r#"version = "1.0.229""#],
    );
    upgrade.block(
        &[r#"checksum = "0123456789abcdef0123456789abcdef""#],
        &[r#"checksum = "fedcba9876543210fedcba9876543210""#],
    );
    quiet(&upgrade);
    // the next package's checksum, swapped beside an upgrade, is still found
    let mut beside = File::edit(
        "Cargo.lock",
        &[r#"version = "1.0.228""#],
        &[r#"version = "1.0.229""#],
    );
    beside.block(
        &[],
        &[
            "checksum = \"fedcba9876543210fedcba9876543210\"",
            "",
            "[[package]]",
            "name = \"x\"",
            "version = \"1\"",
        ],
    );
    beside.block(
        &[r#"checksum = "0123456789abcdef0123456789abcdef""#],
        &[r#"checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#],
    );
    assert_eq!(found(&beside), [INTEGRITY]);
    let cargo = [
        "[[package]]",
        r#"name = "serde""#,
        r#"version = "1.0.210""#,
        r#"source = "registry+https://github.com/rust-lang/crates.io-index""#,
        r#"checksum = "fedcba9876543210fedcba9876543210""#,
    ];
    quiet(&File::new("Cargo.lock", &cargo));
    quiet(&File::new(
        "yarn.lock",
        &[
            "lodash@^4.17.21:",
            "  version \"4.17.21\"",
            "  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c\"",
            "  integrity sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ],
    ));
}

#[test]
fn a_locked_package_from_outside_the_registry_is_reported_once_per_place() {
    let evil = npm_entry(
        "4.17.21",
        "evil.example.net",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );
    let mut twice = evil.clone();
    twice.extend(evil.clone());
    assert_eq!(
        found(&File::new("package-lock.json", &refs(&twice))),
        [SOURCE]
    );
    let plain = npm_entry("4.17.21", "registry.npmjs.org", "B")
        .join("\n")
        .replace("https:", "http:");
    let file = File::new("package-lock.json", &[plain.lines().nth(1).unwrap()]);
    assert_eq!(found(&file), [SOURCE]);
    assert!(
        file.hits()[0].reason.contains("plain http"),
        "{:?}",
        file.hits()
    );
    for (path, line) in [
        (
            "package-lock.json",
            r#"      "resolved": "git+ssh://git@github.com/someone/lodash.git#abc","#,
        ),
        (
            "Cargo.lock",
            r#"source = "git+https://github.com/someone/serde?rev=abc#abc""#,
        ),
        (
            "pnpm-lock.yaml",
            "    resolution: {tarball: https://evil.example.net/x.tgz}",
        ),
        (
            "yarn.lock",
            "  resolution: \"lodash@https://evil.example.net/lodash.tgz\"",
        ),
        (
            "uv.lock",
            r#"sdist = { url = "https://evil.example.net/requests-2.31.0.tar.gz", hash = "sha256:abc" }"#,
        ),
    ] {
        assert_eq!(found(&File::new(path, &[line])), [SOURCE], "{path}: {line}");
    }
    quiet(&File::new(
        "uv.lock",
        &[
            r#"source = { registry = "https://pypi.org/simple" }"#,
            r#"sdist = { url = "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz", hash = "sha256:abcdefabcdefabcdefabcdef" }"#,
        ],
    ));
}
