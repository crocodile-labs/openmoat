//! Lockfiles as a direct dependency is checked (ADR-125): every resolved
//! package's name, an install script the lockfile records, and `go.sum`.

use super::{File, found, quiet};
use crate::diffscan::{INSTALL_SCRIPT, LOCK_INTEGRITY, Level, PACKAGE_NEAR_MISS};

const NEAR: (&str, Level) = (PACKAGE_NEAR_MISS, Level::Review);
const SCRIPT: (&str, Level) = (INSTALL_SCRIPT, Level::Review);
const INTEGRITY: (&str, Level) = (LOCK_INTEGRITY, Level::Deny);

#[test]
fn a_look_alike_a_dependency_pulls_in_is_found_in_every_lockfile() {
    for (path, lines) in [
        (
            "package-lock.json",
            &[
                r#"    "node_modules/some-lib/node_modules/lodahs": {"#,
                r#"      "version": "4.17.21","#,
            ][..],
        ),
        (
            "pnpm-lock.yaml",
            &[
                "  /expresss@4.19.2:",
                "    resolution: {integrity: sha512-x}",
            ][..],
        ),
        (
            "pnpm-lock.yaml",
            &[
                "  expresss@4.19.2:",
                "    resolution: {integrity: sha512-x}",
            ][..],
        ),
        (
            "yarn.lock",
            &["expresss@^4.19.2:", r#"  version "4.19.2""#][..],
        ),
        (
            "yarn.lock",
            &[r#""expresss@npm:^4.19.2":"#, "  version: 4.19.2"][..],
        ),
        (
            "Cargo.lock",
            &[
                "[[package]]",
                r#"name = "serde_jsno""#,
                r#"version = "1.0.0""#,
            ][..],
        ),
        (
            "poetry.lock",
            &[
                "[[package]]",
                r#"name = "reqeusts""#,
                r#"version = "2.31.0""#,
            ][..],
        ),
        (
            "uv.lock",
            &[
                "[[package]]",
                r#"name = "reqeusts""#,
                r#"version = "2.31.0""#,
            ][..],
        ),
        (
            "go.sum",
            &["github.com/sirupsen/logruss v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ="]
                [..],
        ),
    ] {
        assert_eq!(found(&File::new(path, lines)), [NEAR], "{path}: {lines:?}");
    }
}

#[test]
fn the_popular_and_the_everyday_names_of_a_lockfile_are_quiet() {
    // a slice of a real npm tree, transitive packages included
    let names = [
        "debug",
        "ms",
        "safe-buffer",
        "inherits",
        "readable-stream",
        "string_decoder",
        "util-deprecate",
        "once",
        "wrappy",
        "brace-expansion",
        "balanced-match",
        "concat-map",
        "minimatch",
        "glob",
        "fs.realpath",
        "inflight",
        "path-is-absolute",
        "is-number",
        "js-tokens",
        "loose-envify",
        "@babel/code-frame",
        "@types/node",
        "lodash",
        "express",
    ];
    let lines: Vec<String> = names
        .iter()
        .flat_map(|n| {
            [
                format!(r#"    "node_modules/{n}": {{"#),
                r#"      "version": "1.0.0","#.to_owned(),
                r#"      "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz","#.to_owned(),
                "    },".to_owned(),
            ]
        })
        .collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    quiet(&File::new("package-lock.json", &lines));
    // this repository's own Cargo.lock, every line new
    let cargo: Vec<&str> = include_str!("../../../../../Cargo.lock").lines().collect();
    quiet(&File::new("Cargo.lock", &cargo));
    quiet(&File::new(
        "go.sum",
        &[
            "github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nwg75+f6Lvsy/wHu+3BoSGCbBAcpTsTg=",
            "github.com/stretchr/testify v1.9.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=",
        ],
    ));
}

#[test]
fn an_install_script_a_lockfile_records_is_named_with_its_package() {
    let npm = File::new(
        "package-lock.json",
        &[
            r#"    "node_modules/deep/node_modules/esbuild": {"#,
            r#"      "version": "0.21.5","#,
            r#"      "hasInstallScript": true,"#,
        ],
    );
    assert_eq!(found(&npm), [SCRIPT]);
    assert!(
        npm.hits()[0].reason.contains("`esbuild`"),
        "{:?}",
        npm.hits()
    );
    // the flag added to an entry whose name line was kept
    let flag_only = File::edit(
        "package-lock.json",
        &[],
        &[r#"      "hasInstallScript": true,"#],
    );
    assert_eq!(found(&flag_only), [SCRIPT]);
    assert!(flag_only.hits()[0].reason.contains("a locked package"));
    let pnpm = File::new(
        "pnpm-lock.yaml",
        &["  /esbuild@0.21.5:", "    requiresBuild: true"],
    );
    assert_eq!(found(&pnpm), [SCRIPT]);
    // the same words elsewhere, or false, are not a script
    quiet(&File::new(
        "package-lock.json",
        &[r#"      "hasInstallScript": false,"#],
    ));
    quiet(&File::new("Cargo.lock", &["requiresBuild: true"]));
}

#[test]
fn an_install_script_is_not_pinned_on_an_entry_further_up() {
    let mut file = File::new(
        "package-lock.json",
        &[
            r#"    "node_modules/left-pad": {"#,
            r#"      "version": "1.3.0","#,
        ],
    );
    file.block(&[], &[r#"      "hasInstallScript": true,"#]);
    let hits = file.hits();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].reason.contains("a locked package"), "{hits:?}");
}

#[test]
fn a_go_sum_hash_changed_for_the_same_version_is_denied() {
    let old = "github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=";
    let swapped =
        "github.com/sirupsen/logrus v1.9.3 h1:AAAAQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=";
    assert_eq!(
        found(&File::edit("go.sum", &[old], &[swapped])),
        [INTEGRITY]
    );
    // an upgrade changes the version with the hash
    let upgraded =
        "github.com/sirupsen/logrus v1.9.4 h1:BBBBQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=";
    quiet(&File::edit("go.sum", &[old], &[upgraded]));
    // a line moved unchanged
    quiet(&File::edit("go.sum", &[old], &[old]));
}
