//! New network endpoints.

use super::File;
use crate::diffscan::{Change, Level, NEW_HOST, new_hosts};

/// The policy's allow list in these tests.
fn allowed(host: &str) -> bool {
    matches!(host, "github.com" | "api.github.com" | "registry.npmjs.org")
}

/// `(file index, host line)` of each new host in `files`.
fn new(files: &[&File]) -> Vec<(usize, Option<usize>, String)> {
    let changes: Vec<Change<'_>> = files.iter().map(|f| f.change()).collect();
    new_hosts(&changes, allowed)
        .into_iter()
        .map(|(i, hit)| {
            assert_eq!((hit.rule, hit.level), (NEW_HOST, Level::Review));
            let host = hit
                .reason
                .split_whitespace()
                .nth(4)
                .unwrap_or_default()
                .trim_end_matches(',');
            (i, hit.line, host.to_owned())
        })
        .collect()
}

#[test]
fn each_new_host_is_one_finding_at_its_first_line() {
    let code = File::new(
        "src/telemetry.ts",
        &[
            "const a = fetch('https://collect.evil.dev/v1?x=1');",
            "const b = fetch('https://collect.evil.dev/v2');",
            "const ws = new WebSocket(\"wss://user:pw@stream.evil.dev:8443/s\");",
            "const gh = 'https://api.github.com/repos';",
        ],
    );
    let config = File::new(
        "config/prod.yaml",
        &[
            "endpoint: https://collect.evil.dev",
            "mirror: http://45.33.32.156/x",
        ],
    );
    assert_eq!(
        new(&[&code, &config]),
        [
            (0, Some(10), "collect.evil.dev".to_owned()),
            (0, Some(12), "stream.evil.dev".to_owned()),
            (1, Some(11), "45.33.32.156".to_owned()),
        ]
    );
}

#[test]
fn hosts_that_name_no_new_endpoint_are_quiet() {
    let quiet = [
        File::new("README.md", &["See https://docs.acme.dev/guide."]),
        File::new("docs/api.rst", &["https://api.acme.dev"]),
        File::new("package.json", &[r#"  "homepage": "https://acme.dev","#]),
        File::new(
            "package-lock.json",
            &[r#"  "resolved": "https://registry.npmjs.org/x/-/x-1.tgz","#],
        ),
        File::new(
            "src/a.ts",
            &[
                "// see https://docs.acme.dev/why",
                "  # https://acme.dev",
                " * https://acme.dev",
                "const s = 'http://www.w3.org/2000/svg';",
                "const t = 'https://api.example.com/v1';",
                "const u = 'http://localhost:3000/';",
                "const v = 'http://127.0.0.1:8080/';",
                "const w = 'https://svc.test/';",
                "const x = `https://${host}/api`;",
                "const y = 'https://github.com/acme/repo';",
                "const z = 'mailto:me@acme.dev';",
                "const $schema = 'https://json-schema.org/draft/2020-12/schema';",
            ],
        ),
    ];
    let refs: Vec<&File> = quiet.iter().collect();
    assert_eq!(new(&refs), []);
}

#[test]
fn a_host_the_change_moves_is_not_new() {
    let mut moved = File::edit(
        "src/a.py",
        &["URL = 'https://api.acme.dev/v1'"],
        &["URL = 'https://api.acme.dev/v2'"],
    );
    moved.block(&[], &["BACKUP = 'https://backup.acme.dev'"]);
    assert_eq!(
        new(&[&moved]),
        [(0, Some(12), "backup.acme.dev".to_owned())]
    );
    // removed in one file, added in another
    let old = File::edit("src/old.py", &["URL = 'https://api.acme.dev'"], &[]);
    let added = File::new("src/new.py", &["URL = 'https://api.acme.dev'"]);
    assert_eq!(new(&[&old, &added]), []);
}

#[test]
fn text_around_a_url_in_any_script_is_read_safely() {
    let file = File::new(
        "src/a.py",
        &[
            "x = «https://collect.evil.dev»",
            "y = 'été://x' ",
            "z = ':// é'",
        ],
    );
    assert_eq!(
        new(&[&file]),
        [(0, Some(10), "collect.evil.dev".to_owned())]
    );
    // tests and fixtures hold sample URLs
    let sample = File::new(
        "tests/redact.rs",
        &["let u = \"https://hooks.slack.com/x\";"],
    );
    assert_eq!(new(&[&sample]), []);
}
