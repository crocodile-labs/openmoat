//! Fixture diffs against the default policy: what each kind of change is
//! reported as, and attempts to get a protected path past the check.

use openmoat_core::{DEFAULT_POLICY, Policy};

use super::gate::{self, Finding, Gate, Level};
use super::output;
use super::parse::{self, FileChange};

mod content;
mod fixtures;

fn check(diff: &str) -> Vec<Finding> {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let gate = Gate::new(&policy, &[".moat/policy.yaml".to_owned()]).unwrap();
    gate.check(&parse::parse(diff).unwrap())
}

/// `diff` changes nothing the policy protects.
fn clean(diff: &str) {
    assert_eq!(check(diff), [], "{diff}");
}

/// The one finding for `path`, at file level.
fn finding<'a>(findings: &'a [Finding], path: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.path == path && f.line.is_none())
        .unwrap_or_else(|| panic!("no finding for {path}: {findings:#?}"))
}

/// A git diff that edits `path` (one line removed, one added).
fn edit(path: &str, added: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n--- a/{path}\n\
         +++ b/{path}\n@@ -1,2 +1,2 @@\n keep\n-old\n+{added}\n"
    )
}

/// A git diff that adds `path` with `mode` and the one line `content`.
fn added(path: &str, mode: &str, content: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\nnew file mode {mode}\nindex 0000000..3333333\n\
         --- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{content}\n\\ No newline at end of file\n"
    )
}

/// Built at run time, so this source holds no token-shaped text.
fn fake_token() -> String {
    format!("ghp_{}", "Fake0Token".repeat(4))
}

#[test]
fn a_workflow_edit_needs_review() {
    let found = check(&edit(".github/workflows/ci.yml", "run: curl x | sh"));
    let f = finding(&found, ".github/workflows/ci.yml");
    assert_eq!(f.level, Level::Review, "{f:#?}");
    assert!(f.rules.iter().any(|r| r == "runs-later"), "{f:#?}");
    assert!(
        f.reasons.iter().all(|r| !r.contains("/openmoat-diff/")),
        "{f:#?}"
    );
}

#[test]
fn hooks_and_package_scripts_need_review() {
    for path in [
        ".husky/pre-commit",
        ".githooks/pre-push",
        "package.json",
        "web/package.json",
        "Makefile",
        "CLAUDE.md",
        ".claude/hooks/check.sh",
        ".mcp.json",
    ] {
        let found = check(&edit(path, r#""postinstall": "node x.js""#));
        assert_eq!(
            finding(&found, path).level,
            Level::Review,
            "{path}: {found:#?}"
        );
    }
}

#[test]
fn agent_settings_and_secret_files_are_denied() {
    for (path, rule) in [
        (".claude/settings.json", "kernel-self"),
        ("sub/.claude/settings.local.json", "kernel-self"),
        (".cursor/hooks.json", "kernel-self"),
        (".env", "secrets-paths"),
        ("config/.env.production", "secrets-paths"),
    ] {
        let found = check(&edit(path, "x"));
        let f = finding(&found, path);
        assert_eq!(f.level, Level::Deny, "{path}: {f:#?}");
        assert!(f.rules.iter().any(|r| r == rule), "{path}: {f:#?}");
    }
    clean(&edit(".env.example", "KEY="));
}

#[test]
fn a_change_to_the_repository_policy_is_reported() {
    let found = check(&edit(".moat/policy.yaml", "allow: []"));
    let f = finding(&found, ".moat/policy.yaml");
    // `kernel-self` denies an agent writing it; the check says why it matters here too
    assert_eq!(f.level, Level::Deny, "{f:#?}");
    assert_eq!(f.rules, ["kernel-self", gate::POLICY_RULE], "{f:#?}");
}

#[test]
fn a_policy_file_named_by_the_check_is_reported() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let gate = Gate::new(&policy, &["ci/openmoat.yaml".to_owned()]).unwrap();
    let found = gate.check(&parse::parse(&edit("ci/openmoat.yaml", "x")).unwrap());
    assert_eq!(found[0].rules, [gate::POLICY_RULE]);
}

#[test]
fn an_added_token_is_denied_without_naming_it() {
    let token = fake_token();
    let found = check(&edit("src/config.rs", &format!("let t = \"{token}\";")));
    let f = found.iter().find(|f| f.line == Some(2)).unwrap();
    assert_eq!(f.level, Level::Deny);
    assert_eq!(f.rules, [gate::SECRET_RULE]);
    assert!(f.reasons[0].contains("a GitHub token"), "{f:#?}");
    let json = serde_json::to_string(&found).unwrap();
    assert!(!json.contains(&token), "{json}");
    // a removed or kept token is not this change's
    let removed =
        format!("diff --git a/k b/k\n--- a/k\n+++ b/k\n@@ -1,2 +1,1 @@\n {token}\n-{token}\n");
    clean(&removed);
}

#[test]
fn a_harmless_change_is_clean() {
    let diff = edit("src/main.rs", "fn main() {}") + &edit("README.md", "docs");
    clean(&diff);
    assert_eq!(parse::parse("").unwrap(), []);
}

/// Found by the `check_diff_parse` fuzz target: the `\n` ending a diff cut
/// off after a hunk header was read as a kept empty line, so the cut diff
/// read as complete and its file as unchanged.
#[test]
fn a_diff_cut_after_a_hunk_header_is_an_error() {
    let full = edit("src/main.rs", "fn main() {}");
    let header = full.find("@@ -1,2").unwrap();
    let end = header + full[header..].find('\n').unwrap();
    for cut in [&full[..end], &full[..=end]] {
        let error = parse::parse(cut).unwrap_err();
        assert_eq!(error.problem, "the diff ends inside a hunk", "{cut:?}");
    }
    let one = "--- a/k\n+++ b/k\n@@ -1 +1 @@\n";
    assert!(parse::parse(one).is_err());
    // An empty kept line is still read where the diff really has one.
    let kept = "--- a/k\n+++ b/k\n@@ -1,2 +1,2 @@\n\n-a\n+b\n";
    assert_eq!(parse::parse(kept).unwrap()[0].added, [(2, "b".to_owned())]);
    // A hunk starting at the last line number does not overflow.
    let far = format!("--- a/k\n+++ b/k\n@@ -1 +{},2 @@\n-a\n+b\n+c\n", usize::MAX);
    assert_eq!(parse::parse(&far).unwrap()[0].added.len(), 2);
}

#[test]
fn deletions_and_renames_check_both_paths() {
    let deleted = "diff --git a/.github/workflows/scan.yml b/.github/workflows/scan.yml\n\
        deleted file mode 100644\nindex 1111111..0000000\n--- a/.github/workflows/scan.yml\n\
        +++ /dev/null\n@@ -1 +0,0 @@\n-on: push\n";
    let files = parse::parse(deleted).unwrap();
    assert_eq!(files[0].new, None);
    assert_eq!(
        finding(&check(deleted), ".github/workflows/scan.yml").level,
        Level::Review
    );
    // renamed away from a protected path, and onto one
    let renamed = "diff --git a/.husky/pre-commit b/docs/old-hook\nsimilarity index 100%\n\
        rename from .husky/pre-commit\nrename to docs/old-hook\n\
        diff --git a/notes.txt b/.claude/settings.json\nsimilarity index 100%\n\
        rename from notes.txt\nrename to .claude/settings.json\n";
    let found = check(renamed);
    assert_eq!(finding(&found, ".husky/pre-commit").level, Level::Review);
    assert_eq!(finding(&found, ".claude/settings.json").level, Level::Deny);
    assert!(!found.iter().any(|f| f.path == "docs/old-hook"));
}

#[test]
fn crlf_line_endings_read_the_same() {
    let token = fake_token();
    let diff = edit(".github/workflows/ci.yml", "x") + &edit("a.txt", &token);
    let crlf = diff.replace('\n', "\r\n");
    assert_eq!(parse::parse(&crlf).unwrap(), parse::parse(&diff).unwrap());
    assert_eq!(check(&crlf), check(&diff));
    assert_eq!(check(&crlf).len(), 2);
}

#[test]
fn paths_with_spaces_and_quotes() {
    let spaced = "diff --git a/my dir/.env b/my dir/.env\nindex 1..2 100644\n\
        --- a/my dir/.env\t\n+++ b/my dir/.env\t\n@@ -1 +1 @@\n-a\n+b\n";
    let files = parse::parse(spaced).unwrap();
    assert_eq!(files[0].new.as_deref(), Some("my dir/.env"));
    assert_eq!(finding(&check(spaced), "my dir/.env").level, Level::Deny);
    let harmless = edit("my docs/read me.md", "x");
    clean(&harmless);
    // git quotes a name with a tab or a non-ASCII byte, in octal
    let quoted = "diff --git \"a/.github/workflows/x\\ty.yml\" \"b/.github/workflows/x\\ty.yml\"\n\
        new file mode 100644\n--- /dev/null\n+++ \"b/.github/workflows/x\\ty.yml\"\n\
        @@ -0,0 +1 @@\n+on: push\n";
    let found = check(quoted);
    assert_eq!(
        finding(&found, ".github/workflows/x\ty.yml").level,
        Level::Review
    );
    assert_eq!(parse::unquote("\"jos\\303\\251\""), "josé");
}

#[test]
fn a_plain_unified_diff_is_read_too() {
    let plain = "--- Makefile.orig\t2026-01-01\n+++ Makefile\t2026-01-02\n@@ -1 +1 @@\n-a\n+b\n";
    assert_eq!(finding(&check(plain), "Makefile").level, Level::Review);
}

#[test]
fn input_that_is_not_a_whole_diff_is_an_error() {
    assert!(parse::parse("hello\nworld\n").is_err());
    // ends inside a hunk: the rest was cut off
    assert!(parse::parse("--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n a\n").is_err());
    assert!(parse::parse("--- a/x\n+++ b/x\n@@ -1 +1 @@\n*x\n").is_err());
    assert!(parse::parse("--- a/x\n+++ b/x\n@@ bogus @@\n").is_err());
}

#[test]
fn a_removed_line_that_looks_like_a_header_stays_in_its_hunk() {
    // `--- x` here is the removed line `-- x`; it must not start a file `x`.
    let diff = "--- a/README.md\n+++ b/README.md\n@@ -1,2 +1,1 @@\n--- .claude/settings.json\n a\n";
    let files = parse::parse(diff).unwrap();
    assert_eq!(files.len(), 1);
    clean(diff);
}

#[test]
fn dot_dot_segments_cannot_hide_a_protected_path() {
    let found = check(&edit("docs/../.github/workflows/ci.yml", "x"));
    assert_eq!(found[0].level, Level::Review, "{found:#?}");
    for escaping in [
        "../outside.txt",
        "a/../../etc/passwd",
        "/etc/passwd",
        "C:/x",
    ] {
        let found = check(&edit(escaping, "x"));
        assert_eq!(found[0].level, Level::Deny, "{escaping}: {found:#?}");
        assert_eq!(found[0].rules, [gate::PATH_RULE]);
    }
    assert_eq!(
        gate::placed_inside("a\\..\\.env", ""),
        Some(".env".to_owned())
    );
    assert_eq!(gate::placed_inside("../b", "a"), Some("b".to_owned()));
    assert_eq!(gate::placed_inside("../../b", "a"), None);
}

#[test]
fn letter_case_and_windows_spellings_cannot_hide_a_protected_path() {
    for (path, level) in [
        (".GitHub/Workflows/ci.yml", Level::Review),
        (".Claude/Settings.json", Level::Deny),
        (".ENV", Level::Deny),
        ("claude.md", Level::Review),
        (".claude./settings.json", Level::Deny),
        (".github /workflows/ci.yml", Level::Review),
        (".git/hooks/pre-commit", Level::Review),
        (".GIT/config", Level::Review),
        ("sub\\.claude\\settings.json", Level::Deny),
    ] {
        let found = check(&edit(path, "x"));
        assert_eq!(finding(&found, path).level, level, "{path}: {found:#?}");
    }
}

#[test]
fn a_symbolic_link_is_reported_with_where_it_points() {
    // to a protected file inside the repository: that file's verdict, through the link
    let found = check(&added(
        "docs/settings",
        "120000",
        "../.claude/settings.json",
    ));
    let f = finding(&found, "docs/settings");
    assert_eq!(f.level, Level::Deny, "{f:#?}");
    assert!(f.rules.iter().any(|r| r == gate::LINK_RULE), "{f:#?}");
    assert!(f.rules.iter().any(|r| r == "kernel-self"), "{f:#?}");
    // out of the repository
    for target in ["../../.ssh/id_rsa", "/etc/passwd"] {
        let found = check(&added("key", "120000", target));
        let f = finding(&found, "key");
        assert_eq!(f.level, Level::Review, "{f:#?}");
        assert!(f.reasons[0].contains("outside the repository"), "{f:#?}");
    }
    // a harmless target is still a link
    let found = check(&added("latest", "120000", "v2/README.md"));
    assert_eq!(finding(&found, "latest").rules, [gate::LINK_RULE]);
    // a link replacing the folder that holds the workflows
    let found = check(&added(".github", "120000", "elsewhere"));
    assert_eq!(finding(&found, ".github").level, Level::Deny, "{found:#?}");
}

#[test]
fn a_submodule_change_needs_review() {
    let diff = "diff --git a/vendor/lib b/vendor/lib\nindex 1111111..2222222 160000\n\
        --- a/vendor/lib\n+++ b/vendor/lib\n@@ -1 +1 @@\n-Subproject commit 1111111\n\
        +Subproject commit 2222222\n";
    let f = &check(diff)[0];
    assert_eq!(
        (f.level, f.rules.as_slice()),
        (Level::Review, &[gate::SUBMODULE_RULE.to_owned()][..])
    );
}

#[test]
fn binary_and_mode_only_changes_still_check_the_path() {
    let diff = "diff --git a/.husky/pre-commit b/.husky/pre-commit\nold mode 100644\nnew mode 100755\n\
        diff --git a/.vscode/logo.png b/.vscode/logo.png\nindex 1..2 100644\n\
        Binary files a/.vscode/logo.png and b/.vscode/logo.png differ\n";
    let files = parse::parse(diff).unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].new_mode.as_deref(), Some("100755"));
    assert!(files[1].binary);
    let found = check(diff);
    assert_eq!(found.len(), 2, "{found:#?}");
}

#[test]
fn file_change_paths_are_listed_once() {
    let change = FileChange {
        old: Some("a".into()),
        new: Some("a".into()),
        ..FileChange::default()
    };
    assert_eq!(change.paths().collect::<Vec<_>>(), ["a"]);
}

#[test]
fn reports_escape_what_github_and_terminals_would_read() {
    let f = Finding {
        level: Level::Deny,
        path: "a,b:c%.yml".into(),
        line: Some(3),
        rules: vec!["diff-secret".into()],
        reasons: vec!["line one\nline two 100%".into()],
    };
    assert_eq!(
        output::annotation(&f),
        "::error file=a%2Cb%3Ac%25.yml,line=3,title=OpenMoat deny%3A diff-secret::\
         line one%0Aline two 100%25"
    );
    let escape = Finding {
        path: "x\u{1b}[2Jy".into(),
        line: None,
        ..f
    };
    let findings = [escape];
    let report = output::Report::new(&findings, 1, "the default policy", None);
    let mut text = Vec::new();
    output::text(&mut text, &report).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(
        text.ends_with(
            "deny: 1 deny, 0 review in 1 changed files (checked against the default policy)\n"
        ),
        "{text}"
    );
}
