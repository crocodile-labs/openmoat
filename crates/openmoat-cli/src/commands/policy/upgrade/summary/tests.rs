use super::*;

const BEFORE: &str = "version: 1
# Deny rules come first.
deny:
  - id: secrets-paths
    reason: secret material
    fs.read: [\"~/.ssh/**\"]
allow:
  - id: dev-readonly
    reason: read-only tools
    shell: [\"git status\"]
  - id: project-fs
    fs.write: [\"${project}/**\"]
ask:
  - id: runs-later
    reason: runs later
    fs.write: [\"${project}/.git/hooks/**\"]
";

/// A new rule, a pattern added to a deny rule, one added to an allow rule, an
/// exception added to an allow rule, a reworded comment, and the rename.
const AFTER: &str = "version: 1
# Deny rules come first, then allow, then review.
deny:
  - id: secrets-paths
    reason: secret material
    fs.read: [\"~/.ssh/**\", \"~/.cline/data/secrets.json\"]
  - id: card-egress
    reason: sends a payment card number to a host off this machine
    net: [\"cards.example\"]
allow:
  - id: dev-readonly
    reason: read-only tools
    shell: [\"git status\", \"git config user.name\"]
  - id: project-fs
    fs.write: [\"${project}/**\", \"!${project}/**/.git/**\"]
review:
  - id: runs-later
    reason: runs later
    fs.write: [\"${project}/.git/hooks/**\"]
";

fn change(yours: &str, default: &str) -> Change {
    Change {
        clean: true,
        line: 1,
        yours: yours.to_owned(),
        default: default.to_owned(),
    }
}

/// The stretches the merge would apply for [`AFTER`]: one comment, three of code.
fn changes() -> Vec<Change> {
    vec![
        change(
            "# Deny rules come first.\n",
            "# Deny rules come first, then allow, then review.\n",
        ),
        change(
            "    fs.read: [\"~/.ssh/**\"]\n",
            "    fs.read: [\"~/.ssh/**\", \"~/.cline/data/secrets.json\"]\n  - id: card-egress\n",
        ),
        change(
            "    shell: [\"git status\"]\n",
            "    shell: [\"git status\", \"git config user.name\"]\n",
        ),
        change(
            "    fs.write: [\"${project}/**\"]\n",
            "    fs.write: [\"${project}/**\", \"!${project}/**/.git/**\"]\n",
        ),
    ]
}

#[test]
fn each_change_is_grouped_by_what_it_does() {
    let changes = changes();
    let applied: Vec<&Change> = changes.iter().collect();
    let summary = summarise(BEFORE, AFTER, &applied, true);
    assert_eq!(
        summary,
        Summary {
            protections: vec![
                "Denied: sends a payment card number to a host off this machine (`card-egress`)"
                    .to_owned(),
                "`project-fs` no longer allows `${project}/**/.git/**`".to_owned(),
                "`secrets-paths` now also denies `~/.cline/data/secrets.json`".to_owned(),
            ],
            fewer: vec!["`dev-readonly` now also allows `git config user.name`".to_owned()],
            renamed: true,
            wording: 1,
            other: Vec::new(),
            unexplained: 0,
        }
    );
    let mut shown = Vec::new();
    summary.write(&mut shown).unwrap();
    let shown = String::from_utf8(shown).unwrap();
    println!("{shown}");
    assert_eq!(
        shown,
        "  New protections
    + Denied: sends a payment card number to a host off this machine (`card-egress`)
    + `project-fs` no longer allows `${project}/**/.git/**`
    + `secrets-paths` now also denies `~/.cline/data/secrets.json`
  Fewer interruptions
    − `dev-readonly` now also allows `git config user.name`
  Renamed
    ~ `ask` is now `review` (same behaviour)
  + 1 comment and wording update
"
    );
}

#[test]
fn a_removed_pattern_and_a_reworded_reason_are_told_apart() {
    let after = BEFORE
        .replace("[\"~/.ssh/**\"]", "[]\n    fs.write: [\"~/.ssh/**\"]")
        .replace(
            "reason: runs later",
            "reason: runs later, outside any sandbox",
        );
    let changes = [change("a\n", "b\n"), change("c\n", "d\n")];
    let applied: Vec<&Change> = changes.iter().collect();
    let summary = summarise(BEFORE, &after, &applied, false);
    assert_eq!(
        summary.fewer,
        ["`secrets-paths` no longer denies `~/.ssh/**`"],
        "{summary:?}"
    );
    assert_eq!(
        summary.protections,
        ["`secrets-paths` now also denies `~/.ssh/**`"],
        "a read rule became a write rule: {summary:?}"
    );
    assert_eq!(summary.wording, 1, "{summary:?}");
}

#[test]
fn a_change_it_cannot_name_is_counted_for_d_to_show() {
    // The same patterns in another order: the policy decides the same.
    let after = BEFORE.replace(
        "    reason: read-only tools\n    shell: [\"git status\"]\n",
        "    shell: [\"git status\"]\n    reason: read-only tools\n",
    );
    let changes = [change("    reason: x\n", "    shell: x\n")];
    let applied: Vec<&Change> = changes.iter().collect();
    let summary = summarise(BEFORE, &after, &applied, false);
    assert_eq!(summary.unexplained, 1, "{summary:?}");
    let mut shown = Vec::new();
    summary.write(&mut shown).unwrap();
    assert_eq!(
        String::from_utf8(shown).unwrap(),
        "  Other changes: 1 (d to see)\n"
    );
    // A policy that does not read is never described as more than that.
    let summary = summarise(BEFORE, "version: [", &applied, false);
    assert_eq!(summary.unexplained, 1, "{summary:?}");
    assert!(summary.protections.is_empty() && summary.fewer.is_empty());
}

#[test]
fn a_section_besides_the_rules_is_named() {
    let after = format!("{BEFORE}executables:\n  git: [\"/usr/bin/git\"]\n");
    let changes = [change("", "executables:\n")];
    let applied: Vec<&Change> = changes.iter().collect();
    let summary = summarise(BEFORE, &after, &applied, false);
    assert_eq!(summary.other, ["`executables:` changed"], "{summary:?}");
    assert_eq!(summary.unexplained, 0);
}

/// The OpenMoat 0.3.0 default upgraded to this release's: what a person who
/// set up OpenMoat then is shown.
#[test]
fn the_0_3_0_default_upgraded_to_this_release() {
    let dir = tempfile::tempdir().unwrap();
    let home = crate::home::Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    let v0_3_0 = include_str!("../../../../upgrade/default-v0.3.0.yaml");
    std::fs::write(home.policy_path(), v0_3_0).unwrap();
    let plan = crate::upgrade::Plan::for_home(&home).unwrap();
    let applied: Vec<&Change> = plan.merge.applied().collect();
    let summary = summarise(&plan.current, &plan.merge.text, &applied, plan.renamed);
    let mut shown = Vec::new();
    summary.write(&mut shown).unwrap();
    let shown = String::from_utf8(shown).unwrap();
    println!("{shown}");
    assert!(summary.renamed, "{shown}");
    assert!(
        summary
            .protections
            .iter()
            .any(|l| l.contains("(`card-egress`)")),
        "{shown}"
    );
    assert!(
        summary.fewer.iter().any(|l| l.contains("web.search")) || shown.contains("defaults"),
        "the 0.4.0 `web.search: allow` default is named: {shown}"
    );
}

#[test]
fn comments_are_read_as_yaml_reads_them() {
    assert_eq!(strip_comment("  - id: x # note"), "  - id: x ");
    assert_eq!(
        strip_comment("    shell: [\"a # b\"]"),
        "    shell: [\"a # b\"]"
    );
    assert_eq!(strip_comment("# all of it"), "");
    assert_eq!(strip_comment("  url: a#b"), "  url: a#b");
    assert_eq!(
        without_comments("# one\n\n  - id: x  # two\n"),
        without_comments("# changed\n  - id: x\n")
    );
}
