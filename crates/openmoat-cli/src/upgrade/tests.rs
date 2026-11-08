use super::merge::{Change, merge};
use super::{DEFAULT_V0_3_0, line_endings_of, rename};
use crate::integrity::sha256_hex;

const BASE: &str = "defaults:\n  net: deny\n\nallow:\n  - id: a\n    fs.write: [x]\n  - id: b\n";

#[test]
fn the_assumed_base_is_the_released_0_3_0_default() {
    // `git show v0.3.0:crates/openmoat-core/policies/default-v1.yaml | shasum -a 256`
    assert_eq!(
        sha256_hex(DEFAULT_V0_3_0.as_bytes()),
        "ce353aee992e1f3cf0b83a99a9a952f0210f0db71f2598baa5f69ced4a4b779e"
    );
}

#[test]
fn additions_apply_where_the_policy_kept_the_base() {
    let new = BASE
        .replace("net: deny\n", "net: deny\n  web.search: allow\n")
        .replace("[x]", "[x, \"!y\"]");
    let yours = format!("{BASE}  - id: mine\n");
    let merged = merge(BASE, &yours, &new);
    assert_eq!(merged.text, format!("{new}  - id: mine\n"));
    assert_eq!(merged.base, new);
    assert_eq!(merged.applied().count(), 2);
    assert_eq!(merged.conflicts().count(), 0);
    assert_eq!(merged.changes[0].line, 3);
    assert_eq!(merged.changes[1].line, 6);
}

#[test]
fn a_line_the_person_changed_is_kept_and_reported() {
    let new = BASE.replace("[x]", "[x, \"!y\"]");
    let yours = BASE.replace("[x]", "[x, z]");
    let merged = merge(BASE, &yours, &new);
    assert_eq!(merged.text, yours);
    assert_eq!(merged.applied().count(), 0);
    let conflict = merged.conflicts().next().unwrap();
    assert_eq!(conflict.yours, "    fs.write: [x, z]\n");
    assert_eq!(conflict.default, "    fs.write: [x, \"!y\"]\n");
    // Recorded with the old base there, so the change is reported again next time.
    assert_eq!(merged.base, BASE);
}

#[test]
fn a_removed_rule_stays_removed_and_a_change_next_to_an_edit_is_not_applied() {
    let new = BASE.replace("  - id: b\n", "  - id: b\n    shell: [ls]\n");
    let yours = BASE.replace("  - id: b\n", "");
    let merged = merge(BASE, &yours, &new);
    assert_eq!(merged.text, yours);
    assert_eq!(merged.conflicts().count(), 1);
}

#[test]
fn a_change_already_made_is_not_offered() {
    let new = BASE.replace("net: deny\n", "net: deny\n  web.search: allow\n");
    let merged = merge(BASE, &new, &new);
    assert_eq!(merged.text, new);
    assert_eq!(merged.base, new);
    assert_eq!(merged.changes, Vec::<Change>::new());
    assert_eq!(merged.kept, merged.base_lines);
}

#[test]
fn a_policy_from_the_previous_default_is_offered_build_credentials() {
    let new = openmoat_core::DEFAULT_POLICY;
    let start = new.find("  # Maven and Gradle settings").unwrap();
    let end = new.find("  - id: env-secrets").unwrap();
    let old = format!("{}{}", &new[..start], &new[end..]);
    let yours = old.replace(
        "\"~/.zsh_history\"",
        "\"~/.zsh_history\"\n      - \"~/mine\"",
    );
    let merged = merge(&old, &yours, new);
    assert_eq!(merged.conflicts().count(), 0);
    let policy = openmoat_core::Policy::parse(&merged.text).unwrap();
    let group = policy.deny.iter().find(|g| g.id == "build-credentials");
    assert!(group.is_some_and(|g| g.hook_only && g.fs_read.len() == 3));
    assert!(merged.text.contains("~/mine"));
}

#[test]
fn a_policy_from_the_previous_default_is_offered_the_proxy_ca_lines() {
    // A Windows checkout may hold the file with CRLF line ends.
    let new = &openmoat_core::DEFAULT_POLICY.replace("\r\n", "\n");
    let added = "      # a new proxy CA decides which HTTPS the proxy reads and signs for (ADR-043)\n      \
                 - \"{moat,openmoat} proxy ca *\"\n      - \"*/{moat,openmoat} proxy ca *\"\n";
    assert!(new.contains(added));
    let old = new
        .replace(added, "")
        .replace(",proxy*ca,proxy*install,proxy*uninstall}*'", "}*'");
    let yours = old.replace(
        "\"~/.zsh_history\"",
        "\"~/.zsh_history\"\n      - \"~/mine\"",
    );
    let merged = merge(&old, &yours, new);
    assert_eq!(merged.conflicts().count(), 0);
    assert_eq!(
        merged.text,
        new.replace(
            "\"~/.zsh_history\"",
            "\"~/.zsh_history\"\n      - \"~/mine\"",
        )
    );
    assert!(openmoat_core::Policy::parse(&merged.text).is_ok());
}

/// The note on hook-off project settings (`project-settings`) lands in a
/// policy from the previous default, next to the person's own change.
#[test]
fn a_policy_from_the_previous_default_is_offered_the_project_settings_note() {
    let new = &openmoat_core::DEFAULT_POLICY.replace("\r\n", "\n");
    let added = "      # a project's Codex, pi and OpenCode settings (here and below) need review;\n      \
                 # a write whose content turns that host's hook off (`[features] hooks =\n      \
                 # false`, a pi `extensions` entry or an OpenCode plugin entry that removes\n      \
                 # OpenMoat's) is denied before the file changes (`project-settings`)\n";
    assert!(new.contains(added));
    let old = new.replace(added, "");
    let mine = |text: &str| {
        text.replace(
            "\"~/.zsh_history\"",
            "\"~/.zsh_history\"\n      - \"~/mine\"",
        )
    };
    let merged = merge(&old, &mine(&old), new);
    assert_eq!(merged.conflicts().count(), 0);
    assert_eq!(merged.applied().count(), 1);
    assert_eq!(merged.text, mine(new));
    let policy = openmoat_core::Policy::parse(&merged.text).unwrap();
    let runs_later = policy.review.iter().find(|g| g.id == "runs-later").unwrap();
    assert!(
        runs_later
            .fs_write
            .iter()
            .any(|p| p == "**/.codex/config.toml")
    );
}

#[test]
fn crlf_policies_line_up_with_the_lf_default() {
    let yours = BASE.replace('\n', "\r\n");
    let base = line_endings_of(&yours, BASE);
    let new = line_endings_of(&yours, &BASE.replace("[x]", "[x, y]"));
    let merged = merge(&base, &yours, &new);
    assert_eq!(merged.text, new);
    assert_eq!(line_endings_of("lf\n", &yours), BASE);
}

/// After one upgrade only the stretches the person changed are offered: a
/// default addition held back next to one of them is taken by the same upgrade.
#[test]
fn one_upgrade_leaves_only_the_persons_conflicts() {
    let fs_write = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**"]"#;
    let mine = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**", "!${project}/keys/**"]"#;
    let rule = "  - id: my-rule\n    shell: [\"make deploy\"]\n";
    // The 0.3.0 default says `ask:`; `Plan` renames both sides before merging.
    let edited = DEFAULT_V0_3_0
        .replace(fs_write, mine)
        .replace("ask:\n", &format!("ask:\n{rule}"));
    let (base, base_renamed) = rename::old_names(DEFAULT_V0_3_0);
    let (edited, renamed) = rename::old_names(&edited);
    assert!(base_renamed && renamed);
    let first = merge(&base, &edited, openmoat_core::DEFAULT_POLICY);
    assert!(first.text.contains(mine) && first.text.contains(rule));
    assert!(first.conflicts().count() > 0);
    let again = merge(&first.base, &first.text, openmoat_core::DEFAULT_POLICY);
    assert_eq!(again.applied().count(), 0);
    assert_eq!(again.text, first.text);
}

/// ADR-053: a 0.3.0 policy the person never changed upgrades to the current
/// default exactly, `ask:` renamed with the rest, nothing left to offer.
#[test]
fn an_untouched_old_default_upgrades_to_the_new_one_renamed() {
    let (base, _) = rename::old_names(DEFAULT_V0_3_0);
    let merged = merge(&base, &base, openmoat_core::DEFAULT_POLICY);
    assert_eq!(merged.conflicts().count(), 0);
    assert_eq!(merged.text, openmoat_core::DEFAULT_POLICY);
    let p = openmoat_core::Policy::parse(&merged.text).unwrap();
    assert!(!p.old_names.any());
}

/// The 0.3.0 default with a rule added at the top of its `ask:` list and a
/// changed line: the merge with this release's default must stay one valid
/// policy. A whole-file line diff once lined the old `ask:` list up with the
/// new `defer:` and added the default's `review:` header beside the person's.
#[test]
fn an_edit_next_to_a_section_header_never_repeats_the_header() {
    let fs_write = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**"]"#;
    let mine = r#"fs.write: ["${project}/**", "!${project}/.git/**", "!${project}/.moat/**", "!${project}/keys/**"]"#;
    let rule = "  - id: my-rule\n    shell: [\"make deploy\"]\n";
    let edited = DEFAULT_V0_3_0
        .replace(fs_write, mine)
        .replace("ask:\n", &format!("ask:\n{rule}"));
    let (yours, _) = rename::old_names(&edited);
    let base = rename::old_names(DEFAULT_V0_3_0).0;
    let merged = merge(&base, &yours, openmoat_core::DEFAULT_POLICY);
    for key in ["defaults:", "deny:", "allow:", "review:", "defer:"] {
        let n = merged.text.lines().filter(|l| *l == key).count();
        assert_eq!(n, 1, "{key} appears {n} times");
    }
    assert!(merged.text.contains(mine) && merged.text.contains(rule));
    assert!(
        merged.conflicts().next().is_some(),
        "the edit next to the header is reported"
    );
    openmoat_core::Policy::parse(&merged.text).unwrap();
}

#[test]
fn blocks_split_at_top_level_keys_and_rules_only() {
    let text = "# head\nversion: 1\ndeny:\n  - id: a\n    shell: [\"x: y\", \"  - id: z\"]\n# about allow\nallow:\n  - id: b\n    # - id: c\n";
    let blocks = super::merge::blocks(text);
    let keys: Vec<(&str, &str)> = blocks
        .iter()
        .map(|((s, id), _)| (s.as_str(), id.as_str()))
        .collect();
    assert_eq!(
        keys,
        [
            ("", ""),
            ("version", ""),
            ("deny", ""),
            ("deny", "a"),
            ("allow", ""),
            ("allow", "b")
        ]
    );
    let whole: String = blocks.iter().map(|(_, t)| *t).collect();
    assert_eq!(whole, text);
}

/// A policy nobody changed becomes this release's default exactly, rule order
/// included, from the 0.3.0 default and from a base in another order.
#[test]
fn an_unchanged_policy_becomes_the_new_default_exactly() {
    let base = rename::old_names(DEFAULT_V0_3_0).0;
    let new = openmoat_core::DEFAULT_POLICY;
    assert_eq!(merge(&base, &base, new).text, new);
    let reordered = "review:\n  - id: b\n  - id: a\n";
    let start = "review:\n  - id: a\n  - id: b\n";
    assert_eq!(merge(start, start, reordered).text, reordered);
}

/// A rule the default moves from one list to another leaves the old list and
/// joins the new one, even beside the person's own rule.
#[test]
fn a_rule_the_default_moves_to_another_list_moves() {
    let base = "review:\n  - id: a\n  - id: moved\ndefer:\n  - id: d\n";
    let yours = "review:\n  - id: mine\n  - id: a\n  - id: moved\ndefer:\n  - id: d\n";
    let new = "review:\n  - id: a\ndefer:\n  - id: d\n  - id: moved\n";
    let merged = merge(base, yours, new);
    assert_eq!(
        merged.text,
        "review:\n  - id: mine\n  - id: a\ndefer:\n  - id: d\n  - id: moved\n"
    );
    assert_eq!(merged.conflicts().count(), 0);
}
