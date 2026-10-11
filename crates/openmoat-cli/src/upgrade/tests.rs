use super::merge::merge;
use super::{DEFAULT_V0_3_0, line_endings_of};
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
    assert!(merged.changes.is_empty());
    assert_eq!(merged.kept, merged.base_lines);
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
