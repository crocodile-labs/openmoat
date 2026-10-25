use serde_json::{Value, json};

use super::{YamlHookError, parse, remove, upsert};
use crate::HookSpec;
use crate::wire::hook_file::{HookFile, HookOutcome};

/// An entry `{command, timeout}` recognised by its command's ending.
#[derive(Debug)]
struct Plain;

impl HookFile for Plain {
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        json!({ "command": format!("{binary} guard --host {id}"), "timeout": spec.timeout })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry["command"]
            .as_str()
            .is_some_and(|c| c.ends_with(&format!(" guard --host {id}")))
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let c = entry["command"].as_str()?;
        c.strip_suffix(&format!(" guard --host {id}"))
            .map(str::to_owned)
    }
}

static PLAIN: Plain = Plain;

const HOOKS: &[HookSpec] = &[HookSpec::new("pre_tool_call", "", 60, false)];

fn install(text: &str) -> Result<(HookOutcome, String), YamlHookError> {
    upsert(&PLAIN, text, "config.yaml", "x", HOOKS, "/bin/om")
}

fn ours(doc: &str) -> Value {
    parse(doc).unwrap()["hooks"]["pre_tool_call"].clone()
}

/// Installing and removing gives back every one of these files byte for
/// byte, whatever else it holds and however its lists are indented.
#[test]
fn install_then_remove_gives_back_the_file() {
    for original in [
        "",
        "model: hermes-4\n",
        "# only a comment\n",
        "hooks:\n  post_tool_call:\n    - command: log.sh  # keep\n",
        "hooks:\n  pre_tool_call:\n  - command: mine.sh\n    timeout: 5\nother: 1\n",
        "a: 1\nhooks:\n  # the person's note\n  pre_tool_call:\n    - command: mine.sh\n\n    - command: b.sh\nb: 2\n",
        "hooks:\r\n  pre_tool_call:\r\n    - command: mine.sh\r\n",
    ] {
        let (outcome, edited) = install(original).unwrap();
        assert_eq!(outcome, HookOutcome::Installed, "{original:?}");
        let list = ours(&edited);
        assert!(
            list.as_array()
                .unwrap()
                .iter()
                .any(|e| PLAIN.is_ours(e, "x")),
            "{edited}"
        );
        let (again, same) = install(&edited).unwrap();
        assert_eq!(again, HookOutcome::Unchanged);
        assert_eq!(same, edited);
        let back = remove(&PLAIN, &edited, "config.yaml", "x")
            .unwrap()
            .unwrap();
        assert_eq!(back, original, "{edited}");
    }
}

#[test]
fn a_stale_entry_is_rewritten_in_place_and_others_stay() {
    let text = "hooks:\n  pre_tool_call:\n    - command: mine.sh\n    - command: /old guard --host x\n      timeout: 60\n# end\n";
    let (outcome, edited) = install(text).unwrap();
    assert_eq!(outcome, HookOutcome::Updated);
    let list = ours(&edited);
    assert_eq!(list.as_array().unwrap().len(), 2, "{edited}");
    assert!(edited.contains("# end"));
    assert!(edited.contains("/bin/om guard --host x"));
    assert!(!edited.contains("/old guard"));
}

#[test]
fn an_empty_hooks_or_event_value_is_filled_in() {
    for text in [
        "hooks:\n",
        "hooks: {}\n",
        "hooks: ~\n",
        "hooks:\n  pre_tool_call:\n",
        "hooks:\n  pre_tool_call: []\n",
        "hooks:\n  pre_tool_call: ~  # none yet\n",
        "model: hermes-4",
    ] {
        let (_, edited) = install(text).unwrap();
        assert_eq!(
            ours(&edited).as_array().unwrap().len(),
            1,
            "{text:?}: {edited}"
        );
    }
}

/// What the line edit cannot follow is refused, with the entry to add.
#[test]
fn an_inline_or_unreadable_hooks_is_refused() {
    for text in [
        "hooks: {pre_tool_call: [{command: a}]}\n",
        "hooks:\n  pre_tool_call: [{command: a}]\n",
        "\"hooks\":\n  pre_tool_call:\n    - command: a\n",
    ] {
        let error = install(text).unwrap_err();
        assert!(
            matches!(error, YamlHookError::Layout { .. }),
            "{text:?}: {error}"
        );
        assert!(
            error.to_string().contains("/bin/om guard --host x"),
            "{error}"
        );
    }
    for text in ["a: 1\na: 2\n", "a: [\n", "<<: {a: 1}\n"] {
        assert!(
            matches!(install(text), Err(YamlHookError::Unreadable { .. })),
            "{text:?}"
        );
    }
    assert!(matches!(
        install("hooks: [1]\n"),
        Err(YamlHookError::Shape(_))
    ));
}

#[test]
fn remove_leaves_a_file_without_our_entries_alone() {
    let text = "hooks:\n  pre_tool_call:\n    - command: mine.sh\n";
    assert_eq!(remove(&PLAIN, text, "config.yaml", "x").unwrap(), None);
    assert_eq!(remove(&PLAIN, "", "config.yaml", "x").unwrap(), None);
}

#[test]
fn empty_and_comment_only_files_parse_as_an_empty_mapping() {
    for text in ["", "\n\n", "# a\n  # b\n"] {
        assert_eq!(parse(text).unwrap(), json!({}), "{text:?}");
    }
}
