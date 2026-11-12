//! What a call returned, as a host's after-call event reports it (ADR-057,
//! ADR-063): the text the guard keeps fingerprints of.

use openmoat_core::MAX_INJECTED_SCAN_BYTES;
use serde_json::Value;

/// Every string `value` holds, one per line, at most
/// [`MAX_INJECTED_SCAN_BYTES`] (plus the last newline); a string is cut at a
/// character boundary. Object keys are the tool's field names, not its
/// output, so they are left out.
pub(crate) fn text_of(value: &Value) -> String {
    let mut out = String::new();
    collect(value, &mut out);
    out
}

fn collect(value: &Value, out: &mut String) {
    if out.len() >= MAX_INJECTED_SCAN_BYTES {
        return;
    }
    match value {
        Value::String(text) => {
            let room = MAX_INJECTED_SCAN_BYTES - out.len();
            let mut end = text.len().min(room);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            out.push_str(&text[..end]);
            out.push('\n');
        }
        Value::Array(items) => items.iter().for_each(|v| collect(v, out)),
        Value::Object(fields) => fields.values().for_each(|v| collect(v, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn every_string_once_and_no_key() {
        let text = text_of(&json!({"stdout": "a", "n": 1, "list": ["b", {"c": "d"}]}));
        let mut lines = text.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        assert_eq!(lines, ["a", "b", "d"]);
        assert!(!text.contains("stdout"));
    }

    #[test]
    fn the_text_is_bounded_at_a_character_boundary() {
        let big = Value::String("é".repeat(MAX_INJECTED_SCAN_BYTES));
        let text = text_of(&json!([big.clone(), big]));
        assert!(text.len() <= MAX_INJECTED_SCAN_BYTES + 1, "{}", text.len());
    }
}
