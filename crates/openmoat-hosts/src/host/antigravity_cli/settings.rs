//! Antigravity CLI's `settings.json` (`/docs/permissions`, `/docs/settings`):
//! `toolPermission: always-proceed` is what `--dangerously-skip-permissions`
//! corresponds to, which "auto-approves all tool permission requests".

use serde_json::Value;

/// The setting in `doc` that lets a call run with no person asked.
pub(super) fn approves_unseen(doc: &Value) -> Option<&'static str> {
    (doc.get("toolPermission").and_then(Value::as_str) == Some("always-proceed"))
        .then_some("`toolPermission: always-proceed`")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn only_always_proceed_runs_unseen() {
        assert!(approves_unseen(&json!({"toolPermission": "always-proceed"})).is_some());
        for fine in [json!({"toolPermission": "request-review"}), json!({}), json!([])] {
            assert_eq!(approves_unseen(&fine), None, "{fine}");
        }
    }
}
