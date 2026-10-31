//! Refuse hook input accidentally delivered to the home screen.

use std::io::Read as _;

pub(super) fn detected() -> bool {
    let stdin = std::io::stdin();
    if crate::terminal::interactive() {
        return false;
    }
    let mut input = String::new();
    // Bound the home screen's input just like guard input. A truncated or
    // unreadable stream must not turn an accidental hook into success.
    if stdin
        .take(1024 * 1024 + 1)
        .read_to_string(&mut input)
        .is_err()
        || input.len() > 1024 * 1024
    {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(&input).is_ok_and(|value| {
        value
            .as_object()
            .is_some_and(|v| v.contains_key("hook_event_name"))
    })
}
