//! OpenMoat's rules in the `permissions.deny` list of Claude Code's user
//! settings, which it shares with the user's own. A rule is OpenMoat's when
//! `hosts.json` records adding it, so `moat uninstall` takes no rule of the
//! user's, even one spelled the same; versions before that record are known
//! by the spelling of their Linux rules.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::Generated;
use super::settings::{is_linux_spelling, object_at, strip_deny_rules};

/// Replace the `permissions.deny` rules OpenMoat added with `generated`'s.
/// A rule the list already holds is the user's and stays out of `owned`, so
/// [`super::remove`] never takes it.
pub(super) fn write_deny_rules(
    top: &mut Map<String, Value>,
    generated: &Generated,
    owned: &mut Vec<String>,
) -> Result<()> {
    if let Some(Value::Object(permissions)) = top.get_mut("permissions") {
        strip_deny_rules(permissions, owned);
    }
    owned.clear();
    if generated.deny_rules.is_empty() {
        return Ok(());
    }
    let deny = object_at(top, "permissions")?
        .entry("deny")
        .or_insert_with(|| json!([]));
    let Value::Array(deny) = deny else {
        bail!("`permissions.deny` in the settings file is not an array");
    };
    for rule in &generated.deny_rules {
        if !deny.iter().any(|r| r == rule.as_str()) {
            deny.push(json!(rule));
            owned.push(rule.clone());
        }
    }
    Ok(())
}

/// Whether `rule` is OpenMoat's: one it recorded adding (`owned`), or one
/// spelled the way versions before that record wrote theirs, on Linux only.
pub(super) fn is_owned_rule(rule: &Value, owned: &[String]) -> bool {
    rule.as_str().is_some_and(|r| owned.iter().any(|o| o == r)) || is_linux_spelling(rule)
}

/// Whether `permissions.deny` holds every rule of `generated` and no other
/// rule of OpenMoat's (`owned`, or an earlier version's Linux spelling).
pub(super) fn deny_rules_in_sync(root: &Value, generated: &Generated, owned: &[String]) -> bool {
    let deny: Vec<&Value> = root
        .pointer("/permissions/deny")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    generated
        .deny_rules
        .iter()
        .all(|rule| deny.iter().any(|r| *r == rule.as_str()))
        && deny
            .iter()
            .filter(|rule| is_owned_rule(rule, owned))
            .all(|rule| generated.deny_rules.iter().any(|g| *rule == g.as_str()))
}

#[cfg(test)]
mod tests;
