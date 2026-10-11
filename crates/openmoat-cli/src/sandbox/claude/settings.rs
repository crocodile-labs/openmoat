//! Merging the generated block into Claude Code's user settings, and reading
//! it back for `moat doctor`.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::deny_list::{deny_rules_in_sync, is_owned_rule, write_deny_rules};
use super::owned::{OWNED, strip_stale};
use super::{BLOCK_READS, Generated};

/// Merge `generated` into the settings document `root`, keeping every key
/// OpenMoat does not own. `owned` holds the `permissions.deny` rules an earlier
/// apply added (`hosts.json`): they are replaced, and on return `owned` holds
/// the rules this one added. Returns whether anything changed.
pub fn apply(root: &mut Value, generated: &Generated, owned: &mut Vec<String>) -> Result<bool> {
    let Value::Object(top) = root else {
        bail!("the settings file is not a JSON object");
    };
    let before = top.clone();
    let sandbox = object_at(top, "sandbox")?;
    strip_stale(sandbox, generated);
    for (key, value) in &generated.sandbox {
        match value {
            Value::Object(owned) => {
                let nested = object_at(sandbox, key)?;
                for (sub, v) in owned {
                    nested.insert(sub.clone(), v.clone());
                }
            }
            other => {
                sandbox.insert(key.clone(), other.clone());
            }
        }
    }
    if generated.block_reads {
        object_at(top, "permissions")?.insert(BLOCK_READS.into(), json!(true));
    }
    write_deny_rules(top, generated, owned)?;
    Ok(*top != before)
}

/// Whether `rule` is spelled the way earlier versions wrote their Linux
/// `permissions.deny` rules: `Read(./**/…)`, `Edit(./<name>)` naming one
/// working-directory entry, or `Edit(./.<dir>/<name>)` naming one entry of a
/// hidden directory there.
pub(super) fn is_linux_spelling(rule: &Value) -> bool {
    let entry = |name: &str| !name.is_empty() && !name.contains(['/', ')', '*', '?', '[', '{']);
    rule.as_str().is_some_and(|r| {
        r.starts_with("Read(./**/")
            || r.strip_prefix("Edit(./")
                .and_then(|r| r.strip_suffix(')'))
                .is_some_and(|path| match path.split_once('/') {
                    None => entry(path),
                    Some((dir, name)) => dir.starts_with('.') && entry(dir) && entry(name),
                })
    })
}

/// Remove OpenMoat's rules from `permissions.deny`, and the list when that
/// empties it. Returns whether anything was removed.
pub(super) fn strip_deny_rules(permissions: &mut Map<String, Value>, owned: &[String]) -> bool {
    let Some(Value::Array(deny)) = permissions.get_mut("deny") else {
        return false;
    };
    let before = deny.len();
    deny.retain(|rule| !is_owned_rule(rule, owned));
    let removed = deny.len() != before;
    if removed && deny.is_empty() {
        permissions.remove("deny");
    }
    removed
}

/// The inverse of [`apply`]: remove every key OpenMoat writes and the
/// `permissions.deny` rules it added (`owned`), then the objects that leaves
/// empty. Works without a policy, so `moat uninstall` never needs one. Returns
/// whether anything was removed.
pub fn remove(root: &mut Value, owned: &[String]) -> bool {
    let Value::Object(top) = root else {
        return false;
    };
    let mut removed = false;
    if let Some(Value::Object(sandbox)) = top.get_mut("sandbox") {
        for (key, subs) in OWNED {
            if subs.is_empty() {
                removed |= sandbox.remove(*key).is_some();
            } else if let Some(Value::Object(nested)) = sandbox.get_mut(*key) {
                let before = nested.len();
                nested.retain(|sub, _| !subs.contains(&sub.as_str()));
                if nested.len() != before {
                    removed = true;
                    if nested.is_empty() {
                        sandbox.remove(*key);
                    }
                }
            }
        }
    }
    if let Some(Value::Object(permissions)) = top.get_mut("permissions") {
        removed |= permissions.remove(BLOCK_READS).is_some();
        removed |= strip_deny_rules(permissions, owned);
    }
    if removed {
        for key in ["sandbox", "permissions"] {
            if top
                .get(key)
                .and_then(Value::as_object)
                .is_some_and(Map::is_empty)
            {
                top.remove(key);
            }
        }
    }
    removed
}

/// Deny sandboxed writes to the settings files next to `settings`, wherever
/// `CLAUDE_CONFIG_DIR` puts them: the policy names only `~/.claude`, and OpenMoat
/// pins this file.
pub fn protect(generated: &mut Generated, settings: &Path) {
    let Some(dir) = settings.parent() else {
        return;
    };
    let deny = generated
        .sandbox
        .get_mut("filesystem")
        .and_then(|f| f.get_mut("denyWrite"))
        .and_then(Value::as_array_mut);
    if let Some(deny) = deny {
        for name in ["settings.json", "settings.local.json"] {
            let path = json!(crate::context::path_string(&dir.join(name)));
            if !deny.contains(&path) {
                deny.push(path);
            }
        }
    }
}

/// Whether every key OpenMoat owns in `root` has its generated value, with
/// `ours` the `permissions.deny` rules it recorded adding.
pub fn in_sync(root: &Value, generated: &Generated, ours: &[String]) -> bool {
    let owned = generated.sandbox.iter().all(|(key, value)| match value {
        Value::Object(owned) => owned
            .iter()
            .all(|(sub, v)| root.pointer(&format!("/sandbox/{key}/{sub}")) == Some(v)),
        other => root.pointer(&format!("/sandbox/{key}")) == Some(other),
    });
    owned
        && (!generated.block_reads || block_reads_on(root))
        && deny_rules_in_sync(root, generated, ours)
}

fn block_reads_on(root: &Value) -> bool {
    root.pointer(&format!("/permissions/{BLOCK_READS}")) == Some(&json!(true))
}

/// Settings in `root` that weaken the sandbox, worded for `moat doctor`.
pub fn weaknesses(root: &Value, expect_block_reads: bool, proxy_port: Option<u16>) -> Vec<String> {
    let at = |path: &str| root.pointer(path);
    let is = |path: &str, value: bool| at(path) == Some(&json!(value));
    let mut out = Vec::new();
    for key in ["httpProxyPort", "socksProxyPort"] {
        let set = at(&format!("/sandbox/network/{key}")).filter(|v| !v.is_null());
        match proxy_port {
            Some(port) if set != Some(&json!(port)) => out.push(format!(
                "sandbox.network.{key} is not {port}: that traffic does not go through `moat proxy`"
            )),
            None if set.is_some() => out.push(format!(
                "sandbox.network.{key} is set: another proxy decides that traffic, not the allowlist"
            )),
            _ => {}
        }
    }
    let mut flag = |bad: bool, text: &str| {
        if bad {
            out.push(text.to_owned());
        }
    };
    flag(
        !is("/sandbox/enabled", true),
        "sandbox.enabled is not true: Bash runs unsandboxed",
    );
    flag(
        !is("/sandbox/failIfUnavailable", true),
        "sandbox.failIfUnavailable is not true: commands run unsandboxed when the sandbox cannot start",
    );
    flag(
        !is("/sandbox/allowUnsandboxedCommands", false),
        "sandbox.allowUnsandboxedCommands is not false: the model may run a command outside the sandbox",
    );
    flag(
        at("/sandbox/excludedCommands")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
        "sandbox.excludedCommands is not empty: those commands run unsandboxed",
    );
    flag(
        !is("/sandbox/network/strictAllowlist", true),
        "sandbox.network.strictAllowlist is not true: unlisted hosts prompt instead of failing",
    );
    for (path, text) in [
        (
            "/sandbox/filesystem/disabled",
            "sandbox.filesystem.disabled turns file isolation off",
        ),
        (
            "/sandbox/network/allowAllUnixSockets",
            "sandbox.network.allowAllUnixSockets opens every Unix socket",
        ),
        (
            "/sandbox/enableWeakerNetworkIsolation",
            "sandbox.enableWeakerNetworkIsolation is on",
        ),
        (
            "/sandbox/enableWeakerNestedSandbox",
            "sandbox.enableWeakerNestedSandbox is on",
        ),
    ] {
        flag(is(path, true), text);
    }
    flag(
        at("/sandbox/ignoreViolations").is_some_and(|v| !v.is_null()),
        "sandbox.ignoreViolations hides sandbox violations",
    );
    flag(
        expect_block_reads && !block_reads_on(root),
        "permissions.blockReadsOutsideWorkingDirectories is not true: sandboxed commands read the whole home directory",
    );
    out
}

pub(super) fn object_at<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>> {
    match map.entry(key).or_insert_with(|| Value::Object(Map::new())) {
        Value::Object(nested) => Ok(nested),
        _ => bail!("`{key}` in the settings file is not an object"),
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::DEFAULT_POLICY;
    use serde_json::{Value, json};

    use super::super::tests::{generated, generated_for};
    use super::*;

    #[test]
    fn apply_keeps_user_keys_and_is_idempotent() {
        let mut owned = Vec::new();
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({
            "theme": "dark",
            "hooks": { "PreToolUse": [] },
            "permissions": { "allow": ["Bash(ls)"] },
            "sandbox": { "autoAllowBashIfSandboxed": false, "network": { "allowUnixSockets": ["/x.sock"] } },
        });
        assert!(!in_sync(&root, &out, &owned));
        assert!(apply(&mut root, &out, &mut owned).unwrap());
        assert!(
            !apply(&mut root, &out, &mut owned).unwrap(),
            "second apply changes nothing"
        );
        assert!(in_sync(&root, &out, &owned));
        assert_eq!(root["theme"], "dark");
        assert_eq!(root["permissions"]["allow"], json!(["Bash(ls)"]));
        assert_eq!(root["permissions"][BLOCK_READS], json!(true));
        assert_eq!(root["sandbox"]["autoAllowBashIfSandboxed"], json!(false));
        assert_eq!(
            root["sandbox"]["network"]["allowUnixSockets"],
            json!(["/x.sock"])
        );
        assert!(
            weaknesses(&root, true, None).is_empty(),
            "{:?}",
            weaknesses(&root, true, None)
        );
        assert!(apply(&mut json!([]), &out, &mut Vec::new()).is_err());
        assert!(apply(&mut json!({"sandbox": 1}), &out, &mut Vec::new()).is_err());
    }

    #[test]
    fn remove_undoes_apply_and_keeps_user_keys() {
        let mut owned = Vec::new();
        let original = json!({
            "theme": "dark",
            "permissions": { "allow": ["Bash(ls)"] },
            "sandbox": { "autoAllowBashIfSandboxed": false, "network": { "allowUnixSockets": ["/x.sock"] } },
        });
        let mut root = original.clone();
        apply(&mut root, &generated(DEFAULT_POLICY), &mut owned).unwrap();
        assert!(remove(&mut root, &owned));
        assert_eq!(root, original);
        assert!(!remove(&mut root, &owned));

        let mut root = json!({});
        apply(
            &mut root,
            &generated("version: 1\nsandbox:\n  proxy_port: 18555\n"),
            &mut owned,
        )
        .unwrap();
        assert!(remove(&mut root, &owned));
        assert_eq!(root, json!({}), "every key apply writes is owned");
    }

    #[test]
    fn linux_deny_rules_join_the_user_deny_list_and_leave_with_uninstall() {
        let mut owned = Vec::new();
        let out = generated_for(DEFAULT_POLICY, true);
        let user = [
            "Read(~/secret)",
            "Edit(./src/**)",
            "Edit(//tmp/x)",
            "Edit(./src/main.rs)",
            "Edit(./.vscode/a/b)",
        ];
        let mut deny = user.to_vec();
        deny.extend(["Read(./**/old)", "Edit(./old)", "Edit(./.old/hooks.json)"]);
        let mut root = json!({ "permissions": { "deny": deny } });
        assert!(apply(&mut root, &out, &mut owned).unwrap());
        assert!(!apply(&mut root, &out, &mut owned).unwrap(), "idempotent");
        assert!(in_sync(&root, &out, &owned));
        let mut expected: Vec<Value> = user.iter().map(|r| json!(r)).collect();
        expected.extend(out.deny_rules.iter().map(|r| json!(r)));
        assert_eq!(
            root["permissions"]["deny"],
            json!(expected),
            "stale rules go"
        );
        assert!(
            !in_sync(&root, &generated(DEFAULT_POLICY), &owned),
            "rules macOS does not write"
        );
        assert!(remove(&mut root, &owned));
        assert_eq!(root, json!({ "permissions": { "deny": user } }));

        let mut root = json!({});
        apply(&mut root, &out, &mut owned).unwrap();
        assert!(remove(&mut root, &owned));
        assert_eq!(root, json!({}), "the deny list it created goes too");
        assert!(
            apply(
                &mut json!({ "permissions": { "deny": {} } }),
                &out,
                &mut Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn weaknesses_name_every_weakened_setting() {
        let mut owned = Vec::new();
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({});
        apply(&mut root, &out, &mut owned).unwrap();
        root["sandbox"]["enabled"] = json!(false);
        root["sandbox"]["failIfUnavailable"] = Value::Null;
        root["sandbox"]["allowUnsandboxedCommands"] = json!(true);
        root["sandbox"]["excludedCommands"] = json!(["curl"]);
        root["sandbox"]["network"]["allowAllUnixSockets"] = json!(true);
        root["permissions"][BLOCK_READS] = json!(false);
        root["sandbox"]["network"]["httpProxyPort"] = json!(8080);
        let found = weaknesses(&root, true, None).join("\n");
        for key in [
            "httpProxyPort is set",
            "sandbox.enabled",
            "failIfUnavailable",
            "allowUnsandboxedCommands",
            "excludedCommands",
            "allowAllUnixSockets",
            BLOCK_READS,
        ] {
            assert!(found.contains(key), "{key}: {found}");
        }
        assert!(!in_sync(&root, &out, &owned));
    }

    #[test]
    fn weaknesses_name_a_changed_or_missing_moat_proxy_port() {
        let mut owned = Vec::new();
        let out = generated("version: 1\nsandbox:\n  proxy_port: 18555\n");
        let mut root = json!({});
        apply(&mut root, &out, &mut owned).unwrap();
        assert!(weaknesses(&root, false, Some(18555)).is_empty());
        root["sandbox"]["network"]["httpProxyPort"] = json!(8080);
        let network = root["sandbox"]["network"].as_object_mut().unwrap();
        network.remove("socksProxyPort");
        let found = weaknesses(&root, false, Some(18555)).join("\n");
        for key in ["httpProxyPort is not 18555", "socksProxyPort is not 18555"] {
            assert!(found.contains(key), "{key}: {found}");
        }
        assert!(!in_sync(&root, &out, &owned));
    }

    #[test]
    fn protect_denies_writes_to_the_settings_moat_pins() {
        let mut out = generated(DEFAULT_POLICY);
        protect(&mut out, Path::new("/cfg/claude/settings.json"));
        protect(&mut out, Path::new("/cfg/claude/settings.json"));
        let deny = &out.sandbox["filesystem"]["denyWrite"];
        let count = |p: &str| deny.as_array().unwrap().iter().filter(|v| *v == p).count();
        assert_eq!(count("/cfg/claude/settings.json"), 1, "once, however often");
        assert_eq!(count("/cfg/claude/settings.local.json"), 1);
    }

    const WITH_SECRET: &str = "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n";

    #[test]
    fn apply_writes_credentials_and_tls_terminate_from_the_policy() {
        let mut owned = Vec::new();
        let out = generated(WITH_SECRET);
        let aws = json!([{ "idName": "A", "secretName": "B" }]);
        let mut root = json!({ "sandbox": { "credentials": { "awsPairs": aws.clone() } } });
        assert!(apply(&mut root, &out, &mut owned).unwrap());
        assert!(!apply(&mut root, &out, &mut owned).unwrap(), "idempotent");
        assert!(in_sync(&root, &out, &owned));
        assert_eq!(root["sandbox"]["network"]["tlsTerminate"], json!({}));
        let env = &root["sandbox"]["credentials"]["envVars"][0];
        assert_eq!(env["name"], json!("GITHUB_TOKEN"));
        assert_eq!(env["mode"], json!("mask"));
        assert_eq!(
            root["sandbox"]["credentials"]["awsPairs"], aws,
            "user keys survive"
        );
        assert!(remove(&mut root, &owned));
        assert_eq!(
            root,
            json!({ "sandbox": { "credentials": { "awsPairs": aws } } })
        );
    }

    #[test]
    fn dropping_a_secret_strips_the_stale_mask_entry_and_tls_terminate() {
        let mut owned = Vec::new();
        let with = generated(WITH_SECRET);
        let without = generated(DEFAULT_POLICY);
        let mut root = json!({});
        apply(&mut root, &with, &mut owned).unwrap();
        assert!(root["sandbox"].get("credentials").is_some());
        assert_eq!(root["sandbox"]["network"]["tlsTerminate"], json!({}));
        assert!(
            apply(&mut root, &without, &mut owned).unwrap(),
            "removes the stale keys"
        );
        assert!(root["sandbox"].get("credentials").is_none());
        assert!(root["sandbox"]["network"].get("tlsTerminate").is_none());
        assert!(in_sync(&root, &without, &owned));
    }
}
