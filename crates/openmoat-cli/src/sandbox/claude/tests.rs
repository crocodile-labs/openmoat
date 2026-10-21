use openmoat_core::{DEFAULT_POLICY, Policy};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::{assert_golden, lower_for_hosts};

mod git;

pub(super) fn generated(yaml: &str) -> Generated {
    generated_for(yaml, false)
}

pub(super) fn generated_for(yaml: &str, linux: bool) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    generate(&ir, crate::sandbox::proxy_port(&policy), linux).expect("generates")
}

fn list(generated: &Generated, pointer: &str) -> Vec<String> {
    let value = Value::Object(generated.sandbox.clone());
    serde_json::from_value(value.pointer(pointer).cloned().unwrap_or(json!([]))).unwrap()
}

/// The settings and report for the default policy, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_settings() {
    let out = generated(DEFAULT_POLICY);
    let actual = serde_json::to_string_pretty(&json!({
        "sandbox": out.sandbox,
        "permissions": { BLOCK_READS: out.block_reads },
        "losses": out.report.losses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "allowances": out.report.allowances.iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_golden("claude-default.json", &(actual + "\n"));
}

#[test]
fn every_pattern_is_absolute() {
    let out = generated(DEFAULT_POLICY);
    for pointer in [
        "/filesystem/denyRead",
        "/filesystem/allowRead",
        "/filesystem/denyWrite",
    ] {
        for p in list(&out, pointer) {
            assert!(
                p.starts_with('/'),
                "{pointer}: {p} would resolve against ~/.claude"
            );
        }
    }
    let deny = list(&out, "/filesystem/denyRead");
    for expected in [
        "/**/.env",
        "/**/.env.*",
        "/Users/me/.ssh",
        "/Users/me/.cargo/credentials.toml",
    ] {
        assert!(deny.contains(&expected.to_owned()), "{expected}: {deny:?}");
    }
    assert!(list(&out, "/filesystem/allowRead").contains(&"/Users/me/.cargo".to_owned()));
    assert!(
        !list(&out, "/filesystem/allowRead")
            .iter()
            .any(|p| p.contains(".env")),
        "a `**/` exception would re-open .env.example everywhere"
    );
    assert!(out.block_reads);
}

/// #359, #372: on Linux the runtime skips `/**/.env`, so each such read deny is
/// also a `Read(./**/…)` rule, which it expands under the working directory, and
/// each `/**/<name>` write deny an `Edit(./<name>)` rule, which it keeps.
#[test]
fn linux_adds_working_directory_rules_for_wildcard_denies() {
    let mac = generated(DEFAULT_POLICY);
    let linux = generated_for(DEFAULT_POLICY, true);
    let (every_os, linux_only) = linux.deny_rules.split_at(mac.deny_rules.len());
    assert_eq!(every_os, mac.deny_rules, "the rules of every OS come first");
    assert_eq!(
        linux_only,
        [
            "Read(./**/.env)",
            "Read(./**/.env.*)",
            "Read(./**/.envrc)",
            "Read(./**/.moat/audit.db*)",
            "Read(./**/.moat/policy.lock)",
            "Edit(./.env)",
            "Edit(./.envrc)",
            "Edit(./.moat)",
            "Edit(./.cursor/hooks.json)",
            "Edit(./.cursor/sandbox.json)",
            "Edit(./.codex/hooks.json)",
            "Edit(./.copilot/hooks)",
            "Edit(./.copilot/settings.json)",
            "Edit(./.copilot/config.json)",
            "Edit(./.gemini/settings.json)",
        ],
        "another agent's hook file below a directory the policy denies writing \
         (`.cursor`, `.codex`, `.copilot`, `.gemini`) is denied by path (#434); Claude Code keeps its own \
         `.claude` settings read-only itself"
    );
    assert_eq!(linux.sandbox, mac.sandbox, "the sandbox block is the same");
    let dropped = linux
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "claude-code.linux-write-globs");
    let dropped = &dropped.expect("write globs are listed").patterns;
    for pattern in [
        "/**/.env.*",
        "/**/.moat/**",
        "/**/bin/moat",
        "/**/.git/hooks",
    ] {
        assert!(
            dropped.contains(&pattern.to_owned()),
            "{pattern}: {dropped:?}"
        );
    }
    assert!(
        !dropped.iter().any(|p| p.starts_with("/Users/me/")),
        "{dropped:?}"
    );
    for rule in [
        "claude-code.linux-read-rules",
        "claude-code.linux-read-globs",
    ] {
        let reported = linux.report.losses.iter().any(|l| l.rule == rule)
            || linux.report.allowances.iter().any(|a| a.rule == rule);
        assert!(reported, "{rule}: {:?}", linux.report);
    }
    let none = generated_for(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.ssh/**']\n    fs.write: ['~/.ssh/**']\n",
        true,
    );
    assert_eq!(
        none.deny_rules,
        ["Read(//Users/me/.ssh)", "Edit(//Users/me/.ssh)"],
        "absolute denies need no working-directory rule"
    );
    assert!(!none.report.losses.iter().any(|l| l.rule.contains("linux")));
    assert!(
        !none
            .report
            .allowances
            .iter()
            .any(|a| a.rule.contains("linux"))
    );
}

#[test]
fn directory_nodes_with_entries_below_are_left_out_and_listed() {
    let out = generated(DEFAULT_POLICY);
    let deny = list(&out, "/filesystem/denyWrite");
    assert!(
        !deny.contains(&"/**/.claude".to_owned()),
        "would make .claude/worktrees read-only"
    );
    assert!(deny.contains(&"/**/.claude/settings.json".to_owned()));
    assert!(
        deny.contains(&"/Users/me/.codex".to_owned()),
        "a tree rule keeps its directory"
    );
    let nodes = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "claude-code.directory-nodes");
    assert!(nodes.is_some_and(|a| a.patterns.contains(&"/**/.claude".to_owned())));
}

#[test]
fn network_lists_domains_and_keeps_addresses_denied() {
    let out = generated(DEFAULT_POLICY);
    let allowed = list(&out, "/network/allowedDomains");
    assert!(allowed.contains(&"registry.npmjs.org".to_owned()));
    assert!(
        !allowed.iter().any(|h| h == "localhost"),
        "an ask is a deny"
    );
    let denied = list(&out, "/network/deniedDomains");
    assert!(denied.contains(&"metadata.google.internal".to_owned()));
    assert!(!denied.iter().any(|h| h.contains("169.254")));
    assert_eq!(out.sandbox["network"]["strictAllowlist"], json!(true));
}

#[test]
fn both_proxy_ports_name_moat_proxy_only_when_the_policy_opts_in() {
    let out = generated(DEFAULT_POLICY);
    assert!(out.sandbox["network"].get("httpProxyPort").is_none());
    assert!(out.sandbox["network"].get("socksProxyPort").is_none());
    assert!(
        !out.report
            .losses
            .iter()
            .any(|l| l.rule == "claude-code.proxy")
    );
    let own = generated("version: 1\nsandbox:\n  proxy_port: 18555\n");
    assert_eq!(own.sandbox["network"]["httpProxyPort"], json!(18555));
    assert_eq!(own.sandbox["network"]["socksProxyPort"], json!(18555));
    assert!(
        own.report
            .losses
            .iter()
            .any(|l| l.rule == "claude-code.proxy" && l.message.contains("127.0.0.1:18555")),
        "{:?}",
        own.report.losses
    );
}

#[test]
fn a_read_root_inside_a_deny_is_not_reopened() {
    let out = generated(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.ssh/**']\nsandbox:\n  read_roots: ['~/.ssh/pub', '/usr']\n",
    );
    assert_eq!(list(&out, "/filesystem/allowRead"), ["/usr"]);
    assert!(
        out.report
            .losses
            .iter()
            .any(|l| l.message.contains("/Users/me/.ssh/pub"))
    );
}

/// The settings and report for a policy with one env mask and one file mask,
/// as a reviewer reads them: the paired fixture is the stable contract that
/// Claude Code sees from `moat sandbox sync`.
#[test]
fn secrets_policy_matches_the_golden_settings() {
    let out = generated(SECRETS_POLICY);
    let actual = serde_json::to_string_pretty(&json!({
        "sandbox": out.sandbox,
        "permissions": { BLOCK_READS: out.block_reads },
        "losses": out.report.losses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "allowances": out.report.allowances.iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_golden("claude-secrets.json", &(actual + "\n"));
}

const SECRETS_POLICY: &str = "version: 1\n\
     allow:\n  - id: hosts\n    net: ['api.github.com', 'registry.npmjs.org']\n\
     secrets:\n  \
     - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
     - id: npm\n    host: registry.npmjs.org\n    header: Authorization\n    source: { file: ~/.config/moat/npm }\n";

/// #363: policy `secrets:` compile into `sandbox.credentials` with the `mask`
/// mode plus `tlsTerminate`, which Claude Code's own broker needs for HTTPS
/// injection; the entry's `injectHosts` matches the policy's host.
#[test]
fn secrets_become_claude_mask_credentials() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com', 'registry.npmjs.org']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
         - id: npm\n    host: registry.npmjs.org\n    header: Authorization\n    source: { file: ~/.config/moat/npm }\n",
    );
    assert_eq!(out.sandbox["network"]["tlsTerminate"], json!({}));
    let env_vars = out.sandbox["credentials"]["envVars"].as_array().unwrap();
    assert_eq!(env_vars.len(), 1);
    assert_eq!(env_vars[0]["name"], json!("GITHUB_TOKEN"));
    assert_eq!(env_vars[0]["mode"], json!("mask"));
    assert_eq!(env_vars[0]["injectHosts"], json!(["api.github.com"]));
    let files = out.sandbox["credentials"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], json!("~/.config/moat/npm"));
    assert_eq!(files[0]["injectHosts"], json!(["registry.npmjs.org"]));
    assert!(
        out.sandbox["credentials"]
            .get("allowPlaintextInject")
            .is_none()
    );
    assert!(
        out.report
            .allowances
            .iter()
            .any(|a| a.rule == "claude-code.mask-credentials"
                && a.patterns == vec!["gh".to_owned(), "npm".to_owned()])
    );
}

/// `plain_http: true` on any mask entry turns `allowPlaintextInject` on so the
/// value may reach plain-HTTP destinations, and the allowance lists the
/// affected secrets so a reviewer sees which ones a plain-HTTP request may carry.
#[test]
fn plain_http_turns_on_allow_plaintext_inject() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['localhost']\n\
         secrets:\n  \
         - id: local\n    host: localhost\n    header: Authorization\n    source: { env: LOCAL_TOKEN }\n    plain_http: true\n",
    );
    assert_eq!(
        out.sandbox["credentials"]["allowPlaintextInject"],
        json!(true)
    );
    assert!(out.report.allowances.iter().any(
        |a| a.rule == "claude-code.plain-http-inject" && a.patterns == vec!["local".to_owned()]
    ));
}

/// `keychain` sources and secrets whose host is not in `allowedDomains` cannot
/// be injected by Claude Code's broker, so each is dropped from the mask block
/// with a loss that names the secret; the broker still works through `moat proxy`.
#[test]
fn unsupported_sources_and_unlisted_hosts_are_dropped_with_a_loss() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
         - id: kc\n    host: api.github.com\n    header: X-Api-Key\n    source: { keychain: { service: moat, account: k } }\n  \
         - id: elsewhere\n    host: example.com\n    header: Authorization\n    source: { env: EX }\n",
    );
    let env_vars = out.sandbox["credentials"]["envVars"].as_array().unwrap();
    assert_eq!(
        env_vars.len(),
        1,
        "only the env entry survives: {env_vars:?}"
    );
    assert!(out.sandbox["credentials"].get("files").is_none());
    let keychain = out.report.losses.iter().find(|l| l.rule == "secrets.kc");
    let unlisted = out
        .report
        .losses
        .iter()
        .find(|l| l.rule == "secrets.elsewhere");
    assert!(
        keychain.is_some_and(|l| l.message.contains("keychain")),
        "{:?}",
        out.report.losses
    );
    assert!(
        unlisted.is_some_and(|l| l.message.contains("`example.com` is not in `net` allow")),
        "{:?}",
        out.report.losses
    );
}

/// No `secrets:` means no `credentials` block and no `tlsTerminate`, so the
/// default policy keeps its current settings and golden fixture unchanged.
#[test]
fn no_secrets_means_no_credentials_or_tls_terminate() {
    let out = generated(DEFAULT_POLICY);
    assert!(out.sandbox.get("credentials").is_none());
    assert!(out.sandbox["network"].get("tlsTerminate").is_none());
}

/// #401: Claude Code's `allowPlaintextInject` is block-scoped, so lifting TLS
/// for a `plain_http: true` entry alongside an HTTPS-only entry would widen
/// the latter (ADR-019 lowering-widens). Mixed blocks drop the `plain_http`
/// entries from Claude Code's mask list, keep `allowPlaintextInject` out, and
/// name each dropped secret in a loss; `moat proxy` still handles them.
#[test]
fn mixed_plain_http_does_not_widen() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com', 'localhost']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
         - id: local\n    host: localhost\n    header: Authorization\n    source: { env: LOCAL_TOKEN }\n    plain_http: true\n",
    );
    let env_vars = out.sandbox["credentials"]["envVars"].as_array().unwrap();
    assert_eq!(
        env_vars.len(),
        1,
        "only the HTTPS secret survives: {env_vars:?}"
    );
    assert_eq!(env_vars[0]["name"], json!("GITHUB_TOKEN"));
    assert!(
        out.sandbox["credentials"]
            .get("allowPlaintextInject")
            .is_none(),
        "no block-scoped TLS lift in a mixed block"
    );
    let dropped = out.report.losses.iter().find(|l| l.rule == "secrets.local");
    assert!(
        dropped.is_some_and(
            |l| l.message.contains("block-scoped `allowPlaintextInject`")
                && l.message.contains("`openmoat proxy`")
        ),
        "{:?}",
        out.report.losses
    );
    assert!(
        !out.report
            .allowances
            .iter()
            .any(|a| a.rule == "claude-code.plain-http-inject"),
        "{:?}",
        out.report.allowances
    );
    let masked = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "claude-code.mask-credentials");
    assert!(masked.is_some_and(|a| a.patterns == vec!["gh".to_owned()]));
}

/// A policy where every secret is `plain_http: true` still gets
/// `allowPlaintextInject: true`: the happy path from #363 keeps working.
#[test]
fn all_plain_http_still_lifts_tls() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['localhost', 'dev.internal']\n\
         secrets:\n  \
         - id: a\n    host: localhost\n    header: Authorization\n    source: { env: A_TOKEN }\n    plain_http: true\n  \
         - id: b\n    host: dev.internal\n    header: Authorization\n    source: { env: B_TOKEN }\n    plain_http: true\n",
    );
    assert_eq!(
        out.sandbox["credentials"]["allowPlaintextInject"],
        json!(true)
    );
    let env_vars = out.sandbox["credentials"]["envVars"].as_array().unwrap();
    assert_eq!(env_vars.len(), 2);
    assert!(
        out.report
            .allowances
            .iter()
            .any(|a| a.rule == "claude-code.plain-http-inject"
                && a.patterns == vec!["a".to_owned(), "b".to_owned()])
    );
}

/// The settings and report for a mixed policy, paired with the golden fixture
/// a reviewer eyeballs: `allowPlaintextInject` is absent, the `plain_http`
/// secret is dropped, and the loss names it.
#[test]
fn mixed_plain_http_policy_matches_the_golden_settings() {
    let out = generated(
        "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com', 'localhost']\n\
         secrets:\n  \
         - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
         - id: local\n    host: localhost\n    header: Authorization\n    source: { env: LOCAL_TOKEN }\n    plain_http: true\n",
    );
    let actual = serde_json::to_string_pretty(&json!({
        "sandbox": out.sandbox,
        "permissions": { BLOCK_READS: out.block_reads },
        "losses": out.report.losses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "allowances": out.report.allowances.iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_golden("claude-mixed-plain-http.json", &(actual + "\n"));
}
