use openmoat_core::Policy;
use serde_json::json;

use super::super::apply;
use super::super::tests::generated;
use super::*;

const SECRETS: &str = "version: 1\n\
     allow:\n  - id: a\n    net: ['api.github.com', 'api.example.com']\n\
     secrets:\n  \
     - id: gh\n    host: api.github.com\n    header: Authorization\n    source: { env: GITHUB_TOKEN }\n  \
     - id: cfg\n    host: api.example.com\n    header: X-Api-Key\n    source: { file: /Users/me/.config/x/key }\n  \
     - id: off\n    host: unlisted.example.org\n    header: X-Api-Key\n    source: { env: OFF_TOKEN }\n";

fn synced(yaml: &str) -> (Policy, Generated, Value) {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let out = generated(yaml);
    let mut root = json!({});
    apply(&mut root, &out, &mut Vec::new()).expect("applies");
    (policy, out, root)
}

fn names(states: &[(&Secret, Mask)]) -> Vec<(String, Mask)> {
    states
        .iter()
        .map(|(s, m)| (s.id.clone(), m.clone()))
        .collect()
}

#[test]
fn a_synced_settings_file_masks_each_secret_the_generator_writes() {
    let (policy, out, root) = synced(SECRETS);
    let linux = names(&states(&root, &policy.secrets, &out.report, false));
    assert_eq!(linux[0], ("gh".to_owned(), Mask::Active));
    assert_eq!(linux[1], ("cfg".to_owned(), Mask::Active));
    assert!(
        matches!(&linux[2].1, Mask::Skipped(why) if why.contains("not in `net` allow")),
        "{linux:?}"
    );
    let macos = names(&states(&root, &policy.secrets, &out.report, true));
    assert_eq!(macos[0].1, Mask::Active);
    assert_eq!(macos[1].1, Mask::FileDenied, "macOS denies a file mask");
    assert!(Mask::FileDenied.describe().contains("macOS"));
}

#[test]
fn a_missing_entry_or_tls_terminate_is_not_masked() {
    let (policy, out, mut root) = synced(SECRETS);
    root["sandbox"]["network"]
        .as_object_mut()
        .unwrap()
        .remove("tlsTerminate");
    let found = names(&states(&root, &policy.secrets, &out.report, false));
    assert_eq!(
        (&found[0].1, &found[1].1),
        (&Mask::NotWritten, &Mask::NotWritten)
    );

    let (_, _, mut root) = synced(SECRETS);
    root["sandbox"]["credentials"]["envVars"][0]["injectHosts"] = json!(["evil.example"]);
    let found = names(&states(&root, &policy.secrets, &out.report, false));
    assert_eq!(found[0].1, Mask::NotWritten, "another host is not ours");
    assert_eq!(found[1].1, Mask::Active);

    let found = names(&states(&json!({}), &policy.secrets, &out.report, false));
    assert_eq!(found[0].1, Mask::NotWritten, "never synced");
    assert!(Mask::NotWritten.describe().contains("moat sandbox sync"));
}

#[test]
fn a_keychain_source_is_skipped_with_its_loss() {
    let yaml = "version: 1\n\
         allow:\n  - id: a\n    net: ['api.github.com']\n\
         secrets:\n  \
         - id: kc\n    host: api.github.com\n    header: Authorization\n    \
         source: { keychain: { service: gh, account: me } }\n";
    let (policy, out, root) = synced(yaml);
    let found = names(&states(&root, &policy.secrets, &out.report, false));
    assert!(
        matches!(&found[0].1, Mask::Skipped(why) if why.contains("keychain")),
        "{found:?}"
    );
    assert!(
        root["sandbox"].get("credentials").is_none(),
        "nothing to mask, so no block and no tlsTerminate"
    );
    assert!(root["sandbox"]["network"].get("tlsTerminate").is_none());
}

#[test]
fn a_hand_set_plaintext_inject_is_a_weakness_unless_the_policy_lifts_it() {
    let (_, out, mut root) = synced(SECRETS);
    assert!(weaknesses(&root, &out).is_empty());
    root["sandbox"]["credentials"]["allowPlaintextInject"] = json!(true);
    let found = weaknesses(&root, &out).join("\n");
    assert!(found.contains("allowPlaintextInject"), "{found}");

    let plain = "version: 1\n\
         allow:\n  - id: a\n    net: ['api.example.com']\n\
         secrets:\n  \
         - id: p\n    host: api.example.com\n    header: X-Api-Key\n    source: { env: P_TOKEN }\n    plain_http: true\n";
    let (_, out, root) = synced(plain);
    assert_eq!(
        root["sandbox"]["credentials"]["allowPlaintextInject"],
        json!(true)
    );
    assert!(
        weaknesses(&root, &out).is_empty(),
        "the policy asked for it"
    );

    let none = generated("version: 1\n");
    let user = json!({ "sandbox": { "credentials": { "allowPlaintextInject": true } } });
    assert!(
        weaknesses(&user, &none).is_empty(),
        "the user's own block, no secret of ours in it"
    );
}
