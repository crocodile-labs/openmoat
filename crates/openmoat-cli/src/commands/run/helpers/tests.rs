use std::collections::BTreeMap;

use openmoat_core::Policy;

use super::{Helpers, aws_config, git_entries};

const POLICY: &str = "version: 1\nsecrets:\n  - id: gh-git\n    host: github.com\n    \
                      header: Authorization\n    helper: { git: { username: x-access-token } }\n    \
                      source: { env: FAKE_GH }\n  - id: s3\n    host: s3.us-east-1.amazonaws.com\n    \
                      header: X-Amz-Security-Token\n    helper: aws\n    source:\n      mint:\n        \
                      aws-sts:\n          role: arn:aws:iam::123456789012:role/agent\n          \
                      region: us-east-1\n          actions: [s3:GetObject]\n          \
                      resources: ['arn:aws:s3:::bucket/*']\n  - id: plain\n    host: api.example.com\n    \
                      header: X-Key\n    source: { env: FAKE_PLAIN }\n";

fn policy() -> Policy {
    Policy::parse(POLICY).unwrap()
}

#[test]
fn git_gets_a_reset_then_the_helper_for_the_secrets_host_only() {
    let entries = git_entries(&policy(), "/opt/open moat/openmoat");
    assert_eq!(
        entries,
        [
            (
                "credential.https://github.com.helper".to_owned(),
                String::new()
            ),
            (
                "credential.https://github.com.helper".to_owned(),
                "!'/opt/open moat/openmoat' credential git 'gh-git'".to_owned()
            ),
        ]
    );
    assert_eq!(super::quoted("it's"), r"'it'\''s'");
}

#[test]
fn aws_gets_one_profile_per_secret_and_no_value() {
    let (config, profile) = aws_config(&policy(), "/usr/local/bin/openmoat").unwrap();
    assert_eq!(profile.as_deref(), Some("openmoat-s3"));
    assert!(config.contains(
        "[profile openmoat-s3]\ncredential_process = \"/usr/local/bin/openmoat\" credential aws s3\n"
    ));
    assert!(
        !config.contains("gh-git") && !config.contains("plain"),
        "{config}"
    );
    let none = Policy::parse("version: 1\n").unwrap();
    assert!(aws_config(&none, "/m").is_none());
}

#[test]
fn a_run_sets_the_variables_and_removes_its_files() {
    let temp = tempfile::tempdir().unwrap();
    let existing: BTreeMap<&str, &str> = [("GIT_CONFIG_COUNT", "1")].into();
    let helpers = Helpers::prepare(&policy(), temp.path(), &|k| {
        existing.get(k).map(|v| (*v).to_owned())
    })
    .unwrap();
    let vars: BTreeMap<&str, &str> = helpers
        .vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(vars["GIT_CONFIG_COUNT"], "3");
    assert_eq!(
        vars["GIT_CONFIG_KEY_1"],
        "credential.https://github.com.helper"
    );
    assert_eq!(vars["GIT_CONFIG_VALUE_1"], "");
    assert!(vars["GIT_CONFIG_VALUE_2"].ends_with("credential git 'gh-git'"));
    assert_eq!(vars["AWS_PROFILE"], "openmoat-s3");
    let config = std::fs::read_to_string(vars["AWS_CONFIG_FILE"]).unwrap();
    assert!(config.contains("credential aws s3"));
    assert_eq!(
        std::fs::read_to_string(vars["AWS_SHARED_CREDENTIALS_FILE"]).unwrap(),
        ""
    );
    assert!(helpers.removed.contains(&"AWS_ACCESS_KEY_ID"));
    let dir = helpers.dir().unwrap();
    assert!(std::path::Path::new(&dir).is_dir());
    drop(helpers);
    assert!(!std::path::Path::new(&dir).exists());
    // A policy without helpers sets nothing.
    let none = Helpers::prepare(
        &Policy::parse("version: 1\n").unwrap(),
        temp.path(),
        &|_| None,
    )
    .unwrap();
    assert!(none.vars.is_empty() && none.removed.is_empty() && none.dir().is_none());
}
