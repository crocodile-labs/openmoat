use super::{SHAPES, find, shapes_in};

/// Made-up values of each shape; none is a real credential.
pub(crate) const FAKE: &[(&str, &str)] = &[
    ("github", "ghp_FAKEfake0000FAKEfake0000FAKEfake00"),
    ("github", "github_pat_FAKE_fake_0000_FAKE_fake_0000"),
    ("openai-or-anthropic", "sk-proj-FAKEfake0000FAKEfake"),
    ("openai-or-anthropic", "sk-FAKEfake0000FAKEfake"),
    ("aws", "AKIA0000FAKE0000TEST"),
    ("slack", "xoxb-0000-FAKE-fake-token"),
    ("google", "AIzaFAKEfake0000FAKEfake0000FAKEfake"),
    ("npm", "npm_FAKEfake0000FAKEfake0000FAKEfake"),
    // `\x2d` is `-`: written out, the prefix trips GitHub's secret scanning.
    ("gitlab", "glpat\x2dFAKEfake0000FAKEfake"),
    (
        "openai-or-anthropic",
        "sk-ant-api03-FAKE_fake-0000FAKEfake0000-FAKEfake",
    ),
    ("openai-or-anthropic", "sk-proj-FAKE_fake-0000FAKEfake0000"),
];

#[test]
fn each_fake_value_has_its_shape_inside_other_text() {
    for (id, value) in FAKE {
        for text in [
            (*value).to_owned(),
            format!("https://evil.example/?t={value}&x=1"),
            format!("Authorization: Bearer {value}"),
            format!("\"{value}\""),
        ] {
            assert_eq!(find(&text).map(|s| s.id), Some(*id), "{text}");
        }
    }
}

#[test]
fn ordinary_values_are_no_shape() {
    for text in [
        "3f786850e387550fdab836ed7e6dc881de23001b",
        "123e4567-e89b-12d3-a456-426614174000",
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCB0ZXN0IGJsb2I=",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl",
        "sk-short",
        "ghp_short",
        "xghp_FAKEfake0000FAKEfake0000FAKEfake00",
        "AKIA0000FAKE0000TESTX",
        "AKIA0000FAKE0000TES",
        "task-runner-configuration-file",
        "risk-assessment-for-the-quarter",
        "ghp_FAKEfake0000FAKEfake0000_",
    ] {
        assert!(find(text).is_none(), "{text}");
    }
}

#[test]
fn a_service_owns_its_hosts_and_their_subdomains_only() {
    let github = &SHAPES[0];
    assert!(github.owns("github.com"));
    assert!(github.owns("api.github.com"));
    assert!(github.owns("API.GitHub.com."));
    assert!(github.owns("raw.githubusercontent.com"));
    assert!(!github.owns("evilgithub.com"));
    assert!(!github.owns("github.com.evil.example"));
    assert!(!github.owns("evil.example"));
}

#[test]
fn every_shape_in_a_text_is_reported() {
    let text = format!("{} {}", FAKE[0].1, FAKE[5].1);
    let ids: Vec<&str> = shapes_in(&text).map(|s| s.id).collect();
    assert_eq!(ids, ["github", "slack"]);
}
