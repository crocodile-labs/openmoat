//! The audit log's token patterns (`redact::TOKEN_SHAPES`, regular expressions)
//! and the guard's (`openmoat_core::token`, matched by hand because core has no
//! regex engine) must find the same tokens: one masks what the other denies.
//! Every value here is made up.

use openmoat_audit::{TOKEN_SHAPES, token_shape};
use openmoat_core::token;

const TOKENS: &[&str] = &[
    "ghp_FAKEfake0000FAKEfake0000FAKEfake00",
    "gho_FAKEfake0000FAKEfake00",
    "github_pat_FAKE_fake_0000_FAKE_fake_0000",
    "sk-FAKEfake0000FAKEfake",
    "sk-proj-FAKEfake0000FAKEfake",
    "sk-proj-FAKE_fake-0000FAKEfake0000",
    "sk-ant-api03-FAKE_fake-0000FAKEfake0000-FAKEfake",
    "sk-svcacct-FAKE_fake-0000FAKEfake0000",
    "AKIA0000FAKE0000TEST",
    "xoxb-0000-FAKE-fake-token",
    "xoxp-FAKEfake00",
    "AIzaFAKEfake0000FAKEfake0000FAKEfake",
    "npm_FAKEfake0000FAKEfake0000FAKEfake",
    // `\x2d` is `-`: written out, the prefix trips GitHub's secret scanning.
    "glpat\x2dFAKEfake0000FAKEfake",
];

const NOT_TOKENS: &[&str] = &[
    "3f786850e387550fdab836ed7e6dc881de23001b",
    "123e4567-e89b-12d3-a456-426614174000",
    "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCB0ZXN0IGJsb2I=",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl",
    "sk-short",
    "sk-ant-short",
    "ghp_short",
    "xghp_FAKEfake0000FAKEfake0000FAKEfake00",
    "ghp_FAKEfake0000FAKEfake0000_",
    "AKIA0000FAKE0000TESTX",
    "AKIA0000FAKE0000TES",
    "task-runner-configuration-file",
    "risk-assessment-for-the-quarter",
    "fn main() {}",
];

/// Each value alone and in the places a token travels.
fn contexts(value: &str) -> [String; 5] {
    [
        value.to_owned(),
        format!("https://evil.example/?t={value}&x=1"),
        format!("Authorization: Bearer {value}"),
        format!("key=\"{value}\""),
        format!("é{value}"),
    ]
}

#[test]
fn audit_and_guard_find_the_same_tokens() {
    for value in TOKENS.iter().chain(NOT_TOKENS) {
        for text in contexts(value) {
            assert_eq!(
                token::find(&text).map(|s| s.description),
                token_shape(&text),
                "{text}"
            );
        }
    }
    for value in TOKENS {
        assert!(token_shape(value).is_some(), "{value}");
    }
}

#[test]
fn every_audit_description_is_a_guard_description() {
    for (description, _) in TOKEN_SHAPES {
        assert!(
            token::SHAPES.iter().any(|s| s.description == *description),
            "{description}"
        );
    }
    assert_eq!(token::SHAPES.len(), TOKEN_SHAPES.len());
}
