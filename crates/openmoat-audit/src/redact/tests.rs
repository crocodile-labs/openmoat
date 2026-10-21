use super::{
    KnownSecrets, PATTERNS, SHAPES, TOKEN_SHAPES, mask_patterns, redact, redact_value, rules,
    token_shape,
};
use serde_json::json;

#[test]
fn every_pattern_compiles() {
    assert!(
        PATTERNS
            .as_ref()
            .is_some_and(|p| p.len() == rules().count())
    );
    assert!(
        SHAPES
            .as_ref()
            .is_some_and(|p| p.len() == TOKEN_SHAPES.len())
    );
}

#[test]
fn token_shapes_are_named_and_ordinary_text_has_none() {
    assert_eq!(
        token_shape("+ key = \"AKIAIOSFODNN7EXAMPLE\""),
        Some("an AWS access key id")
    );
    assert_eq!(
        token_shape("x=ghp_abcdefghijklmnopqrstuvwxyz0123"),
        Some("a GitHub token")
    );
    for key in [
        "sk-ant-api03-FAKE_fake-0000FAKEfake0000-FAKEfake",
        "sk-proj-FAKE_fake-0000FAKEfake0000",
    ] {
        assert_eq!(
            token_shape(&format!("k={key}")),
            Some("an OpenAI or Anthropic key")
        );
        assert_eq!(redact(&format!("k={key}")), "k=[redacted]");
    }
    for text in [
        "fn main() {}",
        "token: ${{ secrets.X }}",
        "sk-short",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl",
    ] {
        assert_eq!(token_shape(text), None, "{text}");
    }
    let known = KnownSecrets::new([FAKE]).unwrap();
    assert!(known.occurs_in(&format!("+v={}", FAKE.to_ascii_uppercase())));
    assert!(!known.occurs_in("+v=other"));
    assert!(!KnownSecrets::default().occurs_in(FAKE));
}

#[test]
fn without_patterns_nothing_is_kept() {
    let text = "export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123".to_owned();
    assert_eq!(mask_patterns(None, text), "[redacted]");
}

#[test]
fn redacts_string_leaves_of_a_document() {
    let doc = json!({"shell": {"command": "curl -H \"X-Api-Key: abc123def456\" https://x", "n": 1, "list": ["token=ghp_abcdefghijklmnopqrstuvwxyz0123"]}});
    let out = redact_value(doc);
    let text = out.to_string();
    assert!(!text.contains("abc123def456"), "{text}");
    assert!(!text.contains("ghp_abc"), "{text}");
    assert!(text.contains("X-Api-Key: [redacted]"), "{text}");
    assert_eq!(out["shell"]["n"], 1);
}

#[test]
fn named_credentials_keep_their_key() {
    assert_eq!(
        redact("curl -H 'X-Api-Key: abc123def'"),
        "curl -H 'X-Api-Key: [redacted]'"
    );
    assert_eq!(
        redact("export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123"),
        "export TOKEN=[redacted]"
    );
    assert_eq!(
        redact("password=hunter2 user=bob"),
        "password=[redacted] user=bob"
    );
}

#[test]
fn credential_words_inside_longer_names() {
    for (text, want) in [
        (
            "AWS_SECRET_ACCESS_KEY=wJalrFAKEfakeKEY aws s3 ls",
            "AWS_SECRET_ACCESS_KEY=[redacted] aws s3 ls",
        ),
        (
            "GH_TOKEN=abc123 gh pr list",
            "GH_TOKEN=[redacted] gh pr list",
        ),
        ("export NPM_TOKEN='abc123'", "export NPM_TOKEN='[redacted]'"),
        (
            "DATABASE_PASSWORD=hunter2 ./run",
            "DATABASE_PASSWORD=[redacted] ./run",
        ),
        ("MY_TOKEN: abc123", "MY_TOKEN: [redacted]"),
        (
            "curl 'https://x.test/?access_token=abc123&n=1'",
            "curl 'https://x.test/?access_token=[redacted]&n=1'",
        ),
        ("tool --token=abc123", "tool --token=[redacted]"),
        ("tool --token abc123 -v", "tool --token [redacted] -v"),
        (
            "psql --db-password \"abc123\"",
            "psql --db-password \"[redacted]\"",
        ),
        (
            "curl -u alice:s3cret https://x.test",
            "curl -u alice:[redacted] https://x.test",
        ),
        (
            "curl --user=alice:s3cret x.test",
            "curl --user=alice:[redacted] x.test",
        ),
        (
            "curl --user 'alice:s3cret' x.test",
            "curl --user 'alice:[redacted]' x.test",
        ),
    ] {
        assert_eq!(redact(text), want, "{text}");
        assert_eq!(redact(want), want, "{want}");
    }
}

#[test]
fn words_that_only_start_with_a_credential_word_are_kept() {
    for text in [
        "tokenizer=bpe max_tokens=100",
        "the secretary: Jane",
        "passwords are hashed",
        "gh auth login --with-token < token.txt",
        "docker login --password-stdin registry.example",
        "tool --token --verbose",
        "git push -u origin main",
        "sort -u names.txt",
    ] {
        assert_eq!(redact(text), text);
    }
}

#[test]
fn well_known_token_shapes() {
    assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "[redacted]");
    assert_eq!(
        redact("Authorization: Bearer abc.def-ghi_jkl"),
        "Authorization: Bearer [redacted]"
    );
    assert!(redact("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX").contains("[redacted]"));
    assert_eq!(
        redact("https://user:s3cret@host.example/x"),
        "https://user:[redacted]@host.example/x"
    );
}

#[test]
fn ordinary_commands_are_untouched() {
    for cmd in [
        "git status --short",
        "cargo test -p openmoat-core",
        "echo token",
        "cat ~/.ssh/id_rsa",
    ] {
        assert_eq!(redact(cmd), cmd);
    }
}

/// Generated for the test; no real secret is used.
const FAKE: &str = "q7Zp-fake-9xK2mW4v";

#[test]
fn known_values_are_masked_whatever_their_format() {
    let known = KnownSecrets::new([FAKE, "q7Zp-fake-9xK2mW4v-longer", "short"]).unwrap();
    let text = format!("curl https://x.test/?k={FAKE}&n=1 /tmp/{FAKE}-longer/f short");
    assert_eq!(
        known.redact(&text),
        "curl https://x.test/?k=[redacted]&n=1 /tmp/[redacted]/f short"
    );
    let host = format!("http://{}.x.test:80", FAKE.to_ascii_lowercase());
    assert_eq!(known.redact(&host), "http://[redacted].x.test:80");
    let doc = known.redact_value(json!({"mcp": {"args": [FAKE]}}));
    assert_eq!(doc["mcp"]["args"][0], "[redacted]");
    assert_eq!(format!("{known:?}"), "KnownSecrets");
    assert_eq!(KnownSecrets::default().redact(FAKE), FAKE);
}

#[test]
fn idempotent() {
    let once = redact("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123");
    assert_eq!(redact(&once), once);
}

/// Each case is redacted to `want`, and redacting `want` changes nothing.
fn redacts(cases: &[(&str, &str)]) {
    for (text, want) in cases {
        assert_eq!(redact(text), *want, "{text}");
        assert_eq!(redact(want), *want, "{want}");
    }
}

#[test]
fn names_about_a_credential_keep_their_value() {
    for text in [
        "token_count=1200",
        "tool --token-file=/run/secrets/t",
        "password_file=/etc/app/pw",
        "PRIVATE_KEY_PATH=~/.keys/deploy.pem",
        "secret_name: prod-db",
        "api_key_id=42 token_type=bearer",
        "--token-dir=/tmp/t -v",
    ] {
        assert_eq!(redact(text), text);
    }
    redacts(&[
        ("token_value=abc123", "token_value=[redacted]"),
        (
            "password_files_dir_x=abc",
            "password_files_dir_x=[redacted]",
        ),
        ("GH_TOKEN_SECRET=abc123", "GH_TOKEN_SECRET=[redacted]"),
        ("token_count_secret=abc", "token_count_secret=[redacted]"),
    ]);
}

#[test]
fn user_option_masks_a_password_not_a_path_or_ids() {
    for text in [
        "python -u C:\\work\\run.py",
        "python3 -u C:/work/run.py",
        "docker run -u 1000:1000 alpine",
    ] {
        assert_eq!(redact(text), text);
    }
    redacts(&[
        (
            "curl -u alice:s3cret https://x.test",
            "curl -u alice:[redacted] https://x.test",
        ),
        (
            "sudo /usr/bin/curl -u 1000:1000 https://x.test",
            "sudo /usr/bin/curl -u 1000:[redacted] https://x.test",
        ),
        (
            "curl.exe -u C:\\x x.test",
            "curl.exe -u C:[redacted] x.test",
        ),
        ("tool -u admin:hunter2", "tool -u admin:[redacted]"),
        (
            "docker run -u root:wheel x",
            "docker run -u root:[redacted] x",
        ),
    ]);
}

#[test]
fn scheme_names_in_prose_are_kept() {
    for text in [
        "uses bearer authentication for the API",
        "Basic credentials are sent base64 encoded",
        "a Bearer header is required by the standard",
    ] {
        assert_eq!(redact(text), text);
    }
    redacts(&[
        ("-H 'X: Bearer abcdefgh12'", "-H 'X: Bearer [redacted]'"),
        ("bearer abcdefghijkl", "Bearer [redacted]"),
        ("Basic dXNlcjpwYXNz", "Basic [redacted]"),
    ]);
}

#[test]
fn quoted_keys_mask_their_quoted_value() {
    redacts(&[
        (r#"{"token":"x"}"#, r#"{"token":"[redacted]"}"#),
        (
            r#"echo '{"password": "a b \"c\""}' | jq"#,
            r#"echo '{"password": "[redacted]"}' | jq"#,
        ),
        (
            "python3 -c \"d={'api_key': 'abc'}\"",
            "python3 -c \"d={'api_key': '[redacted]'}\"",
        ),
        (r#"{"GH_TOKEN" : "abc"}"#, r#"{"GH_TOKEN" : "[redacted]"}"#),
    ]);
    for text in [
        r#"{"token_count": "12", "max_tokens": "100"}"#,
        r#"{"tokenizer": "bpe", "secretary": "Jane"}"#,
        r#"{"token": ""}"#,
    ] {
        assert_eq!(redact(text), text);
    }
    let doc = redact_value(json!({"command": r#"curl -d '{"password":"hunter22"}' x.test"#}));
    assert!(!doc.to_string().contains("hunter22"), "{doc}");
}

#[test]
fn a_quoted_value_with_spaces_is_masked_whole() {
    for text in [
        r#"export DB_PASSWORD="correct horse battery staple""#,
        "export DB_PASSWORD='correct horse battery staple'",
        "mysql --password 'correct horse battery staple' db",
        r#"curl -u "alice:correct horse battery staple" x.test"#,
    ] {
        let out = redact(text);
        for word in ["correct", "horse", "battery", "staple"] {
            assert!(!out.contains(word), "{text} -> {out}");
        }
        assert_eq!(redact(&out), out, "idempotent");
    }
}
