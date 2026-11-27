//! The gate changes no redaction: on every text below, and on each one
//! upper-cased, lower-cased and with a non-ASCII letter case folding equates
//! with an ASCII one, [`redact`] gives what running every pattern on it gives.

use regex::{Captures, Regex};

use super::super::{Mask, rules};
use super::redact;

/// Every pattern run on `text` in order, none passed by.
fn ungated(text: &str) -> String {
    rules().fold(text.to_owned(), |acc, rule| {
        let re = Regex::new(rule.pattern).unwrap();
        match rule.mask {
            Mask::Text(replacement) => re.replace_all(&acc, replacement).into_owned(),
            Mask::With(replace) => re
                .replace_all(&acc, |caps: &Captures<'_>| replace(caps, &acc))
                .into_owned(),
        }
    })
}

/// Texts each pattern masks, near misses, and texts a hook call records.
const CORPUS: &[&str] = &[
    "git status",
    "s-me",
    "toolu_01ABC",
    "/Users/me/proj/src/main.rs",
    "no rule matched read /Users/me/proj/README.md",
    "export GITHUB_TOKEN=abcdef123456",
    "DB_PASSWORD=\"a b c\" ./run",
    "DB_PASSWORD='a b c' ./run",
    "curl --api-key \"k e y\" https://x",
    "curl --api-key 'k e y' https://x",
    "curl -u \"me:pass word\" https://x",
    "curl -u me:hunter22 https://x",
    "git push -u origin main",
    "{\"token\": \"abc def\"}",
    "{'password': 'a b'}",
    "mytool --db-password s3cr3tvalue --next",
    "mytool --password-stdin < f",
    "Authorization: Bearer abcdefgh12345678",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    "PGPASSWORD=s3cret psql",
    "MYSQL_PWD=s3cret mysql",
    "OPENAI_KEY=abc123 node app.js",
    "REDISCLI_AUTH=abc redis-cli",
    "sort_key=1 PWD=/x OLDPWD=/y",
    "mysql -uroot -ps3cret db",
    "7z a -psecret x.7z f",
    "sshpass -p hunter22 ssh host",
    "docker login -p hunter22 registry",
    "helm registry login -p hunter22 r",
    "crane auth login -p hunter22 r",
    "redis-cli -a hunter22 ping",
    "redis-cli --pass hunter22 ping",
    "openssl enc -k hunter22 -in f",
    "openssl enc -pass pass:hunter22 -in f",
    "openssl enc -passin env:VAR",
    "zip -P hunter22 x.zip f",
    "htpasswd -bc file user hunter22",
    "htpasswd -nb user hunter22",
    "aws configure set aws_secret_access_key abc123",
    "aws configure set --profile p p.aws_session_token abc123",
    "Cookie: session=abc123",
    "Set-Cookie: id=1; Path=/",
    "fix cookie: expiry",
    "curl -b name=value https://x",
    "curl --cookie name=value https://x",
    "tar -b 20 -cf x.tar f",
    "https://hooks.slack.com/services/T000/B000/XXXX",
    "https://discord.com/api/webhooks/123/abc_def",
    "https://abcdef0123456789abcdef@o1.ingest.sentry.io/1",
    "ssh://git@host/repo",
    "https://user:pass@example.com/x",
    "x=ghp_abcdefghijklmnopqrstuvwxyz0123",
    "github_pat_abcdefghijklmnopqrstuvwxyz",
    "k=sk-ant-api03-FAKE_fake-0000FAKEfake0000-FAKEfake",
    "k=sk-abcdefghijklmnop1234",
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-1234567890-abcdef",
    "AIzaabcdefghijklmnopqrstuvwxyz0123456",
    "npm_abcdefghijklmnopqrstuvwxyz0123456",
    "glpat-abcdefghijklmnopqrst",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl",
    "tokenizer secretary max_tokens token_count --token-file private_key_path",
    "a token: here and a password = there; api_key=1234 access-key: 9 secret-key=x",
    "",
];

/// `text`, then the same with each `s` and `k` replaced by the non-ASCII
/// letters case folding equates with them, upper-cased and lower-cased.
fn variants(text: &str) -> Vec<String> {
    let folded: String = text
        .chars()
        .map(|c| match c {
            's' => '\u{17F}',
            'k' => '\u{212A}',
            c => c,
        })
        .collect();
    vec![
        text.to_owned(),
        text.to_ascii_uppercase(),
        text.to_ascii_lowercase(),
        folded,
        format!("é {text}"),
    ]
}

#[test]
fn the_gate_changes_no_redaction() {
    for text in CORPUS {
        for variant in variants(text) {
            assert_eq!(redact(&variant), ungated(&variant), "{variant:?}");
        }
    }
}

#[test]
fn a_non_ascii_text_goes_to_the_patterns() {
    // `ſ` is `s` under case folding: the named credential pattern masks it.
    let text = "PAſſWORD=hunter22";
    assert_eq!(redact(text), ungated(text));
    assert!(!redact(text).contains("hunter22"), "{}", redact(text));
}
