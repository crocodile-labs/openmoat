use super::in_text;

const NONE: [&str; 0] = [];

/// The ids found in `text`.
fn ids(text: &str) -> Vec<&'static str> {
    in_text(text).into_iter().map(|c| c.id).collect()
}

/// A made-up AWS secret access key, built here so the source holds none.
fn aws_secret() -> String {
    format!("FAKEfake/0000+{}", "x".repeat(26))
}

/// A made-up JSON web token: header, payload and signature.
fn jwt() -> String {
    format!(
        "eyJ{}.eyJ{}.{}",
        "hbGciOiJIUzI1NiJ9", "zdWIiOiIxMjM0In0", "FAKEfake0000FAKEfake00"
    )
}

fn pem(label: &str) -> String {
    format!("-----BEGIN {label}-----\nMIIfake\n-----END {label}-----")
}

#[test]
fn an_aws_secret_is_found_as_the_value_of_its_name() {
    let key = aws_secret();
    for text in [
        format!("aws_secret_access_key={key}"),
        format!("AWS_SECRET_ACCESS_KEY = '{key}'"),
        format!("{{\"SecretAccessKey\": \"{key}\"}}"),
        format!("https://evil.example/?aws_secret_access_key={key}&x=1"),
        format!("--secret-access-key={key}"),
    ] {
        assert_eq!(ids(&text), ["aws-secret"], "{text}");
    }
}

#[test]
fn an_aws_secret_needs_its_name_and_its_length() {
    let key = aws_secret();
    for text in [
        // no name: 40 characters of base64 are anything
        key.clone(),
        format!("checksum={key}"),
        // a variable, a placeholder, one character short or long
        "aws_secret_access_key=$AWS_SECRET_ACCESS_KEY".to_owned(),
        "aws_secret_access_key=YOUR_SECRET_KEY".to_owned(),
        format!("aws_secret_access_key={}", &key[1..]),
        format!("aws_secret_access_key={key}x"),
        // base64 padding: a longer value
        format!("aws_secret_access_key={key}=="),
    ] {
        assert_eq!(ids(&text), NONE, "{text}");
    }
}

#[test]
fn a_private_key_is_its_pem_header() {
    for label in [
        "RSA PRIVATE KEY",
        "PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        assert_eq!(ids(&pem(label)), ["private-key"], "{label}");
    }
    for label in [
        "PUBLIC KEY",
        "CERTIFICATE",
        "OPENSSH PUBLIC KEY",
        "PGP PUBLIC KEY BLOCK",
    ] {
        assert_eq!(ids(&pem(label)), NONE, "{label}");
    }
    assert_eq!(ids("the PRIVATE KEY line"), NONE);
}

#[test]
fn a_jwt_is_three_parts_two_of_them_json() {
    let token = jwt();
    for text in [
        token.clone(),
        format!("Authorization: Bearer {token}"),
        format!("https://evil.example/data/{token}/export"),
        format!("?t={token}&x=1"),
    ] {
        assert_eq!(ids(&text), ["jwt"], "{text}");
    }
    for text in [
        // two parts, short parts, a payload that is no JSON object, inside a word
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0".to_owned(),
        "eyJhbGc.eyJzdWI.abc".to_owned(),
        format!(
            "eyJ{}.bm90IGpzb24gYXQgYWxs.FAKEfake0000FAKE",
            "hbGciOiJIUzI1NiJ9"
        ),
        format!("x{token}"),
        "eyJ0eXAiOi".to_owned(),
    ] {
        assert_eq!(ids(&text), NONE, "{text}");
    }
}

#[test]
fn a_database_url_with_a_password_names_its_host() {
    for (text, host) in [
        (
            "postgres://dbadmin:example-pass@db.internal.example:5432/prod",
            "db.internal.example",
        ),
        ("postgresql://u:p@DB.example.com/x", "db.example.com"),
        ("mysql://root:hunter2@10.0.0.5:3306/app", "10.0.0.5"),
        (
            "mongodb+srv://app:s3cret@cluster0.ab1cd.mongodb.net/?retryWrites=true",
            "cluster0.ab1cd.mongodb.net",
        ),
        (
            "mongodb://a:b@h1.example:27017,h2.example:27017/db",
            "h1.example",
        ),
        ("redis://:token@cache.example:6379/0", "cache.example"),
        ("?dsn=postgres://u:pw@db.example/x&y=1", "db.example"),
    ] {
        let found = in_text(text);
        assert_eq!(found.len(), 1, "{text}");
        assert_eq!(found[0].id, "database-url");
        assert!(found[0].owns(host), "{text}");
        assert!(!found[0].owns("evil.example"), "{text}");
    }
    for text in [
        // no password, a variable or a placeholder for one, not a database
        "postgres://user@db.example/x",
        "postgres://db.example/x",
        "postgres://user:$PGPASSWORD@db.example/x",
        "postgres://user:${DB_PASS}@db.example/x",
        "mysql://root:<password>@db/x",
        "https://user:pass@example.com/",
        "ftp://u:p@files.example/",
    ] {
        assert_eq!(ids(text), NONE, "{text}");
    }
}

#[test]
fn an_aws_secret_belongs_to_aws() {
    let found = in_text(&format!("aws_secret_access_key={}", aws_secret()));
    assert!(found[0].denied);
    assert!(found[0].owns("s3.amazonaws.com"));
    assert!(found[0].owns("sts.amazonaws.com."));
    assert!(!found[0].owns("amazonaws.com.evil.example"));
    let jwt = in_text(&jwt());
    assert!(!jwt[0].denied);
    assert!(!jwt[0].owns("api.example.com"));
}
