//! Credentials in the shapes of `redact/programs.rs`. Every made-up value is
//! built at run time, so none reads as a real one in the source.

use super::{redact, redacts};

/// A made-up password of `n` characters.
fn pw(n: usize) -> String {
    "hX7q".chars().cycle().take(n).collect()
}

#[test]
fn passwords_given_to_well_known_programs_are_masked() {
    let p = pw(15);
    let cases: Vec<(String, String)> = [
        ("mysql -u root -p{p} db", "mysql -u root -p[redacted] db"),
        (
            "mysqldump -p'{p}' db > d.sql",
            "mysqldump -p[redacted] db > d.sql",
        ),
        (
            "/usr/bin/mariadb -h x -p{p}",
            "/usr/bin/mariadb -h x -p[redacted]",
        ),
        ("7z a -p{p} out.7z dir", "7z a -p[redacted] out.7z dir"),
        (
            "sshpass -p '{p}' ssh host",
            "sshpass -p [redacted] ssh host",
        ),
        (
            "sshpass -p{p} scp f host:",
            "sshpass -p[redacted] scp f host:",
        ),
        (
            "docker login -u bob -p {p} reg.io",
            "docker login -u bob -p [redacted] reg.io",
        ),
        (
            "podman login reg.io -p {p}",
            "podman login reg.io -p [redacted]",
        ),
        (
            "helm registry login r.io -u u -p {p}",
            "helm registry login r.io -u u -p [redacted]",
        ),
        (
            "redis-cli -h db -a {p} ping",
            "redis-cli -h db -a [redacted] ping",
        ),
        (
            "redis-cli --pass {p} get k",
            "redis-cli --pass [redacted] get k",
        ),
        (
            "openssl enc -aes256 -k {p} -in f",
            "openssl enc -aes256 -k [redacted] -in f",
        ),
        (
            "openssl pkcs12 -passin pass:{p} -in c.p12",
            "openssl pkcs12 -passin pass:[redacted] -in c.p12",
        ),
        (
            "openssl rsa -passout 'pass:{p}' -out k",
            "openssl rsa -passout 'pass:[redacted]' -out k",
        ),
        (
            "zip -r -P {p} out.zip dir",
            "zip -r -P [redacted] out.zip dir",
        ),
        ("unzip -P \"{p}\" x.zip", "unzip -P [redacted] x.zip"),
        (
            "htpasswd -b .htpasswd bob {p}",
            "htpasswd -b .htpasswd bob [redacted]",
        ),
        (
            "htpasswd -bc f bob '{p} x' && ls",
            "htpasswd -bc f bob [redacted] && ls",
        ),
        ("htpasswd -nb bob {p}", "htpasswd -nb bob [redacted]"),
        (
            "aws configure set aws_secret_access_key {p}",
            "aws configure set aws_secret_access_key [redacted]",
        ),
        (
            "aws configure set profile.ci.aws_session_token {p}",
            "aws configure set profile.ci.aws_session_token [redacted]",
        ),
    ]
    .iter()
    .map(|(text, want)| (text.replace("{p}", &p), (*want).to_owned()))
    .collect();
    let cases: Vec<(&str, &str)> = cases
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    redacts(&cases);
}

#[test]
fn environment_names_ending_in_a_credential_word_are_masked() {
    let p = pw(15);
    let cases: Vec<(String, String)> = [
        (
            "PGPASSWORD={p} psql -h db",
            "PGPASSWORD=[redacted] psql -h db",
        ),
        ("MYSQL_PWD={p} mysql", "MYSQL_PWD=[redacted] mysql"),
        ("export OPENAI_KEY={p}", "export OPENAI_KEY=[redacted]"),
        (
            "export STRIPE_SECRET='{p}'",
            "export STRIPE_SECRET='[redacted]'",
        ),
        (
            "env REDISCLI_AUTH={p} redis-cli",
            "env REDISCLI_AUTH=[redacted] redis-cli",
        ),
        (
            "A=1 SMTP_PASS=\"{p}\" ./send",
            "A=1 SMTP_PASS=\"[redacted]\" ./send",
        ),
        ("PGPASS={p} ./x", "PGPASS=[redacted] ./x"),
    ]
    .iter()
    .map(|(text, want)| (text.replace("{p}", &p), (*want).to_owned()))
    .collect();
    let cases: Vec<(&str, &str)> = cases
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    redacts(&cases);
}

#[test]
fn cookies_webhooks_and_keys_in_urls_are_masked() {
    let session = format!("{}{}", "7f3a".repeat(6), "e1");
    let slack = format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        "0A1B".repeat(2),
        "2C3D".repeat(2),
        pw(24)
    );
    let discord = format!(
        "https://discord.com/api/webhooks/{}/{}",
        "1234".repeat(4),
        pw(40)
    );
    let dsn_key = "ab12".repeat(8);
    let git_token = format!("tok{}", "9z".repeat(12));
    let cases: Vec<(String, String)> = vec![
        (
            format!("curl -H 'Cookie: session={session}; theme=dark' https://x.test"),
            "curl -H 'Cookie: [redacted]' https://x.test".to_owned(),
        ),
        (
            format!("Set-Cookie: sid={session}; Path=/; HttpOnly"),
            "Set-Cookie: [redacted]".to_owned(),
        ),
        (
            format!("curl -b 'sid={session}' https://x.test"),
            "curl -b '[redacted]' https://x.test".to_owned(),
        ),
        (
            format!("curl -X POST -d '{{}}' {slack}"),
            "curl -X POST -d '{}' https://hooks.slack.com/services/[redacted]".to_owned(),
        ),
        (
            format!("curl {discord}"),
            "curl https://discord.com/api/webhooks/[redacted]".to_owned(),
        ),
        (
            format!("SENTRY_DSN=https://{dsn_key}@o1.ingest.sentry.io/1 ./run"),
            "SENTRY_DSN=https://[redacted]@o1.ingest.sentry.io/1 ./run".to_owned(),
        ),
        (
            format!("git clone https://{git_token}@github.com/o/r.git"),
            "git clone https://[redacted]@github.com/o/r.git".to_owned(),
        ),
        (
            format!("git clone https://bob:{}@git.example/r", pw(12)),
            "git clone https://bob:[redacted]@git.example/r".to_owned(),
        ),
    ];
    let cases: Vec<(&str, &str)> = cases
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    redacts(&cases);
}

/// Everyday commands that share a flag or a word with the rules above keep
/// every character.
#[test]
fn ordinary_commands_with_the_same_flags_are_untouched() {
    for text in [
        "cargo test -p openmoat-core -p openmoat",
        "ssh -p 2222 me@host",
        "scp -P 2222 f host:",
        "mkdir -p a/b/c",
        "docker run -p 8080:80 nginx",
        "docker compose -p proj up -d",
        "docker ps -a",
        "docker login -u bob reg.io",
        "docker login --password-stdin reg.io",
        "mysql -u root -p",
        "mysql -u root -p db",
        "mysql -h db -P 3306 -u app",
        "ps -p 1234 -o pid",
        "pgrep -a node",
        "zip -r out.zip dir",
        "unzip -o x.zip -d out",
        "wget https://x.test/f.zip -P downloads",
        "7z x archive.7z -oout",
        "openssl rand -hex 16",
        "openssl s_client -connect host:443",
        "openssl enc -d -kfile key.txt -in f",
        "openssl pkcs12 -passin env:P12_PASS -in c.p12",
        "redis-cli -h localhost -n 2 get key",
        "htpasswd -c .htpasswd bob",
        "htpasswd -v .htpasswd bob",
        "aws configure set region us-east-1",
        "aws configure get aws_secret_access_key",
        "echo $PWD",
        "PWD=/tmp ls",
        "cd $OLDPWD",
        "export PATH=/usr/bin:/bin",
        "NODE_ENV=production RUST_LOG=debug cargo run",
        "export GPG_TTY=$(tty)",
        "export SSH_KEY=~/.ssh/id_ed25519",
        "OPENAI_KEY=$OPENAI_KEY ./run",
        "export MONKEY=1 TURKEY=2",
        "export PUBLIC_KEY_PATH=/etc/k.pub",
        "let sort_key = x; cache_key=y",
        "git checkout -b feature/cookie",
        "git commit -m 'fix cookie: handle expiry'",
        "curl -b cookies.txt https://x.test",
        "git clone ssh://git@github.com/o/r.git",
        "git clone https://github.com/o/r",
        "curl https://hooks.slack.com/",
        "rsync -avP src/ dst/",
        "tar -cvpf x.tar dir",
        "grep -P '\\d+' f",
    ] {
        assert_eq!(redact(text), text);
    }
}
