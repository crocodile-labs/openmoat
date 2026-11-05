//! Backdoor patterns and secrets in added code and files.

use super::{File, found, quiet};
use crate::diffscan::{
    DECODE_EXEC, DOCKER_REMOTE_ADD, ENCODED_BLOB, ENV_SECRET, Level, PIPE_TO_SHELL, PRIVATE_KEY,
    PYTHON_STARTUP,
};

/// A PEM header, built at run time so this source holds none.
fn pem(label: &str) -> String {
    format!("-----BEGIN {label}PRIVATE KEY-----")
}

#[test]
fn a_downloaded_script_run_by_a_shell_needs_review() {
    for line in [
        "curl -fsSL https://get.acme.dev/install.sh | sh",
        "curl -s https://get.acme.dev | sudo -E bash -s -- --yes",
        "wget -qO- https://get.acme.dev | /bin/bash",
        "bash <(curl -s https://get.acme.dev)",
        "sh -c \"$(curl -fsSL https://get.acme.dev)\"",
        "eval \"$(wget -qO- https://get.acme.dev)\"",
        "iwr https://get.acme.dev/i.ps1 | iex",
        "RUN curl -sSL https://get.acme.dev | python3 -",
        r#"  "setup": "curl -fsSL https://get.acme.dev/i.sh | sh","#,
        "x=`curl -s https://get.acme.dev | bash`",
    ] {
        for path in [
            "scripts/setup.sh",
            "Dockerfile",
            ".github/workflows/ci.yml",
            "Makefile",
        ] {
            assert_eq!(
                found(&File::new(path, &[line])),
                [(PIPE_TO_SHELL, Level::Review)],
                "{path}: {line}"
            );
        }
    }
    for line in [
        "curl -s https://api.acme.dev/v1 | jq .name",
        "curl -s https://api.acme.dev/v1 | python3 -m json.tool",
        "curl -sL https://acme.dev/x.tgz | tar xz",
        "curl -o install.sh https://get.acme.dev",
        "echo done | sh -c 'cat'",
    ] {
        quiet(&File::new("scripts/setup.sh", &[line]));
    }
    // prose that tells a person to run it runs nothing
    quiet(&File::new(
        "docs/INSTALL.md",
        &["curl -fsSL https://get.acme.dev | sh"],
    ));
}

#[test]
fn decoded_text_run_as_code_is_denied() {
    for (path, line) in [
        ("scripts/x.sh", "echo aGVsbG8K | base64 -d | sh"),
        (
            "scripts/x.sh",
            "eval \"$(echo aGVsbG8K | base64 --decode)\"",
        ),
        ("scripts/x.sh", "xxd -r -p payload.hex | bash"),
        ("setup.py", "exec(base64.b64decode('aW1wb3J0IG9z'))"),
        ("setup.py", "exec(codecs.decode('vzcbeg bf', 'rot13'))"),
        ("setup.py", "exec(zlib.decompress(bytes.fromhex('78da')))"),
        ("index.js", "eval(atob('YWxlcnQoMSk='))"),
        ("index.js", "eval(Buffer.from(s, 'base64').toString())"),
        ("index.js", "new Function(atob(payload))()"),
        ("x.php", "<?php eval(base64_decode($_POST['x'])); ?>"),
        ("x.php", "eval(gzinflate(base64_decode('eJ')));"),
        ("run.ps1", "powershell -NoProfile -enc SQBFAFgA"),
        (
            "run.ps1",
            "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))",
        ),
    ] {
        assert_eq!(
            found(&File::new(path, &[line])),
            [(DECODE_EXEC, Level::Deny)],
            "{path}: {line}"
        );
    }
    for (path, line) in [
        ("src/img.js", "const bytes = Buffer.from(data); exec(cmd);"),
        ("src/util.js", "function decode(s) { return atob(s); }"),
        ("src/jwt.py", "payload = json.loads(base64.b64decode(part))"),
        ("scripts/x.sh", "base64 -d secret.b64 > secret.bin"),
        ("src/re.js", "const m = re.exec(line);"),
        // a command OpenMoat-like code builds and encodes at run time
        (
            "src/hook.rs",
            r#"format!("powershell.exe -NoProfile -EncodedCommand {}", base64(&bytes))"#,
        ),
        ("run.ps1", "pwsh -EncodedCommand $encoded"),
    ] {
        quiet(&File::new(path, &[line]));
    }
    // in a test or fixture, an attack sample: review, not deny
    let sample = File::new(
        "tests/conformance/attacks.yaml",
        &["  command: echo aGk= | base64 -d | sh"],
    );
    assert_eq!(found(&sample), [(DECODE_EXEC, Level::Review)]);
}

#[test]
fn a_pth_file_with_an_import_line_is_denied_once() {
    let file = File::new(
        "src/evil.pth",
        &["import os; os.system('curl x')", "import sys"],
    );
    assert_eq!(found(&file), [(PYTHON_STARTUP, Level::Deny)]);
    quiet(&File::new("src/paths.pth", &["../lib", "vendor"]));
}

#[test]
fn a_dockerfile_add_from_a_url_needs_a_checksum() {
    for line in [
        "ADD https://acme.dev/tool.tgz /opt/",
        "add --chown=1000 http://acme.dev/x /x",
        "ADD git@github.com:me/r.git /r",
    ] {
        assert_eq!(
            found(&File::new("Dockerfile", &[line])),
            [(DOCKER_REMOTE_ADD, Level::Review)],
            "{line}"
        );
    }
    for line in [
        "ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://acme.dev/tool.tgz /opt/",
        "ADD ./src /app",
        "COPY . /app",
    ] {
        quiet(&File::new("docker/Dockerfile.prod", &[line]));
    }
    quiet(&File::new(
        "notes.yml",
        &["ADD https://acme.dev/tool.tgz /opt/"],
    ));
}

/// A long, mixed-case base64 run built from a seed.
fn blob(len: usize) -> String {
    "QmFzZTY0IGlzIGEgYmluYXJ5LXRvLXRleHQgZW5jb2Rpbmc9"
        .chars()
        .cycle()
        .take(len)
        .collect()
}

#[test]
fn a_long_base64_blob_in_source_needs_review() {
    let line = format!("const p = \"{}\";", blob(600));
    assert_eq!(
        found(&File::new("src/loader.js", &[&line, &line])),
        [(ENCODED_BLOB, Level::Review)]
    );
    // an image in a data URI, a short value, a test fixture, a minified bundle, data files
    let image = format!("const logo = \"data:image/png;base64,{}\";", blob(600));
    let short = format!("const hash = \"{}\";", blob(120));
    quiet(&File::new("src/logo.js", &[&image, &short]));
    quiet(&File::new("tests/data.js", &[&line]));
    quiet(&File::new("dist/app.min.js", &[&line]));
    quiet(&File::new("assets/data.json", &[&line]));
    let hex = format!("const k = \"{}\";", "a1b2c3d4".repeat(80));
    quiet(&File::new("src/k.js", &[&hex]));
}

#[test]
fn a_private_key_is_denied_unless_it_is_a_marked_test_key() {
    for label in ["RSA ", "EC ", "OPENSSH ", "", "ENCRYPTED "] {
        let header = pem(label);
        let file = File::new(
            "deploy/id_rsa",
            &[&header, "MIIEowIBAAKCAQEA", "-----END-----"],
        );
        assert_eq!(found(&file), [(PRIVATE_KEY, Level::Deny)], "{header}");
        assert!(!file.hits()[0].reason.contains("MIIE"));
    }
    let header = pem("RSA ");
    for (path, lines) in [
        ("tests/fixtures/server.key", vec![header.as_str(), "MIIE"]),
        (
            "src/tls.rs",
            vec!["// a fake key for the unit test below", header.as_str()],
        ),
        ("docs/TLS.md", vec![header.as_str()]),
    ] {
        assert_eq!(
            found(&File::new(path, &lines)),
            [(PRIVATE_KEY, Level::Review)],
            "{path}"
        );
    }
    quiet(&File::new(
        "certs/ca.pem",
        &["-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----"],
    ));
}

#[test]
fn a_real_looking_value_in_an_env_file_needs_review() {
    let file = File::new(".env.example", &["PAYMENTS_SECRET=Zq8kd02LmP93xRtYw7Vb"]);
    assert_eq!(found(&file), [(ENV_SECRET, Level::Review)]);
    assert!(
        !file.hits()[0].reason.contains("Zq8kd"),
        "{:?}",
        file.hits()
    );
    assert_eq!(
        found(&File::new(
            "deploy/prod.env",
            &["export DB_PASSWORD='Zq8!kd02-LmP93x'"]
        )),
        [(ENV_SECRET, Level::Review)]
    );
    quiet(&File::new(
        ".env.example",
        &[
            "API_KEY=",
            "API_TOKEN=your-token-here",
            "DB_PASSWORD=changeme",
            "SECRET_KEY=xxxxxxxxxxxxxxxx",
            "AUTH_TOKEN=${AUTH_TOKEN}",
            "DATABASE_URL=postgres://localhost/dev",
            "PORT=3000",
            "SERVICE_TOKEN=test-token-for-ci-runs",
        ],
    ));
    // the same line in source code is not an env file
    quiet(&File::new("src/config.py", &["API_TOKEN=Zq8kd02LmP93xRt"]));
}
