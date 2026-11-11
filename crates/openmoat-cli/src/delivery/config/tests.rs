use super::*;

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    // Any name: the state directory is wherever the home says.
    let home = Home::at(dir.path().join("state"));
    (dir, home)
}

fn inside(home: &Home, name: &str) -> String {
    home.root().join(name).to_string_lossy().replace('\\', "/")
}

fn two_sinks(home: &Home) -> String {
    format!(
        "version: 1\nmachine: build-01\nsinks:\n  - id: collector\n    otlp: \
         http://127.0.0.1:4318/v1/logs\n    headers:\n      - name: Authorization\n        \
         prefix: \"Bearer \"\n        value: {{ file: '{token}' }}\n  - id: siem\n    \
         webhook: https://siem.example/openmoat\n    secret: {{ file: '{key}' }}\n    \
         ca_file: '{ca}'\n",
        token = inside(home, "delivery/token"),
        key = inside(home, "delivery/hook.key"),
        ca = inside(home, "delivery/ca.pem"),
    )
}

#[test]
fn a_configuration_with_both_kinds_reads() {
    let (_dir, home) = home();
    let config = parse(&two_sinks(&home), &home).unwrap();
    assert_eq!(config.machine, "build-01");
    assert_eq!(config.start, Start::New);
    assert_eq!(config.max_backlog, DEFAULT_MAX_BACKLOG);
    assert_eq!(config.batch_bytes, DEFAULT_BATCH_BYTES);
    assert_eq!(config.sinks.len(), 2);
    assert_eq!(config.sinks[0].kind, Kind::Otlp);
    assert_eq!(config.sinks[0].headers[0].prefix, "Bearer ");
    assert_eq!(config.sinks[1].kind, Kind::Webhook);
    assert!(config.sinks[1].secret.is_some());
    assert!(config.sinks[1].ca_file.is_some());
}

/// Each change to a valid configuration that must be refused.
#[test]
fn what_could_send_the_log_elsewhere_or_leak_a_key_is_refused() {
    let (_dir, home) = home();
    let good = two_sinks(&home);
    let outside = std::env::temp_dir()
        .join("elsewhere.key")
        .to_string_lossy()
        .replace('\\', "/");
    let cases: Vec<(&str, String)> = vec![
        (
            "env source",
            good.replace("{ file: '", "{ env: 'X")
                .replace(".key' }", "' }"),
        ),
        (
            "file outside the state dir",
            good.replace(&inside(&home, "delivery/hook.key"), &outside),
        ),
        (
            "key in the state dir, outside delivery/, which the agent can read",
            good.replace("delivery/hook.key", "hook.key"),
        ),
        (
            "token in the state dir, outside delivery/",
            good.replace("delivery/token", "policy.d/token"),
        ),
        (
            "a .. out of the state dir",
            good.replace("delivery/hook.key", "../elsewhere.key"),
        ),
        (
            "ca outside the state dir",
            good.replace(&inside(&home, "delivery/ca.pem"), &outside),
        ),
        (
            "webhook over plain http",
            good.replace("https://siem.example", "http://127.0.0.1:9"),
        ),
        (
            "plain http off the machine",
            good.replace("http://127.0.0.1:4318", "http://collector.example:4318"),
        ),
        (
            "webhook without a key",
            good.replace(
                &format!(
                    "    secret: {{ file: '{}' }}\n",
                    inside(&home, "delivery/hook.key")
                ),
                "",
            ),
        ),
        (
            "an unknown key",
            good.replace("machine:", "extra: 1\nmachine:"),
        ),
        ("version 2", good.replace("version: 1", "version: 2")),
        (
            "two kinds in one sink",
            good.replace("    webhook:", "    otlp: https://a.example/\n    webhook:"),
        ),
        ("same id twice", good.replace("id: siem", "id: collector")),
        ("an id with capitals", good.replace("id: siem", "id: SIEM")),
        (
            "a machine with a space",
            good.replace("build-01", "'build 01'"),
        ),
        (
            "backlog too small",
            good.replace("machine:", "max_backlog: 10\nmachine:"),
        ),
        (
            "batch too large",
            good.replace("machine:", "batch_bytes: 99999999999\nmachine:"),
        ),
        (
            "own header name",
            good.replace("name: Authorization", "name: X-OpenMoat-Signature"),
        ),
        (
            "credentials in the URL",
            good.replace("https://siem.example", "https://u:p@siem.example"),
        ),
        (
            "metadata service",
            good.replace("https://siem.example", "https://metadata.google.internal"),
        ),
        ("no sinks", "version: 1\nmachine: a\nsinks: []\n".to_owned()),
    ];
    for (what, text) in cases {
        assert_ne!(text, good, "{what}: the case changed nothing");
        assert!(parse(&text, &home).is_err(), "{what}: {text}");
    }
}

#[test]
fn a_secret_on_an_otlp_sink_is_refused_it_would_sign_nothing() {
    let (_dir, home) = home();
    let text = format!(
        "version: 1\nmachine: m\nsinks:\n  - id: c\n    otlp: https://c.example/v1/logs\n    \
         secret: {{ file: '{}' }}\n",
        inside(&home, "k")
    );
    assert!(parse(&text, &home).is_err());
}

#[test]
fn more_than_the_most_sinks_is_refused() {
    let (_dir, home) = home();
    let mut text = "version: 1\nmachine: m\nsinks:\n".to_owned();
    for i in 0..=MAX_SINKS {
        text.push_str("  - id: s");
        text.push_str(&i.to_string());
        text.push_str("\n    otlp: https://c.example/v1/logs\n");
    }
    assert!(parse(&text, &home).is_err());
}

#[test]
fn an_unpinned_or_changed_file_sends_nothing() {
    let (_dir, home) = home();
    std::fs::create_dir_all(home.root()).unwrap();
    // No file: delivery is off.
    std::fs::write(home.lock_path(), lock_json(None)).unwrap();
    assert!(load_pinned(&home).unwrap().is_none());
    let text = two_sinks(&home);
    std::fs::write(home.delivery_config_path(), &text).unwrap();
    let error = load_pinned(&home).unwrap_err().to_string();
    assert!(error.contains("not pinned"), "{error}");
    let pinned = sha256_hex(text.as_bytes());
    std::fs::write(home.lock_path(), lock_json(Some((&home, &pinned)))).unwrap();
    assert!(load_pinned(&home).unwrap().is_some());
    std::fs::write(
        home.delivery_config_path(),
        text.replace("build-01", "build-02"),
    )
    .unwrap();
    let error = load_pinned(&home).unwrap_err().to_string();
    assert!(error.contains("changed since"), "{error}");
}

/// A lock pinning the delivery file at `digest`, or nothing.
fn lock_json(pin: Option<(&Home, &str)>) -> String {
    let mut entries = serde_json::Map::new();
    if let Some((home, digest)) = pin {
        let path = home.delivery_config_path();
        let key = std::fs::canonicalize(path.parent().unwrap())
            .unwrap()
            .join(path.file_name().unwrap());
        let key = crate::context::strip_verbatim(&key.to_string_lossy());
        entries.insert(key, digest.into());
    }
    serde_json::json!({
        "version": 1, "pinned_at_ms": 0, "binary": "/x/openmoat", "entries": entries,
    })
    .to_string()
}
