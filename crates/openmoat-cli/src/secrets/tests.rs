use openmoat_core::Policy;

use super::*;

/// Generated for the test; no real secret is used.
const VALUE: &str = "fake-file-secret-5d0c1b";

fn policy(source: &str) -> Policy {
    Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: t\n    host: a.test\n    header: X-Key\n    \
         source: {source}\n"
    ))
    .unwrap()
}

#[test]
fn a_home_file_is_read_without_its_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".config")).unwrap();
    std::fs::write(dir.path().join(".config/t"), format!("{VALUE}\r\n")).unwrap();
    let home = dir.path().to_str().unwrap().replace('\\', "/");
    let p = policy("{ file: ~/.config/t }");
    // Kept, the `\r\n` would have been refused as control characters.
    let (b, refresher) = broker(&p, &home).unwrap();
    assert!(b.leak("b.test", VALUE.as_bytes()).is_some());
    let known = refresher.known().unwrap();
    assert_eq!(known.redact(&format!("x{VALUE}x")), "x[redacted]x");
    // The guard reads it too, and skips what it cannot read.
    let known = super::known(&p.secrets, &home).unwrap();
    assert_eq!(known.redact(VALUE), "[redacted]");
    let missing = super::known(&policy("{ file: ~/nope }").secrets, &home).unwrap();
    assert_eq!(missing.redact(VALUE), VALUE);
}

#[test]
fn a_missing_or_unusable_source_names_the_secret_not_a_value() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_str().unwrap().replace('\\', "/");
    let missing = broker(&policy("{ file: ~/nope }"), &home).unwrap_err();
    assert!(
        format!("{missing:#}").contains("reading secret `t`"),
        "{missing:#}"
    );
    std::fs::write(dir.path().join("bad"), "a\0b").unwrap();
    let bad = broker(&policy("{ file: ~/bad }"), &home).unwrap_err();
    assert!(format!("{bad:#}").contains("control character"), "{bad:#}");
    assert!(!format!("{bad:#}").contains("a\0b"));
    let env = broker(&policy("{ env: MOAT_TEST_UNSET_9F3A }"), &home).unwrap_err();
    assert!(
        format!("{env:#}").contains("MOAT_TEST_UNSET_9F3A is not set"),
        "{env:#}"
    );
}

/// A `command` source runs in the proxy only, gives the broker its value with
/// a deadline, and the value is masked in the audit log, never logged.
#[cfg(unix)]
#[test]
fn a_command_source_is_run_by_the_proxy_alone() {
    use std::time::Duration;

    const CMD_VALUE: &str = "fake-command-secret-9e41d0";
    let stand = stand::Stand::new();
    let marker = format!("{}/ran", stand.root);
    // `/bin/sh` only an administrator can change: no deny rule is needed.
    let p = policy(&format!(
        "\n      command: {{ run: [/bin/sh, -c, 'touch {marker}; echo {CMD_VALUE}'], \
         lifetime: 10m }}"
    ));
    // The guard, audit delivery and a sandbox's broker never run it.
    assert_eq!(
        super::known(&p.secrets, &stand.root)
            .unwrap()
            .redact(CMD_VALUE),
        CMD_VALUE
    );
    let error = format!("{:#}", read(&p.secrets[0].source, &stand.root).unwrap_err());
    assert!(error.contains("run by `openmoat proxy` only"), "{error}");
    assert!(!std::path::Path::new(&marker).exists());
    let (b, refresher) = broker(&p, &stand.root).unwrap();
    assert!(std::path::Path::new(&marker).exists());
    let left = b.rotation("t").unwrap().remaining().unwrap();
    assert!(
        left > Duration::from_secs(590) && left <= Duration::from_secs(600),
        "{left:?}"
    );
    assert_eq!(b.leak("b.test", CMD_VALUE.as_bytes()).unwrap().id, "t");
    let known = refresher.known().unwrap();
    assert_eq!(known.redact(&format!("x{CMD_VALUE}x")), "x[redacted]x");
    // A program of the person's own with no deny rule could be changed by the
    // agent: the proxy does not start, and does not run it.
    let path = stand.script("cmd", &format!("touch {marker}-2"));
    let open = policy(&format!(
        "\n      command: {{ run: ['{}'], lifetime: 10m }}",
        path.display()
    ));
    let error = format!("{:#}", broker(&open, &stand.root).unwrap_err());
    assert!(error.contains("reading secret `t`"), "{error}");
    assert!(error.contains("could be changed by the agent"), "{error}");
    assert!(!std::path::Path::new(&format!("{marker}-2")).exists());
}
