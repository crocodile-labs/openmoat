use std::time::Duration;

use super::parse;

/// Generated stand-ins; no real secret is used anywhere in these tests.
const VALUE: &str = "fake-cmd-token-7f3a91";

const LIFETIME: Duration = Duration::from_mins(15);
const NOW: u64 = 1_800_000_000;

#[test]
fn a_plain_answer_is_the_value_for_the_whole_lifetime() {
    let answer = parse(format!("{VALUE}\r\n").as_bytes(), LIFETIME, NOW).unwrap();
    assert_eq!(answer.value.as_str(), VALUE);
    assert_eq!(answer.lifetime, LIFETIME);
}

#[test]
fn a_json_answer_can_only_shorten_the_lifetime() {
    let at = |secs: u64| format!("{{\"value\": \"{VALUE}\", \"expires_at\": {}}}", NOW + secs);
    let answer = parse(at(120).as_bytes(), LIFETIME, NOW).unwrap();
    assert_eq!(
        (answer.value.as_str(), answer.lifetime.as_secs()),
        (VALUE, 120)
    );
    let longer = parse(at(86_400).as_bytes(), LIFETIME, NOW).unwrap();
    assert_eq!(longer.lifetime, LIFETIME);
    let within = format!("{{\"value\": \"{VALUE}\", \"expires_in\": 300}}");
    assert_eq!(
        parse(within.as_bytes(), LIFETIME, NOW)
            .unwrap()
            .lifetime
            .as_secs(),
        300
    );
    let bare = format!("{{\"value\": \"{VALUE}\"}}");
    assert_eq!(
        parse(bare.as_bytes(), LIFETIME, NOW).unwrap().lifetime,
        LIFETIME
    );
}

#[test]
fn an_unusable_answer_is_refused_without_quoting_it() {
    for (out, why) in [
        (String::new(), "no value"),
        (format!("{VALUE}\nsecond-line"), "control character"),
        (format!("{VALUE}\u{7}"), "control character"),
        (
            format!("{{\"value\": \"{VALUE}\", \"expires_at\": {NOW}}}"),
            "less than 10s",
        ),
        (
            format!("{{\"value\": \"{VALUE}\", \"expires_in\": 3}}"),
            "less than 10s",
        ),
        (
            format!("{{\"value\": \"{VALUE}\", \"expiry\": 300}}"),
            "is not {\"value\"",
        ),
        (format!("{{\"value\": \"{VALUE}\""), "is not {\"value\""),
        (format!("{{\"token\": \"{VALUE}\"}}"), "is not {\"value\""),
        (
            format!("{{\"value\": \"{VALUE}\", \"expires_in\": 60, \"expires_at\": {NOW}}}"),
            "both",
        ),
        (
            format!("{{\"value\": \"{VALUE}\\r\\nX-Evil: 1\"}}"),
            "control character",
        ),
    ] {
        let error = format!("{:#}", parse(out.as_bytes(), LIFETIME, NOW).err().unwrap());
        assert!(error.contains(why), "{out:?}: {error}");
        assert!(!error.contains(VALUE), "{error}");
    }
    let error = format!("{:#}", parse(b"\xff\xfe", LIFETIME, NOW).err().unwrap());
    assert!(error.contains("not UTF-8"), "{error}");
}

/// Stand-in programs (`stand.rs`).
#[cfg(unix)]
mod programs {
    use std::path::Path;
    use std::time::Duration;

    use openmoat_core::Policy;

    use super::VALUE;
    use crate::secrets::stand::{Stand, scratch};

    #[test]
    fn a_program_answers_with_its_arguments_and_a_bare_environment() {
        let stand = Stand::new();
        // `CARGO_PKG_NAME` is set for this test process; the program must not
        // see it, and gets the person's home.
        let program = stand.shell(&format!(
            "[ \"$1\" = --print ] || exit 3\n[ \"$HOME\" = '{}' ] || exit 4\n\
             printf '{VALUE}-%s\\n' \"${{CARGO_PKG_NAME:-none}}\"",
            stand.root
        ));
        assert_eq!(program.id(), "t");
        let answer = program.fetch().unwrap();
        assert_eq!(answer.value.as_str(), format!("{VALUE}-none"));
        assert_eq!(answer.lifetime, Duration::from_mins(15));
    }

    #[test]
    fn a_program_the_agent_could_change_is_not_run() {
        let stand = Stand::new();
        let path = stand.script("ok", &format!("echo {VALUE}"));
        let open = Policy::parse("version: 1\n").unwrap();
        let error = format!("{:#}", stand.program(&path, &open).err().unwrap());
        assert!(error.contains("could be changed by the agent"), "{error}");
        assert!(error.contains("fs.write"), "{error}");
        // A link the policy covers, to a file it does not, is refused too.
        let elsewhere = scratch();
        let target = elsewhere.path().join("real");
        std::fs::copy(&path, &target).unwrap();
        let link = Path::new(&stand.root).join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = format!("{:#}", stand.program(&link, &stand.policy).err().unwrap());
        assert!(error.contains("could be changed by the agent"), "{error}");
    }

    #[test]
    fn a_program_changed_after_the_proxy_started_is_not_run() {
        let stand = Stand::new();
        let path = stand.script("ok", &format!("echo {VALUE}"));
        let program = stand.program(&path, &stand.policy).unwrap();
        // Refused on the digest, before anything starts.
        stand.script("ok", "echo fake-planted-value-0000");
        let error = format!("{:#}", program.fetch().err().unwrap());
        assert!(error.contains("changed since the proxy started"), "{error}");
    }

    #[test]
    fn a_failing_hanging_or_flooding_program_gives_no_value() {
        let stand = Stand::new();
        for (name, body, why) in [
            ("fails", format!("echo {VALUE}; exit 7"), "failed"),
            // `exec`: the time limit ends the one process, and no orphan
            // keeps running beside the other tests.
            (
                "hangs",
                format!("echo {VALUE}; exec sleep 5"),
                "did not finish",
            ),
            (
                "floods",
                "head -c 70000 /dev/zero | tr '\\0' a".to_owned(),
                "more than 64 KiB",
            ),
            (
                "control",
                format!("printf '{VALUE}\\033[2J'"),
                "control character",
            ),
        ] {
            let program = stand.shell(&body);
            let error = format!("{:#}", program.fetch().err().unwrap());
            assert!(error.contains(why), "{name}: {error}");
            assert!(!error.contains(VALUE), "{name}: {error}");
        }
    }
}
