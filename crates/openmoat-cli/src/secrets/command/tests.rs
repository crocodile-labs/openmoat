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
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use openmoat_core::Policy;

    use super::VALUE;
    use crate::secrets::stand::{Stand, scratch};

    #[test]
    fn a_program_answers_with_its_arguments_and_a_bare_environment() {
        let stand = Stand::new();
        // `CARGO_PKG_NAME` is set for this test process; the program must not
        // see it.
        let program = stand.shell(&format!(
            "[ \"$1\" = --print ] || exit 3\n\
             printf '{VALUE}-%s\\n' \"${{CARGO_PKG_NAME:-none}}\""
        ));
        assert_eq!(program.id(), "t");
        let answer = program.fetch().unwrap();
        assert_eq!(answer.value.as_str(), format!("{VALUE}-none"));
        assert_eq!(answer.lifetime, Duration::from_mins(15));
    }

    /// Attack: the proxy runs in the agent's project, where the agent wrote
    /// `.git`, tool shims and per-folder configuration that a tool reads from
    /// its working folder, or dotfiles in the home. The program runs in `/`
    /// with an empty home of its own unless the policy says `home: user`.
    #[test]
    fn a_program_runs_in_the_root_with_a_private_home_unless_told_otherwise() {
        let stand = Stand::new();
        let body =
            "printf '%s|%s|%s' \"$(pwd -P)\" \"$HOME\" \"$(ls -A \"$HOME\" | wc -l | tr -d ' ')\"";
        let answer = stand.shell(body).fetch().unwrap();
        let private = std::fs::canonicalize(stand.state())
            .unwrap()
            .join("secret-homes/t");
        let mut seen = answer.value.split('|');
        assert_eq!(seen.next(), Some("/"));
        let home = std::fs::canonicalize(seen.next().unwrap()).unwrap();
        assert_eq!(home, private);
        assert_eq!(seen.next(), Some("0"), "the private home is empty");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&private).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o700);
        let mut source = Stand::source(&["/bin/sh", "-c", body]);
        source.home = openmoat_core::SecretCommandHome::User;
        let answer = stand.shell_with(&source).fetch().unwrap();
        assert_eq!(answer.value.as_str(), format!("/|{}|0", stand.root));
    }

    /// Attack: a tool the program runs by name is planted beside it. The
    /// search path holds the system's folders only, so it is never found.
    #[test]
    fn a_planted_tool_beside_the_program_is_never_used() {
        let stand = Stand::new();
        let marker = format!("{}/planted-ran", stand.root);
        stand.script("python3", &format!("touch '{marker}'"));
        let path = stand.script(
            "token",
            &format!("python3 -c 'print(1)' >/dev/null 2>&1\necho {VALUE}"),
        );
        let answer = stand
            .program(&path, &stand.policy)
            .unwrap()
            .fetch()
            .unwrap();
        assert_eq!(answer.value.as_str(), VALUE);
        assert!(!Path::new(&marker).exists(), "the planted python3 ran");
    }

    /// Attack: the file is swapped between the hash and the start. What runs
    /// is a private copy of the bytes that were hashed, checked again before
    /// each run, and removed with the program.
    #[test]
    fn the_bytes_that_were_hashed_are_the_ones_that_run() {
        let stand = Stand::new();
        let path = stand.script("token", "echo \"$0\"");
        let program = stand.program(&path, &stand.policy).unwrap();
        let ran = PathBuf::from(program.fetch().unwrap().value.as_str());
        let copies = std::fs::canonicalize(stand.state())
            .unwrap()
            .join("secret-programs");
        assert_eq!(
            std::fs::canonicalize(&ran).unwrap().parent(),
            Some(copies.as_path())
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&copies), mode(&ran)), (0o700, 0o700));
        // A changed copy is not run.
        std::fs::write(&ran, "#!/bin/sh\necho fake-planted-value-0000\n").unwrap();
        let error = format!("{:#}", program.fetch().err().unwrap());
        assert!(error.contains("private copy"), "{error}");
        drop(program);
        assert!(!ran.exists());
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
            let mut program = stand.shell(&body);
            if name == "hangs" {
                program = program.with_time_limit(Duration::from_secs(2));
            }
            let error = format!("{:#}", program.fetch().err().unwrap());
            assert!(error.contains(why), "{name}: {error}");
            assert!(!error.contains(VALUE), "{name}: {error}");
        }
    }
}
