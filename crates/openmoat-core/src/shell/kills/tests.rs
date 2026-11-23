use super::{could_be, could_match, quoted_words, targets_root};

#[test]
fn a_quoted_run_is_one_word() {
    assert_eq!(
        quoted_words("pgrep -f 'next dev'"),
        ["pgrep", "-f", "next dev"]
    );
    assert_eq!(quoted_words("pidof \"sshd\" x"), ["pidof", "sshd", "x"]);
}

#[test]
fn patterns_that_could_stop_openmoat() {
    for pattern in [
        "moat",
        "openmoat",
        "open.*",
        ".",
        "o.*t",
        "m.at",
        "openmoat proxy",
        "/usr/local/bin/openmoat",
        "^moat$",
        "mo+at",
        "(open)?moat",
        "vite|moat",
        "[om]+",
        "openx?moat",
        // holds a name: a command line with it matches (conservative)
        "moatx",
    ] {
        assert!(
            could_match(pattern, "openmoat") || could_match(pattern, "moat"),
            "{pattern}"
        );
    }
}

#[test]
fn patterns_that_cannot() {
    for pattern in [
        "latency-compare.py",
        "my-server.js",
        "node .*vite",
        "python3",
        "node",
        "nginx",
        "boat",
        "m\\.at",
        "mo.t\\.py",
        "[a-z]+-server",
    ] {
        assert!(
            !could_match(pattern, "openmoat") && !could_match(pattern, "moat"),
            "{pattern}"
        );
    }
}

#[test]
fn patterns_that_could_stop_a_system_process() {
    for (pattern, name) in [
        ("sshd", "sshd"),
        ("ssh", "sshd"),
        ("^sshd$", "sshd"),
        ("/usr/sbin/sshd", "sshd"),
        ("launchd", "launchd"),
        ("journald", "systemd-journald"),
        ("init", "init"),
        ("vite|sshd", "sshd"),
        ("(ssh)d", "sshd"),
        (".", "launchd"),
        ("Window.*", "WindowServer"),
    ] {
        assert!(could_be(pattern, name), "{pattern} {name}");
    }
}

#[test]
fn developer_patterns_stop_no_system_process() {
    for pattern in [
        "node server",
        "node",
        "vite",
        "next dev",
        "uvicorn",
        "python manage.py runserver",
        "my-server.js",
        "initdb",
        "my-init-script",
        "cronjob-worker",
        "sshd-test-fixture",
        "vite|next",
        "server",
        "postgres",
        "redis-server",
        "/usr/local/bin/node",
    ] {
        for name in super::SYSTEM_NAMES {
            assert!(!could_be(pattern, name), "{pattern} {name}");
        }
    }
}

#[test]
fn root_as_the_user_whose_processes_stop() {
    let argv = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
    for words in [
        &["pkill", "-u", "root"][..],
        &["pkill", "-uroot", "node"],
        &["pkill", "-U", "0"],
        &["pkill", "--euid=root"],
        &["killall", "--user", "root"],
        &["pkill", "-u", "me,root"],
    ] {
        assert!(targets_root(&argv(words)), "{words:?}");
    }
    for words in [
        &["pkill", "-u", "me", "node"][..],
        &["pkill", "-f", "root-server"],
        &["killall", "-u", "rootless"],
    ] {
        assert!(!targets_root(&argv(words)), "{words:?}");
    }
}
