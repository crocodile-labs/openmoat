//! Everyday utilities: which operands they read or write, and which of them
//! run another command.

use super::*;

fn has_any_write(atoms: &[AtomicAction]) -> bool {
    atoms
        .iter()
        .any(|a| matches!(a, AtomicAction::FsWrite { .. }))
}

#[test]
fn fd_pattern_is_no_path_and_its_directories_are_reads() {
    // The first operand is a regex, which a leading `\` would otherwise make a path.
    assert!(!has_read(&parsed("fd '\\.rs$'"), "/.rs$"));
    assert!(has_read(&parsed("fd id_rsa ~/.ssh"), "/Users/me/.ssh"));
    assert!(has_read(&parsed("fd x .."), "/"));
    assert!(!has_read(&parsed("fd -HI '\\.env$'"), "/.env$"));
    // After an option that takes a value the word may be anything: still checked.
    assert!(has_read(&parsed("fd -e rs '\\.rs$'"), "/.rs$"));
}

#[test]
fn grep_pattern_is_no_path_and_its_files_are_reads() {
    // The first operand is text grep never opens; `\.` would make it `/.ENV`.
    for cmd in [
        "grep -n '\\.ENV' notes.md",
        "grep -rn --include=*.md '\\.env' docs",
        "egrep 'a/b|c' notes.md",
        "grep -- '\\.env' notes.md",
        "grep -i -- ~/.ssh/id_rsa notes.md",
    ] {
        let a = parsed(cmd);
        assert!(!a.iter().any(|x| matches!(x, AtomicAction::FsRead { path } if path.contains("env") || path.contains(".ssh"))), "{cmd}: {a:?}");
        assert!(
            has_read(&a, "/p/notes.md") || has_read(&a, "/p/docs"),
            "{cmd}: {a:?}"
        );
    }
    // The files after the pattern are still read.
    assert!(has_read(&parsed("grep -r x ~/.ssh"), "/Users/me/.ssh"));
    assert!(has_read(&parsed("grep x .env"), "/p/.env"));
    // With `-e` or `-f` anywhere every operand is a file (GNU grep permutes options).
    for cmd in [
        "grep ~/.ssh/id_rsa -e x",
        "grep -e x ~/.ssh/id_rsa",
        "grep -ie x ~/.ssh/id_rsa",
        "grep --regexp=x ~/.ssh/id_rsa",
        "grep --reg x ~/.ssh/id_rsa",
        "grep -f pats ~/.ssh/id_rsa",
        "grep --fi=pats ~/.ssh/id_rsa",
        // after an option that may take a value, or one not known, the word may be a file
        "grep -A 2 ~/.ssh/id_rsa x",
        "grep -A2 ~/.ssh/id_rsa x",
        "grep -m1 ~/.ssh/id_rsa x",
        "grep --context 2 ~/.ssh/id_rsa x",
        "grep --frobnicate ~/.ssh/id_rsa x",
    ] {
        assert!(has_read(&parsed(cmd), "/Users/me/.ssh/id_rsa"), "{cmd}");
    }
}

#[test]
fn gofmt_reads_operands_and_writes_them_only_with_w() {
    let atoms = parsed("gofmt -l .");
    assert!(has_read(&atoms, "/p"));
    assert!(!has_any_write(&atoms));
    for cmd in [
        "gofmt -w main.go",
        "gofmt --w=true main.go",
        "gofmt -s -w main.go",
    ] {
        assert!(has_write(&parsed(cmd), "/p/main.go"), "{cmd}");
    }
    assert!(has_write(&parsed("gofmt -w ~/.zshrc"), "/Users/me/.zshrc"));
}

#[test]
fn gofmt_profile_is_a_write() {
    for cmd in [
        "gofmt -l -cpuprofile .git/hooks/pre-commit .",
        "gofmt --cpuprofile=.git/hooks/pre-commit -l .",
    ] {
        assert!(has_write(&parsed(cmd), "/p/.git/hooks/pre-commit"), "{cmd}");
    }
}

#[test]
fn command_v_runs_nothing() {
    for cmd in ["command -v cargo", "command -V cargo", "command -pv cargo"] {
        let atoms = parsed(cmd);
        assert!(!has_shell(&atoms, "cargo"), "{cmd}");
    }
    // Without `-v` it runs the command, which is classified on its own.
    assert!(has_shell(&parsed("command -p rm -rf x"), "rm -rf x"));
    assert!(has_shell(&parsed("command -- cargo -v"), "cargo -v"));
}

#[test]
fn git_restore_paths_are_writes() {
    let atoms = parsed("git restore --staged src/main.rs README.md");
    assert!(has_write(&atoms, "/p/src/main.rs"));
    assert!(has_write(&atoms, "/p/README.md"));
    assert!(!has_write(&atoms, "/p/--staged"));
    assert!(has_write(&parsed("git restore -- -odd"), "/p/-odd"));
    assert!(!has_any_write(&parsed("git status src/main.rs")));
}

#[test]
fn uv_run_classifies_the_wrapped_command() {
    let atoms = parsed("uv run pytest -x");
    assert!(has_shell(&atoms, "uv run pytest -x"));
    assert!(has_shell(&atoms, "pytest -x"));
    assert!(has_read(
        &parsed("uv run cat ~/.ssh/id_rsa"),
        "/Users/me/.ssh/id_rsa"
    ));
    // `uv sync` runs no command of its own.
    assert!(!has_shell(&parsed("uv sync"), "sync"));
}

#[test]
fn pkexec_and_runuser_classify_the_wrapped_command() {
    assert!(has_shell(&parsed("pkexec --user me id -u"), "id -u"));
    assert!(has_shell(&parsed("runuser -u me -- id -u"), "id -u"));
    assert!(has_shell(&parsed("runuser --user=me id -u"), "id -u"));
    // without `-u` the first operand is a user, and `-c` its command line
    let atoms = parsed("runuser - me -c 'id -u'");
    assert!(has_shell(&atoms, "id -u"));
    assert!(!has_shell(&atoms, "me -c id -u"));
}

#[test]
fn interpreter_scripts_are_reads() {
    assert!(has_read(&parsed("python script.py"), "/p/script.py"));
    assert!(has_read(&parsed("cd /tmp && python3 x.py"), "/tmp/x.py"));
    assert!(has_read(&parsed("node build.js"), "/p/build.js"));
}

#[test]
fn launchers_classify_the_command_they_run() {
    for (cmd, inner) in [
        ("taskset -c 0 cargo build", "cargo build"),
        ("chrt -T 5 10 make", "make"),
        ("systemd-run --user --unit x make", "make"),
        ("strace -f -o t.txt ./app", "./app"),
        ("sandbox-exec -f p.sb make", "make"),
        ("arch -arch arm64 make", "make"),
        ("busybox cp a b", "cp a b"),
        ("gdb --args ./app -v", "./app -v"),
        ("daemonize -c /tmp ./app", "./app"),
    ] {
        assert!(has_shell(&parsed(cmd), inner), "{cmd}");
    }
    // `at` and `batch` run their stdin later
    assert!(has_shell(
        &parsed("echo 'cargo build' | at now"),
        "cargo build"
    ));
    assert!(has_read(&parsed("at -f job.sh now"), "/p/job.sh"));
}

#[test]
fn gnu_prefixed_tools_write_like_their_plain_names() {
    for cmd in [
        "gcp a ~/x",
        "gmv a ~/x",
        "/opt/homebrew/bin/grm ~/x",
        "gtouch ~/x",
        "busybox rm ~/x",
        "ditto a ~/x",
        "cpio -pd ~/x",
    ] {
        assert!(has_write(&parsed(cmd), "/Users/me/x"), "{cmd}");
    }
    // the destination of a `pax` copy, and each source's path below it
    let atoms = parsed("pax -rw src/a ~/x");
    assert!(has_write(&atoms, "/Users/me/x"));
    assert!(has_write(&atoms, "/Users/me/x/src/a"));
    // without `-r` and `-w` pax makes or reads an archive
    assert!(!has_write(&parsed("pax -w -f out.pax ~/x"), "/Users/me/x"));
    // `grep`, `gzip` and `git` are no prefixed tools
    assert!(has_shell(&parsed("gzip ~/x"), "gzip ~/x"));
    assert!(!has_write(&parsed("gzip ~/x"), "/Users/me/x"));
}
