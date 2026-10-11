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
