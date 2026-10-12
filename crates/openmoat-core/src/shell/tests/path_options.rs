//! Option values that name files (`path_options.rs`): every spelling a tool
//! takes, and the fail-closed rule for a path attached to any short option.

use super::*;

#[test]
fn option_values_are_reads_or_writes_in_every_spelling() {
    for (cmd, path, write) in [
        ("cmake -B /tmp/b", "/tmp/b", true),
        ("cmake -S. -Bbuild", "/p/build", true),
        ("go build --o=/tmp/x .", "/tmp/x", true),
        (
            "go test -coverprofile cover.out ./...",
            "/p/cover.out",
            true,
        ),
        ("dotnet build --output=out", "/p/out", true),
        ("python3 -m pytest --basetemp /tmp/x", "/tmp/x", true),
        ("cmake -S/tmp/src -B build", "/tmp/src", false),
        ("go build -modfile=/tmp/go.mod .", "/tmp/go.mod", false),
        ("mvn test -gs /tmp/settings.xml", "/tmp/settings.xml", false),
        ("make test --file=/tmp/x.mk", "/tmp/x.mk", false),
        ("bundle exec rspec -I/tmp/lib", "/tmp/lib", false),
    ] {
        let atoms = parsed(cmd);
        assert!(has_write(&atoms, path) == write, "{cmd}: {atoms:?}");
        assert!(has_read(&atoms, path) != write, "{cmd}: {atoms:?}");
    }
    // `-fae` is a flag of its own, not `-f ae`.
    assert!(!has_read(&parsed("mvn test -fae"), "/p/ae"));
}

#[test]
fn options_that_load_code_are_unparseable() {
    for cmd in [
        "cmake -B build --toolchain=/tmp/tc.cmake",
        "gradle build --init-script=/tmp/x.gradle",
        "pytest -pevil",
        "cargo build --config build.rustc-wrapper=/tmp/x",
    ] {
        let outcome = classify(cmd, &ctx());
        assert!(
            matches!(&outcome, ParseOutcome::Unparseable { reason, .. } if reason.contains("runs code")),
            "{cmd}: {outcome:?}"
        );
    }
    assert!(!parsed("pytest -p no:cacheprovider").is_empty());
}

#[test]
fn a_path_attached_to_any_short_option_is_read_and_written() {
    for (cmd, path) in [
        ("ssh -i~/.ssh/id_rsa host", "/Users/me/.ssh/id_rsa"),
        ("tar -C../out -xf a.tar", "/out"),
        ("cc -I=/opt/include x.c", "/opt/include"),
    ] {
        let atoms = parsed(cmd);
        assert!(
            has_read(&atoms, path) && has_write(&atoms, path),
            "{cmd}: {atoms:?}"
        );
    }
    for cmd in [
        "make test -j4",
        "cc -O2 -Wall -DFOO=1 x",
        "xargs sed -i~ s/a/b/",
        "echo -n/x",
    ] {
        let atoms = parsed(cmd);
        let outside = |a: &AtomicAction| matches!(a, AtomicAction::FsWrite { path } if !path.starts_with("/p/"));
        assert!(!atoms.iter().any(outside), "{cmd}: {atoms:?}");
    }
}
