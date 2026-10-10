//! Text tools: option values and program text are data (`shell/text.rs`).

use super::*;

#[test]
fn option_values_are_not_files() {
    let a = parsed("cut -d '/' -f 2 paths.txt");
    assert!(has_read(&a, "/p/paths.txt"));
    assert!(!has_read(&a, "/"));
    assert!(has_read(&parsed("sort -t / -k 2 x"), "/p/x"));
    assert!(!has_read(&parsed("sort -t / -k 2 x"), "/"));
}

#[test]
fn written_files() {
    assert!(has_write(&parsed("sort -o /tmp/out data.txt"), "/tmp/out"));
    assert!(has_write(&parsed("sort -no/tmp/out data.txt"), "/tmp/out"));
    assert!(has_write(
        &parsed("sort data.txt --output ~/.zshrc"),
        "/Users/me/.zshrc"
    ));
    assert!(has_write(&parsed("sort -T /tmp/t data.txt"), "/tmp/t"));
    let a = parsed("uniq -c -f 1 in.txt ~/.bashrc");
    assert!(has_read(&a, "/p/in.txt"));
    assert!(has_write(&a, "/Users/me/.bashrc"));
    assert!(!has_write(&parsed("uniq -c in.txt"), "/p/in.txt"));
}

#[test]
fn a_value_after_an_operand_may_be_a_file() {
    // BSD getopt stops at `data.txt`, so `-t` and `s` are files it reads.
    assert!(has_read(&parsed("sort data.txt -t s"), "/p/s"));
}

#[test]
fn unknown_options_are_reported() {
    for (cmd, marker) in [
        (
            "sort --compress-program=sh x",
            "sort @--compress-program=sh",
        ),
        ("sort --files0-from=list", "sort @--files0-from=list"),
        ("uniq --frobnicate x", "uniq @--frobnicate"),
        ("cut -Q x", "cut @-Q"),
    ] {
        assert!(has_shell(&parsed(cmd), marker), "{cmd}");
    }
    assert!(!has_unproven(&parsed("sort -rn -k2 x | uniq -c")));
}

fn has_unproven(atoms: &[AtomicAction]) -> bool {
    atoms.iter().any(
        |a| matches!(a, AtomicAction::Shell { argv } if argv.get(1).is_some_and(|w| w.starts_with('@'))),
    )
}

#[test]
fn sed_script_is_not_a_file() {
    for cmd in [
        "sed -n '/start/,/end/p' f",
        "sed -n -e 1,20p -e '$p' f",
        "sed --expression=/x/d f",
        "sed -n -e /x/d f -E",
    ] {
        let a = parsed(cmd);
        assert!(has_read(&a, "/p/f"), "{cmd}");
        assert!(!has_unproven(&a), "{cmd}");
        assert!(
            !a.iter()
                .any(|x| matches!(x, AtomicAction::FsRead { path } if path != "/p/f")),
            "{cmd}"
        );
    }
}

#[test]
fn sed_script_files() {
    let a = parsed("sed -n '1r ~/.ssh/id_rsa' x");
    assert!(has_read(&a, "/p/~/.ssh/id_rsa"));
    let a = parsed("sed -n '1r /Users/me/.ssh/id_rsa' x");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"));
    assert!(has_write(&parsed("sed 's/a/b/w /tmp/o' x"), "/tmp/o"));
    for cmd in [
        "sed -f /p/project.sed data",
        "sed -f/p/project.sed data",
        "sed --file=/p/project.sed data",
        "sed data --file /p/project.sed",
    ] {
        let a = parsed(cmd);
        assert!(has_read(&a, "/p/project.sed") && has_unproven(&a), "{cmd}");
    }
    assert!(has_read(
        &parsed("sed -f ~/.ssh/id_rsa x"),
        "/Users/me/.ssh/id_rsa"
    ));
}

#[test]
fn sed_in_place_writes_operands_and_backups() {
    let a = parsed("sed -ni.bak 's/a/b/p' x y");
    assert!(has_write(&a, "/p/x") && has_write(&a, "/p/y"));
    assert!(has_write(&a, "/p/x.bak"));
    assert!(!has_unproven(&a));
    // GNU: the empty word is the script and `s/a/b/` a file; BSD: the reverse
    let a = parsed("sed -i '' 's/a/b/' x");
    assert!(has_write(&a, "/p/x") && has_write(&a, "/p/s/a/b"));
    assert!(!has_unproven(&a));
    // BSD takes `-e` as the suffix
    assert!(has_write(&parsed("sed -i -e p x"), "/p/x-e"));
    assert!(has_write(&parsed("sed --in-place s/a/b/ x"), "/p/x"));
    assert!(has_write(&parsed("sed s/a/b/ x -i"), "/p/x"));
}

#[test]
fn awk_program_and_option_values_are_not_files() {
    let a = parsed("awk -F / -v x=/a '/error/ {print $1}' log.txt");
    assert!(has_read(&a, "/p/log.txt"));
    assert!(!has_unproven(&a));
    assert!(
        !a.iter()
            .any(|x| matches!(x, AtomicAction::FsRead { path } if path != "/p/log.txt"))
    );
    // awk stops reading options at the program: `-F` and the key are files
    let a = parsed("awk '{print}' -F ~/.ssh/id_rsa");
    assert!(has_read(&a, "/Users/me/.ssh/id_rsa"));
}

#[test]
fn awk_forms_that_may_do_more_are_reported() {
    for cmd in [
        "awk 'BEGIN{system(\"id\")}'",
        "awk '{print > \"out\"}' x",
        "awk -f prog.awk x",
        "awk --source='{print}' x",
    ] {
        assert!(has_unproven(&parsed(cmd)), "{cmd}");
    }
}

#[test]
fn sed_forms_that_may_do_more_are_reported() {
    for cmd in [
        "sed -n '1e id' x",
        "sed 's/.*/id/e' x",
        "sed -f prog.sed x",
        "sed -l 5 p x",
        // BSD reads `s/a/b/` as the suffix and `x` as the script
        "sed -i s/a/b/ x",
        "sed -i'/tmp/*' s/a/b/ x",
        // BSD stops at `p`: `-e` and `e id` are files, but GNU runs `e id`
        "sed p -e 'e id' x",
        "sed notes.txt -n -e p",
    ] {
        assert!(has_unproven(&parsed(cmd)), "{cmd}");
    }
}
