use std::ffi::OsString;
use std::path::Path;

use super::*;

fn paths() -> Paths {
    Paths::under(Some(Path::new("/Users/you")))
}

#[test]
fn paths_under_the_home_directory_start_with_a_tilde() {
    let paths = paths();
    assert_eq!(
        paths.shorten("/Users/you/.claude/settings.json"),
        "~/.claude/settings.json"
    );
    assert_eq!(
        paths.shorten("hook installed  /Users/you/.codex/hooks.json, /Users/you/.moat"),
        "hook installed  ~/.codex/hooks.json, ~/.moat"
    );
    assert_eq!(paths.shorten("in /Users/you"), "in ~");
    assert_eq!(paths.shorten("`/Users/you/.moat`"), "`~/.moat`");
    // A name that only starts like the home directory, or holds it inside.
    assert_eq!(paths.shorten("/Users/younger/x"), "/Users/younger/x");
    assert_eq!(paths.shorten("/mnt/Users/you/x"), "/mnt/Users/you/x");
    assert_eq!(paths.shorten("no path here"), "no path here");
    // A trailing separator on the home directory changes nothing.
    let slash = Paths::under(Some(Path::new("/Users/you/")));
    assert_eq!(slash.shorten("/Users/you/.moat"), "~/.moat");
    // No home, or a filesystem root: nothing is shortened.
    assert_eq!(
        Paths::under(None).shorten("/Users/you/.moat"),
        "/Users/you/.moat"
    );
    assert_eq!(
        Paths::under(Some(Path::new("/"))).shorten("/etc/x"),
        "/etc/x"
    );
}

#[test]
fn windows_paths_under_the_home_directory_are_shortened_too() {
    let paths = Paths::under(Some(Path::new(r"C:\Users\you")));
    assert_eq!(
        paths.shorten(r"C:\Users\you\.claude\settings.json"),
        r"~\.claude\settings.json"
    );
    assert_eq!(
        Paths::under(Some(Path::new("C:"))).shorten(r"C:\x"),
        r"C:\x"
    );
}

#[test]
fn attention_lists_broken_things_first_then_the_rest_in_order() {
    let mut attention = Attention::default();
    attention.push(Row::new(Mark::Attention, "Codex", "not trusted"));
    attention.push(Row::new(Mark::Broken, "Lock", "drift"));
    attention.push(Row::new(Mark::Attention, "OpenClaw", "advisory"));
    attention.push(Row::new(Mark::Broken, "Cursor", "hook missing"));
    let labels: Vec<&str> = attention.rows().iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["Lock", "Cursor", "Codex", "OpenClaw"]);
    assert_eq!(attention.len(), 4);
    assert!(attention.names("Codex") && !attention.names("pi"));
}

#[test]
fn colour_only_on_a_terminal_without_no_color() {
    let set = |v: &str| Some(OsString::from(v));
    assert_eq!(Style::new(false, None).mark(Mark::Ok), "✔");
    assert_eq!(Style::new(true, None).mark(Mark::Ok), "\x1b[32m✔\x1b[0m");
    assert_eq!(Style::new(true, set("1")).mark(Mark::Broken), "✗");
    assert_eq!(
        Style::new(true, set("")).mark(Mark::Broken),
        "\x1b[31m✗\x1b[0m"
    );
    assert_eq!(Style::new(false, set("1")).bold("x"), "x");
    assert_eq!(Style::new(true, None).dim("x"), "\x1b[2mx\x1b[0m");
}

#[test]
fn rows_align_their_labels_and_show_the_fix() {
    let mut text = Vec::new();
    let mut out = Printer::new(&mut text, Style::new(false, None), paths());
    let rows = [
        Row::new(Mark::Ok, "Policy", "16 deny"),
        Row::new(Mark::Broken, "Lock", "missing").fix("openmoat init"),
        Row::new(Mark::Info, "Audit log", "/Users/you/.moat/audit.db"),
    ];
    out.rows(&rows).unwrap();
    assert_eq!(
        String::from_utf8(text).unwrap(),
        "  ✔ Policy     16 deny\n  ✗ Lock       missing → openmoat init\n  · Audit log  ~/.moat/audit.db\n"
    );
}

#[test]
fn agent_text_cannot_write_to_the_terminal() {
    let mut text = Vec::new();
    let mut out = Printer::new(&mut text, Style::new(false, None), paths());
    out.rows(&[Row::new(Mark::Attention, "x\x1b]52;c;eA==\x07", "a\nb")])
        .unwrap();
    let shown = String::from_utf8(text).unwrap();
    assert!(
        !shown.contains('\x1b') && shown.matches('\n').count() == 1,
        "{shown:?}"
    );
}

#[test]
fn a_fix_is_split_from_the_text_the_checks_write() {
    assert_eq!(
        split_fix("hook missing; run `openmoat init`"),
        ("hook missing".to_owned(), Some("openmoat init".to_owned()))
    );
    assert_eq!(
        split_fix("x is not pinned by the lock; run `openmoat init` to pin it"),
        (
            "x is not pinned by the lock".to_owned(),
            Some("openmoat init to pin it".to_owned())
        )
    );
    assert_eq!(
        split_fix("missing (run `openmoat init`)"),
        ("missing".to_owned(), Some("openmoat init".to_owned()))
    );
    assert_eq!(split_fix("all intact"), ("all intact".to_owned(), None));
}

#[test]
fn counts_say_one_or_many() {
    assert_eq!(count(1, "agent"), "1 agent");
    assert_eq!(count(0, "agent"), "0 agents");
    assert_eq!(count(5, "agent"), "5 agents");
}
