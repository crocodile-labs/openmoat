//! A secret read from a real pseudo-terminal is not echoed, the terminal is
//! put back, Ctrl-C cancels without a signal, and piped input is refused.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, SpecialCodeIndex, tcgetattr};

use super::unix::read_hidden;
use super::{MAX_SECRET, Source, finish, source};

/// A pseudo-terminal: the side a terminal emulator holds, and the side a
/// program reads from as its terminal.
fn pty() -> (File, File) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    (File::from(master), slave)
}

/// Made at run time, shaped like no real token.
fn made_up() -> String {
    format!("{}:{}", 31_337, "made-up-secret-words")
}

/// Wait until the reader has turned echo off, so what is typed next meets
/// the hidden settings, not the default ones; whether it did within 5 s. The
/// caller types its line either way, so a reader that never got that far
/// does not hang the test.
fn wait_for_echo_off(slave: &File) -> bool {
    let start = Instant::now();
    while tcgetattr(slave)
        .unwrap()
        .local_modes
        .contains(LocalModes::ECHO)
    {
        if start.elapsed() > Duration::from_secs(5) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// What the terminal showed: everything the master side reads up to `END`,
/// which the slave side writes once the read is over.
fn shown(master: &mut File, slave: &mut File) -> String {
    slave.write_all(b"END").unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 256];
    while !seen.ends_with(b"END") {
        let n = master.read(&mut chunk).unwrap();
        assert!(n > 0, "the terminal closed");
        seen.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

#[test]
fn a_secret_typed_at_a_terminal_is_read_and_never_shown() {
    let (mut master, mut slave) = pty();
    let secret = made_up();
    let (off, read) = std::thread::scope(|scope| {
        let reader = scope.spawn(|| read_hidden(&slave));
        let off = wait_for_echo_off(&slave);
        master.write_all(format!("{secret}\n").as_bytes()).unwrap();
        (off, reader.join().unwrap())
    });
    assert!(off, "echo never went off");
    let read = read.unwrap();
    assert_eq!(read.as_slice(), secret.as_bytes());
    let screen = shown(&mut master, &mut slave);
    assert!(
        !screen.contains(&secret),
        "the secret was echoed: {screen:?}"
    );
    assert!(
        !screen.contains("made-up"),
        "part of it was echoed: {screen:?}"
    );
    // The terminal's own settings are back: echo on, Ctrl-C a signal again.
    let after = tcgetattr(&slave).unwrap();
    assert!(after.local_modes.contains(LocalModes::ECHO));
    assert!(after.local_modes.contains(LocalModes::ISIG));
}

#[test]
fn ctrl_c_cancels_the_read_and_puts_the_terminal_back() {
    let (mut master, slave) = pty();
    let interrupt = tcgetattr(&slave).unwrap().special_codes[SpecialCodeIndex::VINTR];
    let (off, result) = std::thread::scope(|scope| {
        let reader = scope.spawn(|| read_hidden(&slave));
        let off = wait_for_echo_off(&slave);
        master.write_all(&[b'a', b'b', interrupt]).unwrap();
        (off, reader.join().unwrap())
    });
    assert!(off, "echo never went off");
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("cancelled"), "{error}");
    let after = tcgetattr(&slave).unwrap();
    assert!(after.local_modes.contains(LocalModes::ECHO));
    assert!(after.local_modes.contains(LocalModes::ISIG));
}

#[test]
fn piped_input_is_never_read_as_a_secret() {
    assert_eq!(source(false, false), Source::Refused);
    assert_eq!(source(false, true), Source::Terminal);
    // Only the debug builds' `MOAT_ASSUME_TTY=1` reads stdin.
    assert_eq!(source(true, false), Source::Stdin);
}

#[test]
fn errors_about_the_line_never_show_it() {
    let secret = made_up();
    assert_eq!(
        finish(format!("  {secret}\r\n").as_bytes())
            .unwrap()
            .as_str(),
        secret
    );
    for bad in [String::new(), " \n".to_owned(), "x".repeat(MAX_SECRET + 1)] {
        let error = format!("{:#}", finish(bad.as_bytes()).unwrap_err());
        assert!(
            !bad.trim().is_empty() || error.contains("no secret"),
            "{error}"
        );
        assert!(!error.contains("xxxx"), "{error}");
    }
    let error = format!("{:#}", finish(b"\xff\xfe").unwrap_err());
    assert!(error.contains("not text"), "{error}");
}
