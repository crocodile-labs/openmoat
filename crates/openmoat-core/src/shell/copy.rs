//! Where a copy or a move writes (`cp`, `mv`, `ln`, `rsync`, `scp`).
//!
//! Into a directory, the command writes the entry named after each source, not
//! the directory: `cp f ~/` writes `~/f`. A destination is a directory when it
//! ends with `/`, is `~`, `.`, `..` or `$HOME`, or is given with `-t DIR` /
//! `--target-directory`. Any other destination (`mv dir newname`) may be
//! replaced itself, so that word stays the write, as it does under `-T`.
//!
//! When an entry name cannot be read from the command line, any entry of the
//! directory may be replaced, so the directory itself stays the write: a source
//! ending with `/` (`rsync -a dist/ ~/` copies the contents of `dist`), a
//! directory word (`cp -r ~ /backup/`), one the shell expands (`$X`, `*`,
//! `{a,b}`) or a remote spec (`scp host:f ~/`). Every operand that is not the
//! destination counts as a source, option values included: a spurious source
//! only adds a write.

use super::tables::WRITE_LAST_PATH;
use crate::paths;

/// Programs that take GNU's `-t DIR` / `--target-directory` and `-T`.
const TARGET_DIRECTORY_PROGRAMS: &[&str] = &["cp", "mv", "ln"];

/// Words that name a directory whatever follows them.
const DIRECTORY_WORDS: &[&str] = &["~", ".", "..", "$HOME", "${HOME}"];

/// Programs to which `host:path` is on another machine (`scp f host:/tmp/`).
const REMOTE_PROGRAMS: &[&str] = &["rsync", "scp"];

/// Characters that hide the entry name: the shell expands the word into names
/// it does not show, or `:` makes it a remote spec (`host:f`).
const UNKNOWN_NAME: &[char] = &['$', '`', '*', '?', '[', '{', ':'];

/// The destination of a copy or a move.
#[derive(Debug)]
pub(super) struct Destination<'a> {
    /// Index in argv of the word that holds it (`DIR`, or `-tDIR` itself).
    pub index: usize,
    pub word: &'a str,
    directory: bool,
}

/// The destination of `argv` when `program` copies or moves, if any.
pub(super) fn destination<'a>(argv: &'a [String], program: &str) -> Option<Destination<'a>> {
    if !(WRITE_LAST_PATH.contains(&program) || program == "mv") {
        return None;
    }
    let gnu = TARGET_DIRECTORY_PROGRAMS.contains(&program);
    if gnu && let Some(target) = target_option(argv) {
        return Some(target);
    }
    let index = (1..argv.len()).rev().find(|&i| !argv[i].starts_with('-'))?;
    let word = argv[index].as_str();
    if REMOTE_PROGRAMS.contains(&program) && is_remote(word) {
        return None;
    }
    let no_target = gnu && argv[1..index].iter().any(|a| is_no_target(a));
    let directory = !no_target
        && (word.ends_with('/')
            || word.ends_with("/.")
            || word.ends_with("/..")
            || DIRECTORY_WORDS.contains(&word));
    Some(Destination {
        index,
        word,
        directory,
    })
}

/// The paths written at `dest` when `sources` are copied or moved there.
pub(super) fn written(dest: &Destination<'_>, sources: &[&str]) -> Vec<String> {
    let names: Option<Vec<&str>> = sources.iter().map(|s| entry_name(s)).collect();
    match names {
        Some(names) if dest.directory && !names.is_empty() => {
            let dir = dest.word.trim_end_matches('/');
            names.iter().map(|name| format!("{dir}/{name}")).collect()
        }
        _ => vec![dest.word.to_owned()],
    }
}

/// The name a source gets inside a directory, when the command line shows it.
fn entry_name(source: &str) -> Option<&str> {
    let name = source.rsplit('/').next().unwrap_or(source);
    let known = !name.is_empty() && !DIRECTORY_WORDS.contains(&name);
    (known && !source.contains(UNKNOWN_NAME)).then_some(name)
}

/// `-t DIR`, `-tDIR`, `-rt DIR`, `--target-directory=DIR` or an unambiguous
/// prefix of it (`--target DIR`), up to `--`.
fn target_option(argv: &[String]) -> Option<Destination<'_>> {
    for (i, arg) in argv.iter().enumerate().skip(1) {
        if arg == "--" {
            return None;
        }
        let inline = if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            if name.is_empty() || !"target-directory".starts_with(name) {
                continue;
            }
            value
        } else if let Some((_, rest)) = arg.strip_prefix('-').and_then(|s| s.split_once('t')) {
            Some(rest).filter(|r| !r.is_empty())
        } else {
            continue;
        };
        let (index, word) = match inline {
            Some(value) => (i, value),
            None => (i + 1, argv.get(i + 1)?.as_str()),
        };
        return Some(Destination {
            index,
            word,
            directory: true,
        });
    }
    None
}

/// A `:` before the first `/` names a host (`host:/tmp/`, `rsync://h/m`), unless
/// it ends a drive letter (`C:/backup/`).
fn is_remote(word: &str) -> bool {
    let head = word.split('/').next().unwrap_or(word);
    head.contains(':') && !paths::is_absolute(word)
}

/// `-T` / `--no-target-directory`: the destination is replaced even if it is a
/// directory.
fn is_no_target(arg: &str) -> bool {
    match arg.strip_prefix("--") {
        Some(long) => long.len() > 2 && "no-target-directory".starts_with(long),
        None => arg.starts_with('-') && arg.contains('T'),
    }
}

#[cfg(test)]
mod tests {
    use super::{destination, written};

    fn writes(cmd: &str) -> Vec<String> {
        let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        let dest = destination(&argv, &argv[0]).expect("a copy");
        let sources: Vec<&str> = argv[1..]
            .iter()
            .enumerate()
            .filter(|(i, a)| i + 1 != dest.index && !a.starts_with('-'))
            .map(|(_, a)| a.as_str())
            .collect();
        written(&dest, &sources)
    }

    #[test]
    fn into_a_directory_writes_the_entry() {
        assert_eq!(writes("cp f ~/"), ["~/f"]);
        assert_eq!(writes("mv src/a.rs ~"), ["~/a.rs"]);
        assert_eq!(writes("cp -r assets /"), ["/assets"]);
        assert_eq!(writes("cp a b ./out/"), ["./out/a", "./out/b"]);
        assert_eq!(writes("rsync -a dist ~/"), ["~/dist"]);
        assert_eq!(writes("cp -t ~ f"), ["~/f"]);
        assert_eq!(writes("cp --target-directory=~ f"), ["~/f"]);
        assert_eq!(writes("mv --target ~ f"), ["~/f"]);
        assert_eq!(writes("cp -rt ~ f"), ["~/f"]);
    }

    #[test]
    fn otherwise_the_destination_itself() {
        assert_eq!(writes("mv dir newname"), ["newname"]);
        assert_eq!(writes("cp -T f ~/"), ["~/"]);
        assert_eq!(writes("mv --no-target-directory f ~"), ["~"]);
        assert_eq!(writes("rsync -a dist/ ~/"), ["~/"]);
        assert_eq!(writes("cp -r ~ /backup/"), ["/backup/"]);
        assert_eq!(writes("cp * ~/"), ["~/"]);
        assert_eq!(writes("cp $X ~/"), ["~/"]);
        assert_eq!(writes("cp ~/"), ["~/"]);
        assert_eq!(writes("scp host:.zshrc notes ~/"), ["~/"]);
        assert!(destination(&["rm".into(), "~".into()], "rm").is_none());
    }

    #[test]
    fn a_remote_destination_is_no_local_write() {
        for cmd in [
            "scp key host:/tmp/",
            "scp key u@host:",
            "rsync -a d host::m/",
            "rsync d rsync://host/m",
        ] {
            let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
            assert!(destination(&argv, &argv[0]).is_none(), "{cmd}");
        }
        assert_eq!(writes("scp f C:/backup/"), ["C:/backup/f"]);
        assert_eq!(writes("cp f host:/tmp/"), ["host:/tmp/f"]);
    }
}
