//! Where an archive tool extracts to: `tar -x` (and `gtar`, `bsdtar`) writes
//! into each `-C DIR` / `--directory DIR`, or into the working directory without
//! one; `unzip` writes into `-d DIR`, or the working directory. The folder is
//! the `fs.write`: the names inside the archive are not on the command line, so
//! a deny on the folder (`kernel-self` on `~/.claude`) or on paths inside it
//! (the folder rule, ADR-038) decides. `ditto SRC DST` is a copy (`copy.rs`).
//! The archive and a `-C` folder stay reads as well (`operands.rs`).

use crate::paths;

const TARS: &[&str] = &["tar", "gtar", "bsdtar"];

/// `unzip` options that list, test or print an archive instead of extracting it.
const UNZIP_NO_EXTRACT: &[char] = &['l', 't', 'v', 'p', 'c', 'z', 'Z'];

/// The folders `program` extracts into, `.` for the working directory; empty
/// when it does not extract.
pub(super) fn destinations(argv: &[String], program: &str) -> Vec<String> {
    if TARS.contains(&program) {
        tar(argv)
    } else if program == "unzip" {
        unzip(argv)
    } else {
        Vec::new()
    }
}

/// Extract mode is `-x`, an `x` in a short-option cluster or in the bundled
/// first word (`tar xzf a.tgz`), `--extract` or a prefix of it, or `--get`. A
/// relative `-C` is taken inside the one before it, as tar does.
fn tar(argv: &[String]) -> Vec<String> {
    let mut extract = false;
    let mut dirs: Vec<String> = Vec::new();
    let mut words = argv.iter().enumerate().skip(1);
    while let Some((i, word)) = words.next() {
        if word == "--" {
            break;
        }
        let bundled = i == 1 && !word.is_empty() && word.chars().all(|c| c.is_ascii_alphabetic());
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            if name == "get" || (name.len() >= 3 && "extract".starts_with(name)) {
                extract = true;
            } else if (name == "cd" || (name.len() >= 3 && "directory".starts_with(name)))
                && let Some(dir) = value.or_else(|| words.next().map(|(_, w)| w.as_str()))
            {
                push_dir(&mut dirs, dir);
            }
        } else if let Some(cluster) = word.strip_prefix('-').or(bundled.then_some(word.as_str())) {
            if cluster == "C" {
                if let Some((_, dir)) = words.next() {
                    push_dir(&mut dirs, dir);
                }
            } else if let Some(dir) = cluster.strip_prefix('C').filter(|d| !d.is_empty()) {
                push_dir(&mut dirs, dir);
            } else if cluster.contains('x') {
                extract = true;
            }
        }
    }
    match (extract, dirs.is_empty()) {
        (false, _) => Vec::new(),
        (true, true) => vec![".".to_owned()],
        (true, false) => dirs,
    }
}

/// Add `dir`, inside the folder before it when relative.
fn push_dir(dirs: &mut Vec<String>, dir: &str) {
    let joined = match dirs.last() {
        Some(prev) if !paths::is_absolute(dir) && !dir.starts_with(['~', '$']) => {
            format!("{}/{dir}", prev.trim_end_matches('/'))
        }
        _ => dir.to_owned(),
    };
    dirs.push(joined);
}

/// `-d DIR`, `-dDIR` or a cluster ending in `d` (`-qd DIR`); without one, the
/// working directory unless an option lists, tests or prints instead.
fn unzip(argv: &[String]) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut no_extract = false;
    let mut words = argv.iter().skip(1);
    while let Some(word) = words.next() {
        let Some(cluster) = word.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        let flags = match cluster.split_once('d') {
            Some((flags, "")) => {
                dirs.extend(words.next().cloned());
                flags
            }
            Some((flags, dir)) => {
                dirs.push(dir.to_owned());
                flags
            }
            None => cluster,
        };
        no_extract |= flags.contains(UNZIP_NO_EXTRACT);
    }
    if dirs.is_empty() && !no_extract {
        dirs.push(".".to_owned());
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::destinations;

    fn of(cmd: &str) -> Vec<String> {
        let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        destinations(&argv, &argv[0])
    }

    #[test]
    fn tar_extracts_into_each_folder_it_is_given() {
        for (cmd, dirs) in [
            ("tar xf e.tar -C ~/.claude", &["~/.claude"][..]),
            ("tar -xzf e.tgz -C /p/vendor", &["/p/vendor"]),
            ("tar -x -f e.tar -C/tmp/x", &["/tmp/x"]),
            (
                "tar --extract --file e.tar --directory ~/.moat",
                &["~/.moat"],
            ),
            ("tar --get -f e.tar --directory=~/.codex", &["~/.codex"]),
            ("tar --extr -f e.tar --dir ~/.codex", &["~/.codex"]),
            ("bsdtar -xf e.tar --cd ~/.claude", &["~/.claude"]),
            ("gtar xvf e.tar -C ~ -C .claude", &["~", "~/.claude"]),
            ("tar -xf e.tar -C /a -C /b", &["/a", "/b"]),
            ("tar xf vendor.tar", &["."]),
            ("tar -xf vendor.tar", &["."]),
        ] {
            assert_eq!(of(cmd), dirs, "{cmd}");
        }
    }

    #[test]
    fn tar_in_other_modes_extracts_nothing() {
        for cmd in [
            "tar czf a.tgz -C ~ .codex",
            "tar -cf a.tar src",
            "tar tf vendor.tar",
            "tar -tvf vendor.tar",
            "tar --create -f a.tar --exclude x src",
            "tar -cf a.tar -- -x",
            "cp -x a b",
        ] {
            assert!(of(cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn unzip_extracts_into_its_folder_or_the_working_directory() {
        for (cmd, dirs) in [
            ("unzip e.zip -d ~/.moat", &["~/.moat"][..]),
            ("unzip -o e.zip -d /p/out", &["/p/out"]),
            ("unzip -qd /p/out e.zip", &["/p/out"]),
            ("unzip -d/p/out e.zip", &["/p/out"]),
            ("unzip a.zip", &["."]),
            ("unzip -o a.zip", &["."]),
            ("unzip -l a.zip", &[]),
            ("unzip -tq a.zip", &[]),
            ("unzip -p a.zip f", &[]),
        ] {
            assert_eq!(of(cmd), dirs, "{cmd}");
        }
    }
}
