//! `sed`: the script is data, read by `script.rs`, never as shell.
//!
//! A script's words are not file operands (`sed -n '/a/,/b/p' f` reads only
//! `f`). Files it reads or writes (`r FILE`, `w FILE`) become `fs` atoms. A
//! script that runs a command or cannot be read, a script file (`-f`, itself a
//! read) and an unknown option become a `sed @<text>` atom, which `text-tools`
//! excludes.
//!
//! GNU sed lets options follow operands and takes the in-place suffix only
//! attached (`-i.bak`); BSD sed stops at the first operand and takes a bare
//! `-i`'s suffix from the next word (`-i ''`). Every word either one could take
//! for the script is read as one, and stays a file operand unless both agree.
//! `-i` makes the file operands, and their backups, writes.

mod script;
#[cfg(test)]
mod tests;

use super::text::{Arg, Operands, Spec, parse, unproven};
use super::{ClassifyError, ShellContext, Sink};

const SED: Spec = Spec {
    flags: "nErsuz",
    valued: "ef",
    optional: "i",
    long_flags: &[
        "quiet",
        "silent",
        "regexp-extended",
        "separate",
        "unbuffered",
        "null-data",
        "posix",
        "debug",
        "sandbox",
        "follow-symlinks",
    ],
    long_valued: &["expression", "file"],
    long_optional: &["in-place"],
    permute: true,
};

/// The command line as both sed implementations may read it.
#[derive(Default)]
struct Line<'a> {
    /// `-e` values: scripts to GNU sed; files to BSD sed after an operand.
    scripts: Vec<&'a str>,
    /// An `-e` comes before the first operand, so BSD sed has a script too.
    script_first: bool,
    operands: Vec<usize>,
    in_place: bool,
    suffixes: Vec<&'a str>,
    /// `-i ''`: to BSD sed the empty word is the suffix and the next operand the script.
    empty_suffix: bool,
}

pub(super) fn classify(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<Operands, ClassifyError> {
    let mut ops = Operands::default();
    let mut line = Line::default();
    for arg in parse(argv, &SED) {
        match arg {
            Arg::Opt {
                name: "e" | "expression",
                value: Some(script),
                data,
            } => {
                line.script_first |= line.operands.is_empty();
                line.scripts.push(script);
                ops.data.extend(data);
            }
            Arg::Opt {
                name: name @ ("i" | "in-place"),
                value,
                data,
            } => {
                line.in_place = true;
                line.suffixes.extend(value);
                // A bare `-i`: BSD sed takes the next word as the suffix.
                let next = data.filter(|_| name == "i" && value.is_none());
                match next.and_then(|at| argv.get(at + 1)).map(String::as_str) {
                    Some("") => line.empty_suffix = true,
                    Some(word) if word.starts_with('-') => line.suffixes.push(word),
                    Some(_) => unproven(argv, "-i", sink)?,
                    None => {}
                }
            }
            // The script is unknown, the file that holds it is read.
            Arg::Opt {
                name: "f" | "file",
                value,
                ..
            } => {
                unproven(argv, "-f", sink)?;
                if let Some(file) = value {
                    sink.read(ctx, file)?;
                }
            }
            Arg::Unknown(word) => unproven(argv, word, sink)?,
            Arg::Opt { .. } => {}
            Arg::Operand(at) => line.operands.push(at),
        }
    }
    for (at, is_data) in operand_scripts(argv, &line) {
        if is_data {
            ops.data.push(at);
        }
        check(argv, &argv[at], ctx, sink)?;
    }
    for script in &line.scripts {
        check(argv, script, ctx, sink)?;
    }
    if line.in_place {
        in_place(argv, &line, &mut ops, ctx, sink)?;
    }
    Ok(ops)
}

/// Operands that one implementation reads as the script, with true when the
/// other agrees, so the word is no file.
fn operand_scripts(argv: &[String], line: &Line<'_>) -> Vec<(usize, bool)> {
    let first = line.operands.first().copied();
    if !line.scripts.is_empty() {
        // BSD sed stops at the first operand: the script unless an `-e` came first.
        return first
            .filter(|_| !line.script_first)
            .map(|at| vec![(at, false)])
            .unwrap_or_default();
    }
    let mut found: Vec<_> = first.map(|at| (at, true)).into_iter().collect();
    if line.empty_suffix && first.is_some_and(|at| argv[at].is_empty()) {
        found.extend(line.operands.get(1).map(|&at| (at, false)));
    }
    found
}

/// Record the files `script` touches, or report it when it may do more.
fn check(
    argv: &[String],
    script: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let Some(effects) = script::effects(script) else {
        return unproven(argv, script, sink);
    };
    for file in &effects.reads {
        sink.read(ctx, &literal(file))?;
    }
    for file in &effects.writes {
        sink.write(ctx, &literal(file))?;
    }
    Ok(())
}

/// Every file operand is rewritten, and backed up next to itself.
fn in_place(
    argv: &[String],
    line: &Line<'_>,
    ops: &mut Operands,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    // GNU sed puts the backup elsewhere when the suffix has a `/` or a `*`.
    if let Some(suffix) = line.suffixes.iter().find(|s| s.contains(['/', '*'])) {
        return unproven(argv, suffix, sink);
    }
    let files: Vec<usize> = line
        .operands
        .iter()
        .copied()
        .filter(|i| !ops.data.contains(i))
        .collect();
    for &file in &files {
        for suffix in line.suffixes.iter().filter(|s| !s.is_empty()) {
            sink.write(ctx, &format!("{}{suffix}", argv[file]))?;
        }
    }
    ops.writes.extend(files);
    Ok(())
}

/// sed does not expand `~`: `w ~/x` writes `./~/x`.
fn literal(file: &str) -> String {
    if file.starts_with('~') {
        format!("./{file}")
    } else {
        file.to_owned()
    }
}
