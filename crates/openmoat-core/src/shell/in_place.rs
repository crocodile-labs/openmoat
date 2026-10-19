//! Commands that rewrite the files they name: `perl -i` and `ruby -i` edit their
//! file operands in place (and write a backup when given a suffix), and `patch`
//! writes the file it patches and its `-o` and `-r` files and reads its `-i`
//! patch file. Each becomes an `fs.write` (or `fs.read`), so the write rules
//! apply. Interpreter code itself is not read here.

use super::{ClassifyError, ShellContext, Sink};

/// Options of `perl` and `ruby` whose value is the rest of the word or else the
/// next word; every other letter that takes a value takes only the rest.
fn takes_next(program: &str, c: char) -> bool {
    match program {
        "perl" => matches!(c, 'e' | 'E'),
        _ => matches!(c, 'e' | 'I' | 'r' | 'C' | 'E'),
    }
}

/// Letters that take the rest of the word as their value.
fn takes_rest(program: &str, c: char) -> bool {
    match program {
        "perl" => "ilx0CdDFIMmV".contains(c),
        _ => "ix0WFKT".contains(c),
    }
}

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match program {
        "perl" | "ruby" => interpreter(argv, program, ctx, sink),
        "patch" => patch(argv, ctx, sink),
        _ => Ok(()),
    }
}

fn interpreter(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let mut suffix: Option<&str> = None;
    let mut code = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            break;
        };
        i += 1;
        if cluster.starts_with('-') {
            continue;
        }
        for (pos, c) in cluster.char_indices() {
            let rest = &cluster[pos + c.len_utf8()..];
            if c == 'i' {
                suffix = Some(rest);
                break;
            }
            if takes_next(program, c) {
                code |= matches!(c, 'e' | 'E') && !(program == "ruby" && c == 'E');
                i += usize::from(rest.is_empty());
                break;
            }
            if takes_rest(program, c) {
                break;
            }
        }
    }
    let Some(suffix) = suffix else {
        return Ok(());
    };
    // without `-e`, the first operand is the script
    let files = argv
        .get(i..)
        .unwrap_or_default()
        .iter()
        .skip(usize::from(!code));
    for file in files {
        sink.write(ctx, file)?;
        if suffix.contains('*') {
            sink.write(ctx, &suffix.replace('*', file))?;
        } else if !suffix.is_empty() {
            sink.write(ctx, &format!("{file}{suffix}"))?;
        }
    }
    Ok(())
}

/// `patch` options whose value is the rest of the word or the next word.
const PATCH_VALUED: &str = "BDdFgioprVYz";
const PATCH_LONG_VALUED: &[&str] = &[
    "input",
    "output",
    "reject-file",
    "directory",
    "strip",
    "prefix",
    "suffix",
    "basename-prefix",
    "ifdef",
    "fuzz",
    "version-control",
    "quoting-style",
    "get",
];

/// `patch [OPTION]… [ORIGFILE [PATCHFILE]]`.
fn patch(argv: &[String], ctx: &ShellContext<'_>, sink: &mut Sink) -> Result<(), ClassifyError> {
    let mut operands = Vec::new();
    let mut options = true;
    let mut words = argv[1..].iter();
    while let Some(arg) = words.next() {
        if !options || arg == "-" || !arg.starts_with('-') {
            operands.push(arg.as_str());
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        let (name, value) = if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None if PATCH_LONG_VALUED.contains(&long) => (long, words.next().cloned()),
                None => (long, None),
            }
        } else {
            let cluster = &arg[1..];
            match cluster
                .char_indices()
                .find(|(_, c)| PATCH_VALUED.contains(*c))
            {
                Some((pos, c)) => {
                    let rest = &cluster[pos + c.len_utf8()..];
                    let value = if rest.is_empty() {
                        words.next().cloned()
                    } else {
                        Some(rest.to_owned())
                    };
                    (&cluster[pos..pos + c.len_utf8()], value)
                }
                None => continue,
            }
        };
        let Some(value) = value.filter(|v| !v.is_empty() && v != "-") else {
            continue;
        };
        match name {
            "i" | "input" => sink.read(ctx, &value)?,
            "o" | "output" | "r" | "reject-file" => sink.write(ctx, &value)?,
            _ => {}
        }
    }
    let mut operands = operands.into_iter().filter(|o| *o != "-");
    if let Some(target) = operands.next() {
        sink.write(ctx, target)?;
    }
    if let Some(patch_file) = operands.next() {
        sink.read(ctx, patch_file)?;
    }
    Ok(())
}
