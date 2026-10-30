//! Text tools whose arguments are data, not files or shell: `sort`, `uniq`,
//! `cut`, and `sed` (`sed/`) and `awk` (`awk.rs`), whose programs are data too.
//!
//! These tools read their file operands and print, except for a few options and
//! operands that write a file (`sort -o out`, `uniq in out`) or run a program
//! (`sort --compress-program=gzip`). Their options are read the way getopt reads
//! them: an option value is data, never a file operand, and a file the command
//! writes becomes an `fs.write`. Anything the classifier does not know to be
//! harmless becomes a `<program> @<argument>` shell atom; the default policy's
//! `text-tools` rule excludes those, so the command asks.

use super::{ClassifyError, ShellContext, Sink, awk, sed};
use crate::action::AtomicAction;
use crate::lexer::Word;

/// What the caller must know about a text tool's arguments.
#[derive(Debug, Default)]
pub(super) struct Operands {
    /// argv indices that are program text or option values, not files.
    pub data: Vec<usize>,
    /// argv indices of operands that the command writes.
    pub writes: Vec<usize>,
}

/// How a program reads its options.
pub(super) struct Spec {
    /// Short options that take no value.
    pub flags: &'static str,
    /// Short options whose value is the rest of the word or the next word.
    pub valued: &'static str,
    /// Short options whose value, if any, is the rest of the word (`sed -i.bak`).
    pub optional: &'static str,
    /// Long options (without `--`) that take no value.
    pub long_flags: &'static [&'static str],
    /// Long options whose value follows `=` or is the next word.
    pub long_valued: &'static [&'static str],
    /// Long options whose value, if any, follows `=`.
    pub long_optional: &'static [&'static str],
    /// GNU getopt order: options may follow operands, up to `--`. Without it the
    /// first operand ends the options (POSIX, BSD, awk).
    pub permute: bool,
}

/// One argument as getopt reads it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Arg<'a> {
    /// An option (`"n"`, or a long name without `--`) with its value.
    Opt {
        name: &'a str,
        value: Option<&'a str>,
        /// The word holding the value, when it can only be a value. A separate
        /// value after an operand is a file to a getopt that does not permute.
        data: Option<usize>,
    },
    /// The argv index of an operand.
    Operand(usize),
    /// A word that looks like an option the spec does not know.
    Unknown(&'a str),
}

/// Classify a text tool's options; for any other program, nothing. `words`
/// are `argv` as the lexer read them, for what the shell expands in them.
pub(super) fn classify(
    argv: &[String],
    words: &[Word],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<Operands, ClassifyError> {
    let (mut ops, operands) = match program {
        "sed" => return sed::classify(argv, ctx, sink),
        "awk" => return awk::classify(argv, words, sink),
        "sort" => options(argv, &SORT, SORT_WRITES, ctx, sink)?,
        "uniq" => options(argv, &UNIQ, &[], ctx, sink)?,
        "cut" => options(argv, &CUT, &[], ctx, sink)?,
        _ => return Ok(Operands::default()),
    };
    if program == "uniq" {
        // `uniq INPUT OUTPUT` writes its second operand.
        ops.writes.extend(operands.get(1));
    }
    Ok(ops)
}

/// `sort` options whose value is a file it writes (temporary files go in `-T`).
const SORT_WRITES: &[&str] = &["o", "T", "output", "temporary-directory"];

const SORT: Spec = Spec {
    flags: "bcCdfghiMmnRrsuVz",
    valued: "kStTo",
    optional: "",
    long_flags: &[
        "ignore-leading-blanks",
        "dictionary-order",
        "ignore-case",
        "general-numeric-sort",
        "ignore-nonprinting",
        "month-sort",
        "human-numeric-sort",
        "numeric-sort",
        "random-sort",
        "reverse",
        "version-sort",
        "check",
        "merge",
        "stable",
        "unique",
        "zero-terminated",
        "debug",
    ],
    long_valued: &[
        "key",
        "sort",
        "buffer-size",
        "field-separator",
        "parallel",
        "output",
        "temporary-directory",
    ],
    long_optional: &[],
    permute: true,
};

const UNIQ: Spec = Spec {
    flags: "cdDiuz",
    valued: "fsw",
    optional: "",
    long_flags: &[
        "count",
        "repeated",
        "ignore-case",
        "unique",
        "zero-terminated",
    ],
    long_valued: &["skip-fields", "skip-chars", "check-chars"],
    long_optional: &["all-repeated", "group"],
    permute: true,
};

const CUT: Spec = Spec {
    flags: "nsz",
    valued: "bcdf",
    optional: "",
    long_flags: &["complement", "only-delimited", "zero-terminated"],
    long_valued: &[
        "bytes",
        "characters",
        "delimiter",
        "fields",
        "output-delimiter",
    ],
    long_optional: &[],
    permute: true,
};

/// Option values are data; the values of `writes` options are written files;
/// an unknown option is reported. Also returns the operands' argv indices.
fn options(
    argv: &[String],
    spec: &Spec,
    writes: &[&str],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(Operands, Vec<usize>), ClassifyError> {
    let mut ops = Operands::default();
    let mut operands = Vec::new();
    for arg in parse(argv, spec) {
        match arg {
            Arg::Opt { name, value, data } => {
                ops.data.extend(data);
                if let Some(path) = value.filter(|_| writes.contains(&name)) {
                    sink.write(ctx, path)?;
                }
            }
            Arg::Unknown(word) => unproven(argv, word, sink)?,
            Arg::Operand(i) => operands.push(i),
        }
    }
    Ok((ops, operands))
}

/// Report `text`, which the classifier cannot prove harmless, as `<program> @<text>`.
pub(super) fn unproven(argv: &[String], text: &str, sink: &mut Sink) -> Result<(), ClassifyError> {
    sink.push(AtomicAction::Shell {
        argv: vec![argv[0].clone(), format!("@{text}")],
    })
}

/// Read `argv` the way getopt does with `spec`.
pub(super) fn parse<'a>(argv: &'a [String], spec: &Spec) -> Vec<Arg<'a>> {
    let mut parsed = Vec::new();
    let mut at = 1;
    let mut options_ended = false;
    let mut seen_operand = false;
    while let Some(word) = argv.get(at) {
        let next = argv.get(at + 1).map(String::as_str);
        // A separate value is data only where no getopt could take it for a file.
        let separate = (!seen_operand).then_some(at + 1);
        if options_ended || word == "-" || !word.starts_with('-') {
            parsed.push(Arg::Operand(at));
            seen_operand = true;
            options_ended |= !spec.permute;
        } else if word == "--" {
            options_ended = true;
        } else {
            let (arg, took_next) = match word.strip_prefix("--") {
                Some(long) => long_option(word, long, next, spec, at, separate),
                None => short_cluster(word, next, spec, at, separate, &mut parsed),
            };
            parsed.push(arg);
            at += usize::from(took_next);
        }
        at += 1;
    }
    parsed
}

/// `--name`, `--name=value` or `--name value`; true when the value is the next word.
fn long_option<'a>(
    word: &'a str,
    long: &'a str,
    next: Option<&'a str>,
    spec: &Spec,
    at: usize,
    separate: Option<usize>,
) -> (Arg<'a>, bool) {
    let (name, attached) = match long.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (long, None),
    };
    let opt = |value, data| Arg::Opt { name, value, data };
    if spec.long_flags.contains(&name) && attached.is_none() {
        (opt(None, None), false)
    } else if spec.long_optional.contains(&name) {
        (opt(attached, Some(at)), false)
    } else if !spec.long_valued.contains(&name) {
        (Arg::Unknown(word), false)
    } else if attached.is_some() {
        (opt(attached, Some(at)), false)
    } else if next.is_some() {
        (opt(next, separate), true)
    } else {
        (Arg::Unknown(word), false)
    }
}

/// `-abc`, `-kVALUE`, `-k VALUE`: every option but the last goes to `args`; the
/// last is returned, with true when its value is the next word.
fn short_cluster<'a>(
    word: &'a str,
    next: Option<&'a str>,
    spec: &Spec,
    at: usize,
    separate: Option<usize>,
    args: &mut Vec<Arg<'a>>,
) -> (Arg<'a>, bool) {
    let cluster = &word[1..];
    for (pos, c) in cluster.char_indices() {
        let name = &cluster[pos..pos + c.len_utf8()];
        let rest = &cluster[pos + c.len_utf8()..];
        let opt = |value, data| Arg::Opt { name, value, data };
        if spec.flags.contains(c) {
            if rest.is_empty() {
                return (opt(None, None), false);
            }
            args.push(opt(None, None));
        } else if spec.optional.contains(c) {
            return (opt(Some(rest).filter(|r| !r.is_empty()), Some(at)), false);
        } else if spec.valued.contains(c) && !rest.is_empty() {
            return (opt(Some(rest), Some(at)), false);
        } else if spec.valued.contains(c) && next.is_some() {
            return (opt(next, separate), true);
        } else {
            break;
        }
    }
    (Arg::Unknown(word), false)
}

#[cfg(test)]
mod tests {
    use super::{Arg, SORT, parse};

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn options_values_and_operands() {
        let a = argv("sort -rnk 2 data.txt -o out --key=3 -- -x");
        let opt = |name, value, data| Arg::Opt { name, value, data };
        assert_eq!(
            parse(&a, &SORT),
            [
                opt("r", None, None),
                opt("n", None, None),
                opt("k", Some("2"), Some(2)),
                Arg::Operand(3),
                // after an operand, BSD sort reads `out` as a file
                opt("o", Some("out"), None),
                opt("key", Some("3"), Some(6)),
                Arg::Operand(8),
            ]
        );
    }

    #[test]
    fn unknown_options_and_missing_values() {
        for line in [
            "sort --compress-program=gzip",
            "sort --comp=x",
            "sort -y",
            "sort -k",
        ] {
            let a = argv(line);
            assert!(
                matches!(parse(&a, &SORT).as_slice(), [Arg::Unknown(_)]),
                "{line}"
            );
        }
    }
}
