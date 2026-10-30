//! Pipe consumers that keep only the variable names of an environment listing.
//!
//! `env | cut -d= -f1`, `printenv | sed 's/=.*//'` and `env | awk -F= '{print
//! $1}'` print the names and drop every value, so the listing is not the dump
//! the `env-dump` rule denies: its atom becomes `env @names-only`. Only these
//! exact filters count; `| grep`, `| sort`, `| head`, `| cut -d= -f2` and
//! `| tee` pass values on and leave the listing as it is.

use crate::shell::tables::ENV_BUILTINS;
use crate::shell::tokens::basename;

/// Programs that print every environment variable when given no name.
const LISTERS: &[&str] = &["env", "printenv"];

/// Whether `program` (`argv`) lists the environment and the stage it pipes
/// into, `consumer`, keeps only the names.
pub(super) fn keeps_only_names(argv: &[String], program: &str, consumer: &[String]) -> bool {
    let lists = LISTERS.contains(&program) || ENV_BUILTINS.contains(&program);
    lists && argv[1..].iter().all(|a| a.starts_with('-')) && names_only(consumer)
}

/// Whether the stage prints the text before the first `=` of each line and
/// nothing else.
fn names_only(stage: &[String]) -> bool {
    let Some((program, args)) = stage.split_first() else {
        return false;
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match basename(program) {
        "cut" => cut_first_field(&args),
        "sed" => sed_strips_values(&args),
        "awk" => awk_first_field(&args),
        _ => false,
    }
}

/// `cut -d= -f1` in each spelling of its two options, `-s` allowed.
fn cut_first_field(args: &[&str]) -> bool {
    let (mut delimiter, mut field) = (false, false);
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let separate = matches!(*arg, "-d" | "--delimiter" | "-f" | "--fields");
        let next = args.get(i + 1).copied();
        match option_value(arg, "-d", "--delimiter", next) {
            Some("=") => delimiter = true,
            Some(_) => return false,
            None => match option_value(arg, "-f", "--fields", next) {
                Some("1") => field = true,
                None if matches!(*arg, "-s" | "--only-delimited") => {}
                Some(_) | None => return false,
            },
        }
        i += 1 + usize::from(separate);
    }
    delimiter && field
}

/// The value of `arg` as the option `short`/`long`: attached (`-d=`,
/// `--delimiter==`) or the next word (`-d =`, `--delimiter =`).
fn option_value<'a>(
    arg: &'a str,
    short: &str,
    long: &str,
    next: Option<&'a str>,
) -> Option<&'a str> {
    if arg == short || arg == long {
        return next;
    }
    arg.strip_prefix(short)
        .or_else(|| arg.strip_prefix(long)?.strip_prefix('='))
}

/// `sed 's/=.*//'` or `sed -E 's/=.*$//'`: one script that deletes from the
/// first `=` to the end of the line, with any delimiter and no file operand.
fn sed_strips_values(args: &[&str]) -> bool {
    let mut script = None;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match *arg {
            "-E" | "-r" | "--regexp-extended" => {}
            "-e" | "--expression" => {
                let Some(next) = args.get(i + 1) else {
                    return false;
                };
                if script.replace(*next).is_some() {
                    return false;
                }
                i += 1;
            }
            _ if arg.starts_with('-') || script.is_some() => return false,
            _ => script = Some(arg),
        }
        i += 1;
    }
    script.is_some_and(strips_values)
}

/// `s<d>=.*<d><d>` or `s<d>=.*$<d><d>` for one delimiter character `<d>`.
fn strips_values(script: &str) -> bool {
    let Some(rest) = script.strip_prefix('s') else {
        return false;
    };
    let mut chars = rest.chars();
    let Some(delimiter) = chars.next() else {
        return false;
    };
    if delimiter.is_alphanumeric() || matches!(delimiter, '\\' | '=' | '.' | '*' | '$') {
        return false;
    }
    let tail = format!("{delimiter}{delimiter}");
    let Some(pattern) = chars.as_str().strip_suffix(&tail) else {
        return false;
    };
    pattern == "=.*" || pattern == "=.*$"
}

/// `awk -F= '{print $1}'`, the separator given attached or as the next word.
fn awk_first_field(args: &[&str]) -> bool {
    let program = match args {
        ["-F=", program] | ["-F", "=", program] => *program,
        _ => return false,
    };
    let compact: String = program.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "{print$1}" || compact == "{print$1;}"
}

#[cfg(test)]
mod tests {
    use super::names_only;

    fn stage(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn filters_that_keep_only_names() {
        for words in [
            &["cut", "-d=", "-f1"][..],
            &["cut", "-d", "=", "-f", "1"],
            &["cut", "-f1", "-d="],
            &["cut", "-s", "-d=", "-f1"],
            &["cut", "--delimiter==", "--fields=1"],
            &["/usr/bin/cut", "-d=", "-f1"],
            &["sed", "s/=.*//"],
            &["sed", "-E", "s/=.*$//"],
            &["sed", "-e", "s/=.*//"],
            &["sed", "s#=.*##"],
            &["awk", "-F=", "{print $1}"],
            &["awk", "-F", "=", "{print$1}"],
            &["awk", "-F=", "{ print $1 }"],
        ] {
            assert!(names_only(&stage(words)), "{words:?}");
        }
    }

    #[test]
    fn filters_that_pass_values_on() {
        for words in [
            &["cut", "-d=", "-f2"][..],
            &["cut", "-d=", "-f1-"],
            &["cut", "-d=", "-f1,2"],
            &["cut", "-d:", "-f1"],
            &["cut", "-d=", "-f1", "names.txt"],
            &["cut", "-c1"],
            &["cut", "-d="],
            &["sed", "s/=/ /"],
            &["sed", "s/=.*//g"],
            &["sed", "-n", "s/=.*//p"],
            &["sed", "s/=.*//", "file"],
            &["sed", "-e", "s/=.*//", "-e", "p"],
            &["sed", "s/=.*$//;p"],
            &["awk", "-F=", "{print $2}"],
            &["awk", "-F=", "{print $1, $2}"],
            &["awk", "{print $1}"],
            &["grep", "-i", "key"],
            &["sort"],
            &["head"],
            &["base64"],
            &["tee", "out"],
        ] {
            assert!(!names_only(&stage(words)), "{words:?}");
        }
    }
}
