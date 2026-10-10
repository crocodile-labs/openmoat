//! How a shell (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`) was asked to run:
//! a command string, a script file, or a program read from stdin.
//!
//! `bash -lc 'cmd'`, `sh -ec 'cmd'`, `bash --login -c 'cmd'` and `bash -c -- 'cmd'`
//! all run `cmd`, so options are parsed the way the shell parses them instead of
//! looking for a literal `-c`. POSIX shells take `c` as a flag anywhere in an
//! option cluster and run the first operand; fish takes the command as the value
//! of `-c`. An option whose meaning is unknown could swallow the operand that
//! holds the command, so it makes the command line unparseable (`ask`).

use super::ClassifyError;

/// What one shell invocation executes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ShellRun<'a> {
    /// Command strings the shell runs (`-c`, fish `-C`/`--init-command`).
    pub code: Vec<&'a str>,
    /// The script file operand, when there is one.
    pub script: Option<&'a str>,
    /// True when the shell reads its program from stdin (`bash`, `bash -s`, `sh -`).
    pub reads_stdin: bool,
}

/// Option grammar of one shell.
struct Grammar {
    /// Short options that consume the next argument (`-o pipefail`, `+O extglob`).
    short_values: &'static str,
    /// Long options that consume the next argument unless written `--name=value`.
    long_values: &'static [&'static str],
    /// Long options without a value; `None` accepts any name (zsh `--sh-word-split`).
    long_flags: Option<&'static [&'static str]>,
}

const BASH_LONG_FLAGS: &[&str] = &[
    "debug",
    "debugger",
    "dump-po-strings",
    "dump-strings",
    "help",
    "login",
    "noediting",
    "noprofile",
    "norc",
    "posix",
    "pretty-print",
    "protected",
    "restricted",
    "verbose",
    "version",
];

const BASH: Grammar = Grammar {
    short_values: "oO",
    long_values: &["rcfile", "init-file"],
    long_flags: Some(BASH_LONG_FLAGS),
};
// `sh` is bash in POSIX mode on macOS and dash on Debian. Only what both read
// the same way is understood: dash rejects every long option, and bash's `-O`
// takes a value, so `sh -O extglob -c X` still runs `X`.
const SH: Grammar = Grammar {
    short_values: "oO",
    long_values: &[],
    long_flags: Some(&[]),
};
const DASH: Grammar = Grammar {
    short_values: "o",
    long_values: &[],
    long_flags: Some(&[]),
};
// zsh accepts every option name as `--name` and has one long option with a value.
const ZSH: Grammar = Grammar {
    short_values: "o",
    long_values: &["emulate"],
    long_flags: None,
};
// ksh93 `-R file`, mksh `-T tty`.
const KSH: Grammar = Grammar {
    short_values: "oRT",
    long_values: &[],
    long_flags: Some(&[]),
};

/// fish options (getopt, stops at the first operand): `c` and `C` carry code.
const FISH_SHORT_FLAGS: &str = "hPilNnv";
const FISH_SHORT_VALUES: &str = "cCpdfDo";
const FISH_LONG_FLAGS: &[&str] = &[
    "help",
    "interactive",
    "login",
    "no-config",
    "no-execute",
    "print-debug-categories",
    "print-rusage-self",
    "private",
    "version",
];
const FISH_LONG_VALUES: &[&str] = &[
    "command",
    "init-command",
    "debug",
    "debug-output",
    "debug-stack-frames",
    "features",
    "profile",
    "profile-startup",
];

/// Parse the options of `argv` (`argv[0]` is the shell) for the shell `program`.
pub(super) fn parse<'a, S: AsRef<str>>(
    program: &str,
    argv: &'a [S],
) -> Result<ShellRun<'a>, ClassifyError> {
    let words: Vec<&'a str> = argv.iter().skip(1).map(AsRef::as_ref).collect();
    let grammar = match program {
        "fish" => return fish(&words),
        "zsh" => &ZSH,
        "sh" => &SH,
        "dash" => &DASH,
        "ksh" => &KSH,
        _ => &BASH,
    };
    posix(grammar, program, &words)
}

fn unknown(program: &str, option: &str) -> ClassifyError {
    ClassifyError::ShellOption {
        program: program.to_owned(),
        option: option.to_owned(),
    }
}

fn posix<'a>(
    grammar: &Grammar,
    program: &str,
    args: &[&'a str],
) -> Result<ShellRun<'a>, ClassifyError> {
    let (mut command, mut stdin) = (false, false);
    let mut i = 0;
    while let Some(&arg) = args.get(i) {
        i += 1;
        // `-` ends the options like `--` (POSIX: the first operand, then ignored).
        if arg == "--" || arg == "-" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline_value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            let known_flag = grammar.long_flags.is_none_or(|f| f.contains(&name));
            if grammar.long_values.contains(&name) {
                i += usize::from(!inline_value);
            } else if inline_value || !known_flag {
                return Err(unknown(program, arg));
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix(['-', '+']).filter(|c| !c.is_empty()) else {
            i -= 1;
            break;
        };
        for c in cluster.chars() {
            match c {
                'c' => command = true,
                's' => stdin = true,
                _ if grammar.short_values.contains(c) => i += 1,
                _ if c.is_ascii_alphanumeric() => {}
                _ => return Err(unknown(program, arg)),
            }
        }
    }
    let operand = args.get(i).copied();
    if command {
        let code = operand.ok_or_else(|| unknown(program, "-c without a command"))?;
        return Ok(ShellRun {
            code: vec![code],
            ..ShellRun::default()
        });
    }
    let script = operand.filter(|_| !stdin);
    Ok(ShellRun {
        code: Vec::new(),
        script,
        reads_stdin: script.is_none(),
    })
}

fn fish<'a>(args: &[&'a str]) -> Result<ShellRun<'a>, ClassifyError> {
    let mut code = Vec::new();
    let mut command = false;
    let mut i = 0;
    while let Some(&arg) = args.get(i) {
        i += 1;
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            if FISH_LONG_VALUES.contains(&name) {
                let value = fish_value(inline, args, &mut i, arg)?;
                command |= name == "command";
                if name == "command" || name == "init-command" {
                    code.push(value);
                }
            } else if inline.is_some() || !FISH_LONG_FLAGS.contains(&name) {
                return Err(unknown("fish", arg));
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            i -= 1;
            break;
        };
        for (pos, c) in cluster.char_indices() {
            if FISH_SHORT_VALUES.contains(c) {
                let rest = Some(&cluster[pos + c.len_utf8()..]).filter(|r| !r.is_empty());
                let value = fish_value(rest, args, &mut i, arg)?;
                command |= c == 'c';
                if c == 'c' || c == 'C' {
                    code.push(value);
                }
                break;
            }
            if !FISH_SHORT_FLAGS.contains(c) {
                return Err(unknown("fish", arg));
            }
        }
    }
    let operand = args.get(i).copied().filter(|_| !command);
    Ok(ShellRun {
        code,
        script: operand.filter(|s| *s != "-"),
        reads_stdin: !command && operand.is_none_or(|s| s == "-"),
    })
}

/// An option's value: attached (`-cX`, `--command=X`) or the next argument.
fn fish_value<'a>(
    attached: Option<&'a str>,
    args: &[&'a str],
    i: &mut usize,
    option: &str,
) -> Result<&'a str, ClassifyError> {
    if let Some(value) = attached {
        return Ok(value);
    }
    let value = args
        .get(*i)
        .copied()
        .ok_or_else(|| unknown("fish", option))?;
    *i += 1;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::shell::tokens::basename;

    /// `(code, script, reads_stdin)` for a space-separated command line.
    fn run(cmd: &str) -> (Vec<String>, Option<String>, bool) {
        let argv: Vec<&str> = cmd.split(' ').collect();
        let r = parse(basename(argv[0]), &argv).unwrap_or_else(|e| panic!("`{cmd}`: {e}"));
        let code = r.code.iter().map(|c| (*c).to_owned()).collect();
        (code, r.script.map(str::to_owned), r.reads_stdin)
    }

    #[test]
    fn command_string_after_any_option_spelling() {
        for cmd in [
            "bash -c X",
            "bash -lc X",
            "bash -cl X",
            "zsh -ic X",
            "sh -ec X",
            "sh -O extglob -c X",
            "dash -xc X",
            "ksh -c X",
            "/bin/bash -lc X",
            "bash -c -- X",
            "bash -c - X",
            "bash -x -c X",
            "bash -c -l X",
            "bash --login -c X",
            "bash --norc --noprofile -c X",
            "bash --rcfile rc -c X",
            "bash --init-file=rc -c X",
            "bash -o pipefail -c X",
            "bash +o posix -c X",
            "bash -eo pipefail -c X",
            "bash -O extglob -lc X",
            "bash -co pipefail X",
            "zsh --no-rcs -c X",
            "zsh --emulate sh -c X",
            "ksh -R xref -c X",
            "fish -c X",
            "fish -lc X",
            "fish --login --command X",
            "fish --command=X",
            "fish -cX",
            "fish -d 3 -c X",
        ] {
            assert_eq!(run(cmd).0, ["X"], "{cmd}");
        }
        assert_eq!(
            run("bash -c X name arg").0,
            ["X"],
            "operands after it are data"
        );
        assert_eq!(run("fish -C INIT -c X").0, ["INIT", "X"]);
    }

    #[test]
    fn script_and_stdin() {
        let script = |cmd| run(cmd).1;
        assert_eq!(script("bash build.sh -c x").as_deref(), Some("build.sh"));
        assert_eq!(
            script("bash -- -c").as_deref(),
            Some("-c"),
            "`--` ends options"
        );
        assert_eq!(script("bash -o errexit b.sh").as_deref(), Some("b.sh"));
        assert_eq!(
            script("bash -o pipefail"),
            None,
            "`pipefail` is the option value"
        );
        assert_eq!(script("fish -C INIT x.fish").as_deref(), Some("x.fish"));
        for cmd in [
            "bash",
            "bash -l",
            "bash -s",
            "bash -s -- arg",
            "sh -s arg",
            "sh -",
            "bash -o pipefail",
            "zsh -i",
            "fish",
            "fish -",
        ] {
            assert_eq!(run(cmd), (vec![], None, true), "{cmd}");
        }
        for cmd in ["bash x.sh", "sh -c x", "fish x.fish", "fish -c x"] {
            assert!(!run(cmd).2, "{cmd}");
        }
    }

    #[test]
    fn unknown_options_are_refused() {
        for cmd in [
            "bash --frobnicate -c X",
            "bash --login=yes -c X",
            "dash --login -c X",
            "sh --login -c X",
            "sh --rcfile X -c Y",
            "ksh --login -c X",
            "bash -c",
            "bash -l%c X",
            "fish --frobnicate -c X",
            "fish -q -c X",
            "fish -c",
        ] {
            let argv: Vec<&str> = cmd.split(' ').collect();
            assert!(parse(argv[0], &argv).is_err(), "{cmd}");
        }
    }
}
