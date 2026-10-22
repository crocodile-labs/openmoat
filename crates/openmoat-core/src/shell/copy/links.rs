//! Whether a command makes hard links to its sources (`ln`, `link`, `cp -l`).
//!
//! The options are read the way the programs read them, so a value is never
//! taken for an option: `-S SUFFIX`/`--suffix` and `-t DIR`/`--target-directory`
//! consume the word after them (`ln -S -s a b` and `ln -t -s a` make hard
//! links), and GNU's unambiguous prefixes of the long options count
//! (`--sym`). GNU reads options after the operands too, BSD and
//! `POSIXLY_CORRECT` stop at the first operand, so `ln a dir -s` is a hard link
//! to one of them: `ln` makes a symbolic link only for an `-s` before the first
//! operand. An `ln` long option that is unknown or ambiguous (`--s`) counts as
//! a hard link, the reading that adds the source's write.

/// Short options of `ln` and `cp` that take a value.
const SHORT_VALUES: &[char] = &['S', 't'];

/// GNU `ln`'s long options; `suffix` and `target-directory` take a value.
const LN_LONG: &[&str] = &[
    "backup",
    "directory",
    "force",
    "interactive",
    "logical",
    "no-dereference",
    "no-target-directory",
    "physical",
    "relative",
    "suffix",
    "symbolic",
    "target-directory",
    "verbose",
    "help",
    "version",
];

/// GNU long options of `ln` and `cp` that consume the next word unless written
/// `--name=VALUE`.
const LONG_VALUES: &[&str] = &["suffix", "target-directory"];

/// One option or operand of an `ln` or `cp` command line.
#[derive(Debug, PartialEq, Eq)]
enum Word<'a> {
    /// A short option letter.
    Short(char),
    /// A long option as written, without `--` and any `=VALUE`.
    Long(&'a str),
    Operand,
}

/// Whether `argv` makes hard links to its sources.
pub(super) fn hard_links(argv: &[String], program: &str) -> bool {
    match program {
        "link" => true,
        "ln" => !symbolic(argv),
        "cp" => words(argv).iter().any(|(word, _)| match word {
            Word::Short(c) => *c == 'l',
            Word::Long(name) => "link".starts_with(name),
            Word::Operand => false,
        }),
        _ => false,
    }
}

/// `ln` makes a symbolic link: a real `-s` or `--symbolic` comes before the
/// first operand, and no long option leaves the reading in doubt.
fn symbolic(argv: &[String]) -> bool {
    let mut symbolic = false;
    for (word, before_operands) in words(argv) {
        match word {
            Word::Short('s') => symbolic |= before_operands,
            Word::Long(name) => match long_option(name) {
                Some("symbolic") => symbolic |= before_operands,
                Some(_) => {}
                None => return false,
            },
            Word::Short(_) | Word::Operand => {}
        }
    }
    symbolic
}

/// The `ln` long option `name` abbreviates, when it names exactly one.
fn long_option(name: &str) -> Option<&'static str> {
    if let Some(exact) = LN_LONG.iter().find(|o| **o == name) {
        return Some(exact);
    }
    let mut matches = LN_LONG.iter().filter(|o| o.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) if !name.is_empty() => Some(only),
        _ => None,
    }
}

/// The options and operands of `argv` in order, each with whether it comes
/// before the first operand; option values are skipped.
fn words(argv: &[String]) -> Vec<(Word<'_>, bool)> {
    let mut out = Vec::new();
    let mut before_operands = true;
    let mut options_ended = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if options_ended || arg == "-" || !arg.starts_with('-') {
            out.push((Word::Operand, before_operands));
            before_operands = false;
            continue;
        }
        if arg == "--" {
            options_ended = true;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, false), |(n, _)| (n, true));
            let takes_value = LONG_VALUES
                .iter()
                .any(|o| !name.is_empty() && o.starts_with(name));
            i += usize::from(takes_value && !attached);
            out.push((Word::Long(name), before_operands));
            continue;
        }
        for (pos, c) in arg.char_indices().skip(1) {
            out.push((Word::Short(c), before_operands));
            if SHORT_VALUES.contains(&c) {
                // the rest of the word, or else the next word, is the value
                i += usize::from(pos + c.len_utf8() == arg.len());
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hard_links;

    fn hard(line: &str) -> bool {
        let argv: Vec<String> = line.split(' ').map(str::to_owned).collect();
        hard_links(&argv, &argv[0])
    }

    #[test]
    fn an_option_value_is_never_read_as_dash_s() {
        for line in [
            "ln -S -s a b",
            "ln --suffix -s a b",
            "ln --su -s a b",
            "ln -t -s a",
            "ln --target-directory -s a",
            "ln --target -s a",
            "ln -fS -s a b",
        ] {
            assert!(hard(line), "{line}");
        }
    }

    #[test]
    fn dash_s_after_an_operand_is_a_hard_link_to_bsd() {
        for line in ["ln a ./ -s", "ln a x -s", "ln a -s x", "ln -- -s a b"] {
            assert!(hard(line), "{line}");
        }
    }

    #[test]
    fn an_unknown_or_ambiguous_long_option_is_a_hard_link() {
        for line in ["ln -s --s a b", "ln -s --frobnicate a b"] {
            assert!(hard(line), "{line}");
        }
    }

    #[test]
    fn symbolic_links() {
        for line in [
            "ln -s a b",
            "ln -s -- a b",
            "ln -sf a b",
            "ln -fs a b",
            "ln --sym a b",
            "ln --symbolic --force a b",
            "ln -s -S.l a b",
            "ln -s -S .l a b",
            "ln -sS .l a b",
            "ln -s -t dir a",
            "ln -s --suffix=.l a b",
        ] {
            assert!(!hard(line), "{line}");
        }
    }

    #[test]
    fn cp_links_with_dash_l_anywhere() {
        for line in [
            "cp -l a b",
            "cp -al a b",
            "cp a b -l",
            "cp --li a b",
            "cp --l a b",
        ] {
            assert!(hard(line), "{line}");
        }
        for line in [
            "cp a b",
            "cp -L a b",
            "cp -t/tmp/l a",
            "cp -S l a b",
            "cp --links-not-an-option a b",
        ] {
            assert!(!hard(line), "{line}");
        }
        assert!(hard("link a b"));
        assert!(!hard("mv a b"));
    }
}
