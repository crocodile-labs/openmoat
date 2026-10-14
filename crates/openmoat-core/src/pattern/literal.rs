//! Shell patterns that match one command literally.
//!
//! A person who approves a command (`moat allow --always`) approves exactly
//! that command. Written as a rule, glob characters would become wildcards
//! (`cat *` would allow every `cat`), a leading `!` an exclusion and a
//! trailing `$` an end anchor, so each word is escaped before it becomes a
//! pattern.

use crate::lexer::{self, Token};
use crate::policy::PolicyError;
use crate::shell::tables::RESERVED_PREFIXES;

/// A shell pattern that matches `command` token for token and nothing wider.
///
/// Glob characters and `$` are put in one-character classes (`*` → `[*]`).
/// Words the pattern lexer would split or reinterpret (whitespace, quotes,
/// operators, a leading `!`) are single-quoted. Operators (`|`, `&&`, …) stay
/// operators. Shell rules are prefixes, so arguments appended after the
/// approved command still match.
pub fn literal_shell_pattern(command: &str) -> Result<String, PolicyError> {
    let bad = || PolicyError::BadShellPattern {
        pattern: command.to_owned(),
    };
    // The classifier sees the words braces make (`{cat,.env}` runs `cat .env`),
    // so the approval names them too.
    let (mut tokens, too_many) =
        lexer::expand_braces(lexer::lex(command.trim()).map_err(|_| bad())?);
    if too_many.is_some() {
        return Err(bad());
    }
    if tokens.is_empty() {
        return Err(PolicyError::EmptyPattern);
    }
    // `! git diff --quiet`, `do make test`: the classifier reports the command
    // after a reserved word, so the approval names that command.
    let reserved = tokens
        .iter()
        .take_while(|t| {
            matches!(t, Token::Word(w) if !w.quoted && RESERVED_PREFIXES.contains(&w.text.as_str()))
        })
        .count();
    if reserved < tokens.len() {
        tokens.drain(..reserved);
    }
    if let Some(subcommand) = git_subcommand(&tokens) {
        tokens = subcommand;
    }
    tokens
        .iter()
        .map(|token| match token {
            Token::Word(w) => Ok(literal_word(&w.text)),
            Token::Operator(op) => Ok(op.symbol().to_owned()),
            Token::HereDoc { .. } => Err(bad()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(" "))
}

/// The classifier reports `git -C dir status` as `git status` (and reads `dir`),
/// so an approval of a plain git command line names the subcommand the same way;
/// otherwise the approved rule could never match. When an option can run a
/// program the command line as written is judged too, so it stays as written.
fn git_subcommand(tokens: &[Token]) -> Option<Vec<Token>> {
    let argv = tokens
        .iter()
        .map(|t| match t {
            Token::Word(w) => Some(w.text.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    if argv.first().map(|p| crate::shell::tokens::basename(p)) != Some("git") {
        return None;
    }
    let git = crate::shell::git::parse(&argv);
    if git.keep_original || git.subcommand.len() == argv.len() {
        return None;
    }
    let keep = git.subcommand.len();
    let mut out = tokens[..1].to_vec();
    out.extend_from_slice(&tokens[tokens.len() - (keep - 1)..]);
    Some(out)
}

fn literal_word(text: &str) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '*' | '?' | '[' | ']' | '{' | '}' | '$' => format!("[{c}]"),
            // A backslash escapes the next character in a shell pattern; as
            // a one-character class it is literal.
            '\\' => "[\\\\]".to_owned(),
            c => c.to_string(),
        })
        .collect();
    let needs_quotes = escaped.is_empty()
        || escaped.starts_with('!')
        || escaped
            .chars()
            .any(|c| c.is_whitespace() || "'\"\\|&;<>()`#".contains(c));
    if needs_quotes {
        format!("'{}'", escaped.replace('\'', "'\\''"))
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::ShellPattern;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|w| (*w).to_owned()).collect()
    }

    fn compiled(command: &str) -> ShellPattern {
        ShellPattern::compile(&literal_shell_pattern(command).unwrap()).unwrap()
    }

    #[test]
    fn glob_characters_and_anchors_stay_literal() {
        assert_eq!(
            literal_shell_pattern("npm install left-pad").unwrap(),
            "npm install left-pad"
        );
        assert_eq!(literal_shell_pattern("cat *").unwrap(), "cat [*]");
        let cat = compiled("cat *");
        assert!(cat.is_match(&argv(&["cat", "*"])));
        assert!(
            !cat.is_match(&argv(&["cat", "~/.ssh/id_rsa"])),
            "`*` is not a wildcard"
        );
        let q = compiled("ls file?.[ch] '{a,b}'");
        assert!(q.is_match(&argv(&["ls", "file?.[ch]", "{a,b}"])));
        assert!(!q.is_match(&argv(&["ls", "file1.c", "a"])));
        // Unquoted braces are the words bash makes of them, as classified.
        assert_eq!(
            literal_shell_pattern("{cat,.env} x{1..2}").unwrap(),
            "cat .env x1 x2"
        );
        assert!(literal_shell_pattern("x{1..300}").is_err());
        let bang = compiled("!echo hi $");
        assert!(!bang.negated, "a leading `!` stays literal");
        assert!(
            bang.is_match(&argv(&["!echo", "hi", "$", "more"])),
            "`$` is not an anchor"
        );
    }

    #[test]
    fn a_leading_reserved_word_is_not_part_of_the_command() {
        assert_eq!(
            literal_shell_pattern("! git diff --quiet").unwrap(),
            "git diff --quiet"
        );
        assert_eq!(literal_shell_pattern("do make test").unwrap(), "make test");
        assert_eq!(literal_shell_pattern("'do' x").unwrap(), "do x");
        assert_eq!(literal_shell_pattern("do").unwrap(), "do");
    }

    #[test]
    fn backslashes_stay_literal() {
        // `\` left a dangling
        // escape in the glob, so the approved rule broke the whole policy.
        for command in ["++\\\\", "printf 'a\\nb'", "echo C:\\\\temp"] {
            let pattern = literal_shell_pattern(command).unwrap();
            let compiled = ShellPattern::compile(&pattern)
                .unwrap_or_else(|e| panic!("{command:?} -> {pattern:?}: {e}"));
            let words: Vec<String> = crate::lexer::lex(command)
                .unwrap()
                .into_iter()
                .map(|t| t.to_string())
                .collect();
            assert!(compiled.is_match(&words), "{command:?} -> {pattern:?}");
        }
    }

    /// The classifier strips git's global options (`shell/git.rs`); an approval
    /// that kept them could never match (found by the `literal_pattern` fuzz target).
    #[test]
    fn git_global_options_are_approved_the_way_they_are_classified() {
        assert_eq!(
            literal_shell_pattern("git -C crates/x status").unwrap(),
            "git status"
        );
        assert_eq!(
            literal_shell_pattern("/usr/bin/git --no-pager log -1").unwrap(),
            "/usr/bin/git log -1"
        );
        assert!(compiled("git -C crates/x status").is_match(&argv(&["git", "status"])));
        // An option that can run a program keeps the command line as written,
        // which the classifier also reports.
        assert_eq!(
            literal_shell_pattern("git -c core.fsmonitor=x status").unwrap(),
            "git -c core.fsmonitor=x status"
        );
        // Not plain words: left alone.
        assert_eq!(
            literal_shell_pattern("git -C x status | head").unwrap(),
            "git -C x status | head"
        );
    }

    #[test]
    fn quotes_and_operators_round_trip() {
        assert!(compiled("echo \"it's\"").is_match(&argv(&["echo", "it's"])));
        let piped = compiled("npm test | tee out.log");
        assert!(piped.is_match(&argv(&["npm", "test", "|", "tee", "out.log"])));
    }

    #[test]
    fn unusable_commands_are_errors() {
        assert!(matches!(
            literal_shell_pattern("echo 'unterminated"),
            Err(PolicyError::BadShellPattern { .. })
        ));
        assert!(matches!(
            literal_shell_pattern("   "),
            Err(PolicyError::EmptyPattern)
        ));
        assert!(literal_shell_pattern("cat <<EOF\nx\nEOF\n").is_err());
    }
}
