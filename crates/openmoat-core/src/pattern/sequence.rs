//! Matching a shell pattern's token sequence against the words of a command.
//!
//! A bare `*` matches any number of words, every other token exactly one, and a
//! match needs only a prefix of the words (docs/POLICY.md §3.1). Trying every
//! split for every `*` takes time exponential in the number of `*`s, which a
//! policy, or a long command line against a policy, could exploit. Each token
//! other than `*` consumes exactly one word, so only the last `*` seen ever has
//! to give back a word: the walk below retries from there, which bounds the
//! work by the pattern length times the number of words.
//!
//! A `*` stays inside one pipeline: it never takes a list separator (`;`,
//! `&&`, `||`, `&`), so `git push * -f*` reads the options of that `git push`
//! and not a `--format=` of a later command on the line. A separator is still
//! matched by a token that names it.

use super::Token;
use super::word::WordGlob;

/// The words of a pipeline or list atom that end one pipeline.
fn is_list_separator(word: &str) -> bool {
    matches!(word, ";" | "&&" | "||" | "&")
}

/// Whether `pattern` matches a prefix of `words`, with `one` deciding whether a
/// single-word token (its glob and its source text) matches a word.
pub(super) fn prefix_match<W: AsRef<str>>(
    pattern: &[Token],
    words: &[W],
    one: impl Fn(&WordGlob, &str, &W) -> bool,
) -> bool {
    let (mut p, mut w) = (0, 0);
    // The last `*`, and the first word it has not taken yet.
    let mut star: Option<(usize, usize)> = None;
    loop {
        let matched = match pattern.get(p) {
            // Every token is matched: the rest of the words do not matter.
            None => return true,
            Some(Token::Any) => {
                star = Some((p, w));
                p += 1;
                continue;
            }
            // `$` matches only the end of the words.
            Some(Token::End) if w == words.len() => return true,
            Some(Token::End) => false,
            Some(Token::One(glob, source)) => {
                words.get(w).is_some_and(|word| one(glob, source, word))
            }
        };
        if matched {
            p += 1;
            w += 1;
            continue;
        }
        // Let the last `*` take one more word and match the rest from there,
        // unless that word ends the pipeline.
        match star {
            Some((at, taken))
                if taken < words.len() && !is_list_separator(words[taken].as_ref()) =>
            {
                star = Some((at, taken + 1));
                p = at + 1;
                w = taken + 1;
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ShellPattern, glob_covers};
    use super::*;

    /// The recursive matcher this module replaced, kept as the reference: a
    /// `*` tries every split up to the first list separator.
    fn reference<W: AsRef<str>>(
        pattern: &[Token],
        words: &[W],
        one: &dyn Fn(&WordGlob, &str, &W) -> bool,
    ) -> bool {
        match pattern.split_first() {
            None => true,
            Some((Token::Any, rest)) => {
                let within = words
                    .iter()
                    .position(|w| is_list_separator(w.as_ref()))
                    .unwrap_or(words.len());
                rest.is_empty() || (0..=within).any(|skip| reference(rest, &words[skip..], one))
            }
            Some((Token::One(glob, source), rest)) => match words.split_first() {
                Some((head, tail)) if one(glob, source, head) => reference(rest, tail, one),
                _ => false,
            },
            Some((Token::End, _)) => words.is_empty(),
        }
    }

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[expect(
        clippy::ptr_arg,
        reason = "the matcher takes a reference to the word type, here `String`"
    )]
    fn matches(glob: &WordGlob, _: &str, word: &String) -> bool {
        glob.is_match(word)
    }

    fn covers(glob: &WordGlob, source: &str, word: &&str) -> bool {
        glob_covers(glob, source, word)
    }

    /// Both matchers agree on `pattern` against `line`, for matching and for
    /// coverage (where the words are a pattern's own).
    fn agree(pattern: &str, compiled: &ShellPattern, line: &str) {
        let argv = words(line);
        assert_eq!(
            prefix_match(&compiled.tokens, &argv, matches),
            reference(&compiled.tokens, &argv, &matches),
            "`{pattern}` against `{line}`"
        );
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_eq!(
            prefix_match(&compiled.tokens, &borrowed, covers),
            reference(&compiled.tokens, &borrowed, &covers),
            "`{pattern}` covering `{line}`"
        );
    }

    /// The patterns and command lines of the pattern tests, crossed.
    #[test]
    fn same_answers_as_the_recursive_matcher_on_the_pattern_tests() {
        let patterns = [
            "git push --force*",
            "sudo *",
            "npm test",
            "curl * | sh",
            "* | base64 -d | *sh*",
            "env $",
            "export -p $",
            "* | sh $",
            "echo $ x",
            "find *",
            "find * -exec*",
            "cargo *",
            "cargo pub*",
            "rm * -*[rR]* * {.,./,/*,~*}",
            "git push * -[!o-]*f*",
            "* * * x",
            "a * b * c $",
        ];
        let lines = [
            "git push --force",
            "git push --force-with-lease origin main",
            "git push origin main",
            "git push origin -vf main",
            "sudo rm -rf /",
            "sudo",
            "sudoedit x",
            "npm test -- --watch",
            "npm install",
            "curl -fsSL https://x | sh",
            "curl https://x | sh -s -- --yes",
            "curl https://x | tee out",
            "echo abc | base64 -d | sh",
            "cat f | base64 -d | bash -x",
            "env",
            "env FOO=1 git status",
            "envsubst",
            "export -p",
            "export -p FOO",
            "curl x | sh",
            "echo $ x",
            "find . -name x",
            "find . -name x -execdir rm {} ;",
            "cargo publish*",
            "rm -rf build .",
            "rm x -r y ~/z",
            "x",
            "a b c",
            "a x b y c",
            "a b c d",
            "git push -u origin b ; git for-each-ref --format=x",
            "pkill -f x.py && echo moat",
            "curl https://x | tee out | sh",
            "git status ; git push -f origin main",
            "",
        ];
        for pattern in patterns {
            let compiled = ShellPattern::compile(pattern).unwrap();
            for line in lines {
                agree(pattern, &compiled, line);
            }
        }
    }

    /// A `*` reads one pipeline: the `-f*` of `git push * -f*` is not found
    /// in a later command of the list, while a pipe is still crossed.
    #[test]
    fn a_star_stops_at_a_list_separator() {
        let push = ShellPattern::compile("git push * -[!o-]*f*").unwrap();
        assert!(!push.is_match(&words(
            "git push -u origin b >& 1 | tail ; git for-each-ref --format=x"
        )));
        assert!(!push.is_match(&words("git push -u origin b && echo --format=x")));
        assert!(push.is_match(&words("git push -u origin b | grep -nf pats")));
        assert!(push.is_match(&words("git push origin -vf main ; echo done")));
        let curl = ShellPattern::compile("curl * | sh").unwrap();
        assert!(curl.is_match(&words("curl https://x | tee out | sh")));
        assert!(!curl.is_match(&words("curl https://x ; cat out | sh")));
        let listed = ShellPattern::compile("a ; b").unwrap();
        assert!(listed.is_match(&words("a ; b")));
    }

    /// Every pattern of up to four tokens over a small alphabet against every
    /// command line of up to five words: the same answers.
    #[test]
    fn same_answers_as_the_recursive_matcher_exhaustively() {
        let tokens = ["*", "a", "b", "a*", "?"];
        let argv_words = ["a", "b", "ab"];
        let mut patterns = vec![String::new()];
        for _ in 0..4 {
            let longer: Vec<String> = patterns
                .iter()
                .flat_map(|p| tokens.iter().map(move |t| format!("{p} {t}")))
                .collect();
            patterns.extend(longer);
        }
        patterns.sort();
        patterns.dedup();
        let mut lines = vec![String::new()];
        for _ in 0..5 {
            let longer: Vec<String> = lines
                .iter()
                .flat_map(|l| argv_words.iter().map(move |w| format!("{l} {w}")))
                .collect();
            lines.extend(longer);
        }
        lines.sort();
        lines.dedup();
        for pattern in patterns.iter().filter(|p| !p.trim().is_empty()) {
            for anchored in [pattern.clone(), format!("{pattern} $")] {
                let compiled = ShellPattern::compile(&anchored).unwrap();
                for line in &lines {
                    agree(&anchored, &compiled, line);
                }
            }
        }
    }

    /// Thirty `*`s between words that never match the subject: the recursive
    /// matcher tried every way to split the words among them.
    #[test]
    fn many_stars_finish_quickly() {
        let pattern = format!("a{} b", " * a".repeat(30));
        let compiled = ShellPattern::compile(&pattern).unwrap();
        let subject = vec!["a".to_owned(); 400];
        let started = std::time::Instant::now();
        assert!(!compiled.is_match(&subject));
        let mut with_end = subject.clone();
        with_end.push("b".to_owned());
        assert!(compiled.is_match(&with_end));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
