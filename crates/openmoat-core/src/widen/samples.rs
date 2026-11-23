//! Concrete strings a glob matches, and the near misses at its edges: the
//! generated boundary cases of the never-widen check (ADR-111).
//!
//! A sample need not match: every sample is decided under both policies, and
//! only a verdict that moves toward `allow` counts. Samples are cheap, so each
//! glob gets a few fills (nothing, one word, two levels) and the strings just
//! outside it (its literal folder, a sibling, the folder itself for `dir/**`).

/// The filler for one `*`, `?` or class, and for one directory level of `**`.
const WORD: &str = "w";

/// Most samples one glob yields, so a policy with a wide brace group cannot
/// make the check slow.
const MAX_SAMPLES: usize = 48;

/// How the wildcards of a glob are filled.
#[derive(Clone, Copy)]
enum Fill {
    /// `*` and `**` match nothing.
    Empty,
    /// One word for each.
    Word,
    /// `**` two directory levels deep, `*` one word.
    Deep,
}

/// Strings `glob` matches (each brace alternative, each fill) and the near
/// misses at its edges. `glob` is one spelling as [`crate::EvalContext::spellings`]
/// gives it; a leading `!` is ignored.
pub(super) fn glob(glob: &str) -> Vec<String> {
    let body = glob.strip_prefix('!').unwrap_or(glob);
    let mut out = Vec::new();
    for alternative in crate::ir::brace_alternatives(body) {
        for fill in [Fill::Empty, Fill::Word, Fill::Deep] {
            out.push(filled(&alternative, fill));
        }
        if let Some(dir) = alternative.strip_suffix("/**") {
            out.push(dir.to_owned());
        }
        let start = crate::pattern::literal_start_of(&alternative);
        if !start.is_empty() {
            out.push(start.to_owned());
            out.push(format!("{start}{WORD}"));
            let trimmed = start.trim_end_matches('/');
            if let Some(folder) = trimmed.rfind('/').map(|i| &trimmed[..i]) {
                if !folder.is_empty() {
                    out.push(folder.to_owned());
                }
                out.push(format!("{folder}/{WORD}"));
            }
        }
        if out.len() >= MAX_SAMPLES {
            break;
        }
    }
    out.sort();
    out.dedup();
    out.truncate(MAX_SAMPLES);
    out
}

/// Host samples: [`glob`]'s, lowercased, and the spellings a suffix or prefix
/// check gets wrong (`wgithub.com` for `github.com`, `github.com.w`).
pub(super) fn host(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    for sample in glob(pattern) {
        let sample = sample.to_ascii_lowercase();
        let bare = sample.trim_start_matches('.');
        if !bare.is_empty() && !bare.contains(':') {
            out.push(format!("{WORD}{bare}"));
            out.push(format!("{bare}.{WORD}"));
        }
        out.push(sample);
    }
    out.retain(|h| !h.is_empty());
    out.sort();
    out.dedup();
    out
}

/// `glob` with its wildcards filled as `fill` says and its escapes resolved.
fn filled(glob: &str, fill: Fill) -> String {
    let star = match fill {
        Fill::Empty => "",
        Fill::Word | Fill::Deep => WORD,
    };
    let levels = match fill {
        Fill::Empty => "",
        Fill::Word => WORD,
        Fill::Deep => "w/w",
    };
    let mut out = String::new();
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                // `**/` with nothing in it is no folder at all.
                if levels.is_empty() && chars.peek() == Some(&'/') {
                    chars.next();
                } else {
                    out.push_str(levels);
                }
            }
            '*' => out.push_str(star),
            '?' => out.push_str(WORD),
            '[' => out.push(class_member(&mut chars)),
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// A character the class at `chars` (after its `[`) matches; consumes it.
fn class_member(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> char {
    let negated = matches!(chars.peek(), Some('!' | '^'));
    if negated {
        chars.next();
    }
    let mut members = Vec::new();
    let mut first = true;
    for c in chars.by_ref() {
        if c == ']' && !first {
            break;
        }
        members.push(c);
        first = false;
    }
    if negated {
        ['w', 'q', '0', '_', 'Z']
            .into_iter()
            .find(|c| !members.contains(c))
            .unwrap_or('~')
    } else {
        members.first().copied().unwrap_or('w')
    }
}

/// Argument lists a shell pattern matches, filled as for globs, and the same
/// with one more argument (a pattern is a prefix of argv). `words` are the
/// pattern's lexed words.
pub(super) fn shell(words: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for fill in [Fill::Empty, Fill::Word, Fill::Deep] {
        let mut argv = Vec::new();
        for word in words {
            match (word.as_str(), fill) {
                ("$", _) => break,
                ("*", Fill::Empty) => {}
                ("*", Fill::Word) => argv.push(WORD.to_owned()),
                ("*", Fill::Deep) => argv.extend([WORD.to_owned(), format!("--{WORD}")]),
                (word, fill) => argv.push(filled(word, fill)),
            }
        }
        if argv.is_empty() {
            continue;
        }
        let mut longer = argv.clone();
        longer.push(format!("./{WORD}"));
        out.push(argv);
        out.push(longer);
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_glob_yields_what_it_matches_and_its_edges() {
        let samples = glob("/h/.ssh/**");
        for want in ["/h/.ssh", "/h/.ssh/", "/h/.ssh/w", "/h/.ssh/w/w", "/h/w"] {
            assert!(samples.contains(&want.to_owned()), "{want}: {samples:?}");
        }
        let samples = glob("**/.env.*");
        assert!(samples.contains(&".env.".to_owned()), "{samples:?}");
        assert!(samples.contains(&"w/.env.w".to_owned()), "{samples:?}");
        let samples = glob("/h/{a,b}[!a]?");
        assert!(samples.contains(&"/h/aww".to_owned()), "{samples:?}");
        assert!(samples.contains(&"/h/bww".to_owned()), "{samples:?}");
    }

    #[test]
    fn hosts_get_lookalikes() {
        let samples = host("*.github.com");
        for want in ["w.github.com", ".github.com", "wgithub.com", "github.com.w"] {
            assert!(samples.contains(&want.to_owned()), "{want}: {samples:?}");
        }
    }

    #[test]
    fn shell_patterns_yield_argument_lists() {
        let words: Vec<String> = ["git", "push", "--force*"].map(str::to_owned).into();
        let argvs = shell(&words);
        assert!(argvs.contains(&vec!["git".into(), "push".into(), "--force".into()]));
        assert!(argvs.contains(&vec!["git".into(), "push".into(), "--forcew".into()]));
        let anchored: Vec<String> = ["env", "$"].map(str::to_owned).into();
        assert!(shell(&anchored).contains(&vec!["env".to_owned()]));
    }
}
