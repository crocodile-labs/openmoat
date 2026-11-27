//! The regular expressions globset compiles a glob to, read back as automata
//! over bytes (ADR-111).
//!
//! The proof reads `Glob::regex()`, the expression globset itself matches
//! with, rather than the glob: what is proven is then about the matcher the
//! engine runs. globset writes a small subset of regex syntax, and this
//! reads exactly that subset: the flags `(?-u)` and `(?i)`, `^` and `$`
//! around the body, literals (escaped with `\`, bytes as `\xNN`), `.` (any
//! byte: globset turns on `dot_matches_new_line`), byte classes `[…]`/`[^…]`
//! with ranges, groups `(?:…|…)`, and `*` and `?` after an atom. Anything
//! else is [`Unsupported`]: the kind is then not proven, never guessed.

/// A set of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Bytes([u64; 4]);

impl Bytes {
    const NONE: Self = Self([0; 4]);
    const ALL: Self = Self([u64::MAX; 4]);

    fn one(b: u8) -> Self {
        let mut set = Self::NONE;
        set.insert(b);
        set
    }

    fn insert(&mut self, b: u8) {
        self.0[usize::from(b >> 6)] |= 1 << (b & 63);
    }

    pub(super) fn contains(self, b: u8) -> bool {
        self.0[usize::from(b >> 6)] & (1 << (b & 63)) != 0
    }

    fn negated(self) -> Self {
        Self(self.0.map(|w| !w))
    }

    /// Every ASCII letter in the set also in its other case: `(?i)` without
    /// Unicode folds ASCII only.
    fn folded(self) -> Self {
        let mut out = self;
        for b in 0..=u8::MAX {
            if self.contains(b) && b.is_ascii_alphabetic() {
                out.insert(b ^ 0x20);
            }
        }
        out
    }
}

/// globset wrote something this reader does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unsupported(pub String);

/// A Thompson automaton: state 0 starts, [`Nfa::accept`] accepts.
#[derive(Debug, Clone, Default)]
pub(super) struct Nfa {
    /// Byte edges per state.
    pub edges: Vec<Vec<(Bytes, usize)>>,
    /// Empty edges per state.
    pub empty: Vec<Vec<usize>>,
    pub accept: usize,
}

impl Nfa {
    fn state(&mut self) -> usize {
        self.edges.push(Vec::new());
        self.empty.push(Vec::new());
        self.edges.len() - 1
    }

    /// One automaton accepting what any of `regexes` matches.
    pub(super) fn union<'a>(
        regexes: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, Unsupported> {
        let mut nfa = Self::default();
        let start = nfa.state();
        let accept = nfa.state();
        nfa.accept = accept;
        for regex in regexes {
            let (s, e) = Parser::new(regex, &mut nfa)?.whole()?;
            nfa.empty[start].push(s);
            nfa.empty[e].push(accept);
        }
        Ok(nfa)
    }

    /// `states` with every state reachable through empty edges, sorted.
    pub(super) fn closure(&self, states: &mut Vec<usize>) {
        let mut stack = states.clone();
        while let Some(s) = stack.pop() {
            for &t in &self.empty[s] {
                if !states.contains(&t) {
                    states.push(t);
                    stack.push(t);
                }
            }
        }
        states.sort_unstable();
        states.dedup();
    }
}

struct Parser<'r, 'n> {
    text: &'r [u8],
    at: usize,
    fold: bool,
    nfa: &'n mut Nfa,
}

impl<'r, 'n> Parser<'r, 'n> {
    fn new(regex: &'r str, nfa: &'n mut Nfa) -> Result<Self, Unsupported> {
        let body = regex
            .strip_prefix("(?-u)")
            .ok_or_else(|| Unsupported(format!("`{regex}` is not a byte regex")))?;
        let (fold, body) = match body.strip_prefix("(?i)") {
            Some(rest) => (true, rest),
            None => (false, body),
        };
        let body = body
            .strip_prefix('^')
            .and_then(|b| b.strip_suffix('$'))
            .ok_or_else(|| Unsupported(format!("`{regex}` is not anchored")))?;
        Ok(Self {
            text: body.as_bytes(),
            at: 0,
            fold,
            nfa,
        })
    }

    fn unsupported(&self) -> Unsupported {
        Unsupported(format!(
            "`{}` at byte {}",
            String::from_utf8_lossy(self.text),
            self.at
        ))
    }

    fn whole(mut self) -> Result<(usize, usize), Unsupported> {
        let frag = self.alternation()?;
        if self.at == self.text.len() {
            Ok(frag)
        } else {
            Err(self.unsupported())
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn alternation(&mut self) -> Result<(usize, usize), Unsupported> {
        let start = self.nfa.state();
        let end = self.nfa.state();
        loop {
            let (s, e) = self.sequence()?;
            self.nfa.empty[start].push(s);
            self.nfa.empty[e].push(end);
            if self.peek() == Some(b'|') {
                self.at += 1;
            } else {
                return Ok((start, end));
            }
        }
    }

    fn sequence(&mut self) -> Result<(usize, usize), Unsupported> {
        let start = self.nfa.state();
        let mut end = start;
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            let (s, e) = self.atom()?;
            let (s, e) = match self.peek() {
                Some(b'*') => {
                    self.at += 1;
                    let hub = self.nfa.state();
                    self.nfa.empty[hub].push(s);
                    self.nfa.empty[e].push(hub);
                    (hub, hub)
                }
                Some(b'?') => {
                    self.at += 1;
                    self.nfa.empty[s].push(e);
                    (s, e)
                }
                _ => (s, e),
            };
            self.nfa.empty[end].push(s);
            end = e;
        }
        Ok((start, end))
    }

    fn atom(&mut self) -> Result<(usize, usize), Unsupported> {
        let set = match self.peek() {
            Some(b'(') => {
                if !self.text[self.at..].starts_with(b"(?:") {
                    return Err(self.unsupported());
                }
                self.at += 3;
                let frag = self.alternation()?;
                if self.peek() != Some(b')') {
                    return Err(self.unsupported());
                }
                self.at += 1;
                return Ok(frag);
            }
            Some(b'[') => {
                self.at += 1;
                self.class()?
            }
            Some(b'.') => {
                self.at += 1;
                Bytes::ALL
            }
            Some(b'*' | b'?' | b'+' | b'{' | b'^' | b'$') | None => {
                return Err(self.unsupported());
            }
            Some(_) => {
                let byte = self.literal()?;
                self.fold(Bytes::one(byte))
            }
        };
        let s = self.nfa.state();
        let e = self.nfa.state();
        self.nfa.edges[s].push((set, e));
        Ok((s, e))
    }

    fn fold(&self, set: Bytes) -> Bytes {
        if self.fold { set.folded() } else { set }
    }

    /// One literal byte: plain, `\` and a punctuation character, or `\xNN`.
    fn literal(&mut self) -> Result<u8, Unsupported> {
        let c = self.peek().ok_or_else(|| self.unsupported())?;
        self.at += 1;
        if c != b'\\' {
            return Ok(c);
        }
        let next = self.peek().ok_or_else(|| self.unsupported())?;
        self.at += 1;
        if next == b'x' {
            let hex = self
                .text
                .get(self.at..self.at + 2)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| self.unsupported())?;
            self.at += 2;
            Ok(hex)
        } else if next.is_ascii_punctuation() || next == b' ' {
            Ok(next)
        } else {
            Err(self.unsupported())
        }
    }

    /// A class after its `[`, through its `]`.
    fn class(&mut self) -> Result<Bytes, Unsupported> {
        let negated = self.peek() == Some(b'^');
        if negated {
            self.at += 1;
        }
        let mut set = Bytes::NONE;
        loop {
            match self.peek() {
                None | Some(b'[') => return Err(self.unsupported()),
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                Some(_) => {
                    let low = self.literal()?;
                    let high =
                        if self.peek() == Some(b'-') && self.text.get(self.at + 1) != Some(&b']') {
                            self.at += 1;
                            self.literal()?
                        } else {
                            low
                        };
                    if high < low {
                        return Err(self.unsupported());
                    }
                    for b in low..=high {
                        set.insert(b);
                    }
                }
            }
        }
        let set = self.fold(set);
        Ok(if negated { set.negated() } else { set })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `nfa` accepts `text`, by simulation.
    fn accepts(nfa: &Nfa, text: &str) -> bool {
        let mut states = vec![0];
        nfa.closure(&mut states);
        for b in text.bytes() {
            let mut next: Vec<usize> = states
                .iter()
                .flat_map(|&s| nfa.edges[s].iter())
                .filter(|(set, _)| set.contains(b))
                .map(|&(_, t)| t)
                .collect();
            nfa.closure(&mut next);
            states = next;
        }
        states.contains(&nfa.accept)
    }

    /// Every glob shape the default policy uses, read back and checked
    /// against globset on matching and non-matching candidates.
    #[test]
    fn the_automaton_matches_as_globset_does() {
        let globs = [
            ("/h/.ssh/**", false),
            ("**/.env", false),
            ("**/.env.*", false),
            ("**", false),
            ("/h/{a,b,}/x?", false),
            ("/h/[!a-c]*.pem", false),
            ("/h/a**b/**/c", false),
            ("*.GitHub.com", true),
            ("/p/src/[A-Z]x", true),
            ("/h/caf\u{e9}/*", false),
            ("/h/[\u{e9}]", false),
            ("/h/a\\*b", false),
            // a spliced directory's literal glob characters (`paths::glob_literal`)
            ("/h/a[*]b", false),
            ("/h/a[?][[][]][{][,][}]/**", true),
        ];
        let candidates = [
            "",
            "/",
            "/h",
            "/h/",
            "/h/.ssh",
            "/h/.ssh/id",
            "/h/.ssh/a/b",
            "x/.env",
            ".env",
            "/a/.env.local",
            "/h/a/xy",
            "/h//x1",
            "/h/b/x\n",
            "/h/d.pem",
            "/h/a.pem",
            "/h/aXb/c",
            "/h/ab/q/c",
            "/h/a/b/c",
            "api.github.com",
            "API.GITHUB.COM",
            "/p/src/qx",
            "/p/src/Qx",
            "/h/caf\u{e9}/x",
            "/h/\u{e9}",
            "/h/a*b",
            "/h/axb",
            "/h/a?[]{,}",
            "/h/A?[]{,}/x",
            "/h/ax[]{,}/x",
        ];
        for (glob, ci) in globs {
            let g = globset::GlobBuilder::new(glob)
                .literal_separator(true)
                .case_insensitive(ci)
                .build()
                .unwrap();
            let nfa = Nfa::union([g.regex()]).unwrap();
            let m = g.compile_matcher();
            for c in candidates {
                assert_eq!(
                    accepts(&nfa, c),
                    m.is_match(c),
                    "{glob} on {c:?}: {}",
                    g.regex()
                );
            }
        }
    }

    #[test]
    fn other_syntax_is_refused() {
        for regex in ["^a$", "(?-u)^a+$", "(?-u)^(a)$", "(?-u)^\\d$", "(?-u)^a"] {
            assert!(Nfa::union([regex]).is_err(), "{regex}");
        }
    }
}
