//! The operating systems a `#[cfg(...)]` attribute lets code compile on, so a
//! `// protection:` mark ([`crate::marks`]) cannot claim a test runs on an OS
//! where the test is compiled out.

use std::fmt;

/// The operating systems of the protection matrix, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Os {
    Linux,
    Mac,
    Windows,
}

impl Os {
    /// Every OS, in the matrix's order.
    pub const EVERY: [Os; 3] = [Os::Linux, Os::Mac, Os::Windows];

    /// The name a mark spells it with.
    pub fn id(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Mac => "macos",
            Os::Windows => "windows",
        }
    }

    /// The OS of `id` ([`Os::id`]).
    pub fn of(id: &str) -> Option<Os> {
        Os::EVERY.into_iter().find(|os| os.id() == id)
    }

    /// The OS of a runner of the weekly job (`ubuntu-latest`, `macos-15`).
    pub fn of_runner(runner: &str) -> Option<Os> {
        if runner.starts_with("ubuntu") {
            Some(Os::Linux)
        } else if runner.starts_with("macos") {
            Some(Os::Mac)
        } else if runner.starts_with("windows") {
            Some(Os::Windows)
        } else {
            None
        }
    }

    fn bit(self) -> u8 {
        match self {
            Os::Linux => 1,
            Os::Mac => 2,
            Os::Windows => 4,
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Os::Linux => "Linux",
            Os::Mac => "macOS",
            Os::Windows => "Windows",
        })
    }
}

/// A set of operating systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oses(u8);

impl Oses {
    pub const ALL: Oses = Oses(7);

    pub fn contains(self, os: Os) -> bool {
        self.0 & os.bit() != 0
    }

    pub fn and(self, other: Oses) -> Oses {
        Oses(self.0 & other.0)
    }

    fn or(self, other: Oses) -> Oses {
        Oses(self.0 | other.0)
    }

    fn not(self) -> Oses {
        Oses(!self.0 & 7)
    }

    fn of(os: Os) -> Oses {
        Oses(os.bit())
    }
}

/// The OSes code under the attribute line `line` (`#[cfg(unix)]`) compiles
/// on: every OS for a line that is not a `cfg`. An upper bound: a predicate
/// that names no OS (`feature = "x"`) is taken as true everywhere, so only
/// what the attribute says about the OS narrows the set.
pub fn oses_of(line: &str) -> Oses {
    let Some(inner) = line
        .trim()
        .strip_prefix("#[cfg(")
        .and_then(|rest| rest.strip_suffix(")]"))
    else {
        return Oses::ALL;
    };
    let mut parser = Parser {
        text: inner.as_bytes(),
        at: 0,
    };
    match parser.predicate() {
        Some((oses, _)) if parser.done() => oses,
        _ => Oses::ALL,
    }
}

/// A recursive reader of a `cfg` predicate: each result is the set of OSes
/// it holds on and whether that set is exact (it named only OSes).
struct Parser<'a> {
    text: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn done(&mut self) -> bool {
        self.skip_space();
        self.at == self.text.len()
    }

    fn eat(&mut self, byte: u8) -> bool {
        self.skip_space();
        if self.text.get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn word(&mut self) -> Option<String> {
        self.skip_space();
        let start = self.at;
        while self
            .text
            .get(self.at)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            self.at += 1;
        }
        (self.at > start).then(|| String::from_utf8_lossy(&self.text[start..self.at]).into_owned())
    }

    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }
        let start = self.at;
        while self.text.get(self.at).is_some_and(|b| *b != b'"') {
            self.at += 1;
        }
        let value = String::from_utf8_lossy(&self.text[start..self.at]).into_owned();
        self.eat(b'"').then_some(value)
    }

    fn list(&mut self) -> Option<Vec<(Oses, bool)>> {
        if !self.eat(b'(') {
            return None;
        }
        let mut items = Vec::new();
        loop {
            if self.eat(b')') {
                return Some(items);
            }
            items.push(self.predicate()?);
            if !self.eat(b',') {
                return self.eat(b')').then_some(items);
            }
        }
    }

    fn predicate(&mut self) -> Option<(Oses, bool)> {
        let name = self.word()?;
        match name.as_str() {
            "any" => Some(
                self.list()?
                    .into_iter()
                    .fold((Oses(0), true), |(set, exact), (one, one_exact)| {
                        (set.or(one), exact && one_exact)
                    }),
            ),
            "all" => Some(
                self.list()?
                    .into_iter()
                    .fold((Oses::ALL, true), |(set, exact), (one, one_exact)| {
                        (set.and(one), exact && one_exact)
                    }),
            ),
            "not" => {
                let mut inner = self.list()?;
                if inner.len() != 1 {
                    return None;
                }
                let (set, exact) = inner.remove(0);
                Some(if exact {
                    (set.not(), true)
                } else {
                    (Oses::ALL, false)
                })
            }
            "unix" => Some((Oses::of(Os::Linux).or(Oses::of(Os::Mac)), true)),
            "windows" => Some((Oses::of(Os::Windows), true)),
            _ if self.eat(b'=') => {
                let value = self.string()?;
                match (name.as_str(), Os::of(&value)) {
                    ("target_os", Some(os)) => Some((Oses::of(os), true)),
                    ("target_os", None) => Some((Oses(0), true)),
                    ("target_family", _) if value == "unix" => {
                        Some((Oses::of(Os::Linux).or(Oses::of(Os::Mac)), true))
                    }
                    ("target_family", _) if value == "windows" => {
                        Some((Oses::of(Os::Windows), true))
                    }
                    _ => Some((Oses::ALL, false)),
                }
            }
            _ => Some((Oses::ALL, false)),
        }
    }
}

#[test]
fn a_cfg_names_the_oses_it_compiles_on() {
    let set = |line: &str| {
        Os::EVERY
            .into_iter()
            .filter(|os| oses_of(line).contains(*os))
            .map(Os::id)
            .collect::<Vec<_>>()
    };
    assert_eq!(set("#[cfg(unix)]"), ["linux", "macos"]);
    assert_eq!(set("#[cfg(not(unix))]"), ["windows"]);
    assert_eq!(set("#[cfg(not(windows))]"), ["linux", "macos"]);
    assert_eq!(set(r#"#[cfg(target_os = "linux")]"#), ["linux"]);
    assert_eq!(
        set(r#"#[cfg(any(target_os = "macos", target_os = "linux"))]"#),
        ["linux", "macos"]
    );
    assert_eq!(
        set(r#"#[cfg(not(any(target_os = "macos", target_os = "linux")))]"#),
        ["windows"]
    );
    assert_eq!(
        set(r#"#[cfg(all(unix, not(target_os = "macos")))]"#),
        ["linux"]
    );
    // What names no OS narrows nothing, even under `not`.
    assert_eq!(
        set(r#"#[cfg(not(feature = "x"))]"#),
        ["linux", "macos", "windows"]
    );
    assert_eq!(
        set(r#"#[cfg(all(unix, feature = "x"))]"#),
        ["linux", "macos"]
    );
    assert_eq!(set("#[test]"), ["linux", "macos", "windows"]);
}
