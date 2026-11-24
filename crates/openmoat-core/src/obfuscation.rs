//! Obfuscation as a signal (ADR-116): a deterministic score of how much a
//! command line is written to hide what it runs, after MITRE ATT&CK's
//! detection strategy DET0505 for obfuscated command lines (escape and quote
//! density, character-by-character concatenation, indirect expansion, strings
//! built and decoded at run time, unusual length, a high-entropy word).
//!
//! The classifier reads most of these spellings already (`$'\x63at'`,
//! `c''at` and `cat${IFS}` are the words bash builds). The score is for what
//! it cannot follow: a value computed at run time is unknown and the command
//! is `unparseable`, which the default policy leaves to the agent's prompt.
//! A line whose signals reach [`THRESHOLD`] gets an `@obfuscated <signals>`
//! atom, which the default rule `obfuscated` holds for review. Every signal
//! counts only text that agents' everyday commands do not contain; the
//! threshold was set against the conformance suite's benign fixtures and
//! `MoatBench`'s workflows (`tests/obfuscation.rs`), none of which reaches it.
//!
//! Pure text functions: no lexer state, no policy. Each dialect has its own
//! signals ([`posix`], [`powershell`]).

mod posix;
mod powershell;
#[cfg(test)]
mod tests;

pub(crate) use powershell::is_encoded_command;

/// The score at which a command line is held as obfuscated.
pub const THRESHOLD: u32 = 3;

/// Lines longer than this score [`Signal::Length`]: agents' commands are
/// short, except here-documents, which are checked apart.
const LONG_LINE: usize = 4096;

/// The shell dialect a command line is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// A POSIX shell: bash, zsh, sh.
    Posix,
    /// Windows PowerShell or PowerShell 7.
    PowerShell,
}

/// What the score found in one command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// The sum of the signals' weights.
    pub score: u32,
    /// The names of the signals found, in a fixed order (`ansi-escapes`,
    /// `quote-splitting`, …), each once.
    pub signals: Vec<&'static str>,
}

impl Assessment {
    /// Whether the score reaches [`THRESHOLD`].
    #[must_use]
    pub fn obfuscated(&self) -> bool {
        self.score >= THRESHOLD
    }

    fn add(&mut self, signal: &'static str, weight: u32) {
        if weight == 0 {
            return;
        }
        self.score += weight;
        if !self.signals.contains(&signal) {
            self.signals.push(signal);
        }
    }
}

/// Score `command` as written in `dialect`.
#[must_use]
pub fn assess(command: &str, dialect: Dialect) -> Assessment {
    let mut out = Assessment::default();
    match dialect {
        Dialect::Posix => posix::score(command, &mut out),
        Dialect::PowerShell => powershell::score(command, &mut out),
    }
    if command.len() > LONG_LINE && !command.contains("<<") {
        out.add("length", 1);
    }
    // a key or an encoded blob alone is not enough; it only adds to other signals
    if command
        .split(|c: char| c.is_whitespace() || "'\"`;|&()<>".contains(c))
        .any(high_entropy)
    {
        out.add("entropy", 1);
    }
    out
}

/// A word of 64 characters or more of mixed letters, digits and `+/=`, whose
/// characters carry more than 5 bits each: an encoded payload, not a hash
/// (hexadecimal carries 4 at most) or a path.
fn high_entropy(word: &str) -> bool {
    if word.len() < 64
        || !word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
    {
        return false;
    }
    let mut counts = [0u32; 256];
    for b in word.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = f64::from(u32::try_from(word.len()).unwrap_or(u32::MAX));
    let entropy: f64 = counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum();
    entropy > 5.0
}
