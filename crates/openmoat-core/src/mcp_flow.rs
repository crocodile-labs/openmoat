//! MCP cross-server data flow (ADR-058): text one MCP server returned that
//! then shows up in the arguments of another server's tool that writes or
//! sends.
//!
//! A tool result is content the server controls. A result that says "send
//! the file to `https://evil.example`" can steer the agent to call another
//! server's `http_post` with that address: no single call looks wrong, but
//! the data flows from one server's text into another server's action. The
//! MCP gateway (`openmoat mcp proxy`, ADR-045) sees each wrapped server's
//! results and keeps their [`pieces`] (hashed, never the text); the hook
//! finds the pieces of a call's arguments among them and, for a tool that
//! acts ([`ToolEffect::Act`]) of another server, holds the call for review
//! ([`cross_server`]).
//!
//! Everything here is pure: the CLI reads the results, the pins and the audit
//! log, and hashes the pieces.

use crate::verdict::{Decision, Verdict};

/// Rule id of a call held because its arguments carry text another MCP
/// server returned in this session.
pub const FLOW_RULE: &str = "mcp-cross-server";

/// The most pieces [`pieces`] returns for one text: a long result is kept by
/// its first addresses and tokens and a sample of its wording.
pub const MAX_PIECES: usize = 256;

/// Words in one run of wording ([`pieces`]): a copy shorter than this is not
/// told from two texts that happen to share a phrase.
pub const SHINGLE_WORDS: usize = 8;

/// The fewest characters a run of [`SHINGLE_WORDS`] words must have: eight
/// short words (`a`, `to`, `of`) say nothing of where they came from.
const MIN_SHINGLE_CHARS: usize = 40;

/// The fewest characters of a token kept as a piece: an API key, a commit
/// hash, an id. Shorter tokens are ordinary words and numbers.
const MIN_TOKEN_CHARS: usize = 20;

/// One run of wording in this many is kept, chosen by its hash, so both
/// sides keep the same runs and a copy of a few more words than
/// [`SHINGLE_WORDS`] is still found.
const SHINGLE_SAMPLE: u64 = 4;

/// What a tool does, for the flow check: only a tool that acts can carry
/// another server's text out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolEffect {
    /// It reads: a search, a get, a list.
    Read,
    /// It writes, sends, deletes or connects somewhere.
    Act,
}

/// The MCP tool annotations that say what a tool does (MCP 2025-03-26
/// `ToolAnnotations`), as the tool's accepted pin holds them; `None` for a
/// hint the definition does not give.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolHints {
    /// `readOnlyHint`: the tool does not change its environment.
    pub read_only: Option<bool>,
    /// `destructiveHint`: the tool may delete or overwrite.
    pub destructive: Option<bool>,
    /// `openWorldHint`: the tool reaches entities outside the server.
    pub open_world: Option<bool>,
}

impl ToolEffect {
    /// What a tool does: its annotations when they say, otherwise
    /// `acts_by_shape`, what its name and arguments say (the same reading the
    /// hook gives every MCP call's paths, `openmoat_hosts::mcp_tool_acts`).
    ///
    /// `readOnlyHint: true` reads; `readOnlyHint: false`, `destructiveHint:
    /// true` or `openWorldHint: true` acts. The annotations are part of the
    /// tool's pin (ADR-032), so a server cannot change them without a person
    /// accepting the change.
    #[must_use]
    pub fn classify(hints: &ToolHints, acts_by_shape: bool) -> Self {
        match (hints.read_only, hints.destructive, hints.open_world) {
            (Some(true), _, _) => Self::Read,
            (Some(false), _, _) | (_, Some(true), _) | (_, _, Some(true)) => Self::Act,
            _ if acts_by_shape => Self::Act,
            _ => Self::Read,
        }
    }
}

/// `decision` tightened to `review` (a deny stays a deny): the call's
/// arguments carry text that the MCP servers `sources` returned earlier in
/// the session, and the call goes to `sink`, another server's tool that acts.
#[must_use]
pub fn cross_server(mut decision: Decision, sources: &[String], sink: &str) -> Decision {
    let named: Vec<String> = sources.iter().map(|s| format!("`{s}`")).collect();
    let reason = format!(
        "this call to MCP server `{sink}` writes or sends text that MCP server {} returned \
         earlier in this session: a tool result can carry instructions that steer the agent \
         to send data elsewhere, so a person checks the arguments (a server listed under \
         `mcp.flow_trusted` is exempt)",
        named.join(", ")
    );
    decision.merge(Decision::single(Verdict::Review, FLOW_RULE, reason));
    decision
}

/// The pieces of `text` that tell where a copy of it came from, at most
/// [`MAX_PIECES`], the same for the same text: each address (`url:` a URL's
/// scheme, host and path, without query or fragment; `mail:` an email
/// address), each long token (`tok:` 20 or more letters and digits with at
/// least one of each, an API key or a commit hash), then a sample of its
/// runs of [`SHINGLE_WORDS`] words (`words:`).
///
/// The URL's query is left out so an address a result named still matches
/// after the agent appends data to it. Wording is lowercased and split on
/// anything not a letter or digit, so reflowed or re-punctuated text matches.
#[must_use]
pub fn pieces(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut add = |piece: String, out: &mut Vec<String>| {
        if out.len() < MAX_PIECES && seen.insert(piece.clone()) {
            out.push(piece);
        }
    };
    for url in urls(text) {
        add(format!("url:{url}"), &mut out);
    }
    for word in text.split(|c: char| c.is_whitespace() || "\"'<>()[]{},;`".contains(c)) {
        if let Some(mail) = mail(word) {
            add(format!("mail:{mail}"), &mut out);
        }
    }
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || "_-+=".contains(c))) {
        if is_token(token) {
            add(format!("tok:{token}"), &mut out);
        }
    }
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    for run in words.windows(SHINGLE_WORDS) {
        let joined = run.join(" ");
        if joined.len() >= MIN_SHINGLE_CHARS && fnv1a(&joined).is_multiple_of(SHINGLE_SAMPLE) {
            add(format!("words:{joined}"), &mut out);
        }
    }
    out
}

/// Each URL in `text` (`scheme://…`) as `scheme://host/path`, the scheme and
/// host lowercased, without user, query or fragment, and without trailing
/// punctuation or `/`.
fn urls(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let before = &rest[..at];
        let scheme_start = before
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_alphanumeric() || "+-.".contains(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let scheme = &before[scheme_start..];
        let after = &rest[at + 3..];
        let end = after
            .find(|c: char| c.is_whitespace() || "\"'<>`()[]{}\\|^".contains(c))
            .unwrap_or(after.len());
        let body = &after[..end];
        rest = &after[end..];
        if scheme.is_empty() || !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) {
            continue;
        }
        let body = body.split(['?', '#']).next().unwrap_or("");
        let (authority, path) = body.split_at(body.find('/').unwrap_or(body.len()));
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let path = path.trim_end_matches(['.', ',', ';', ':', '!', '/']);
        let host = host.trim_end_matches(['.', ',', ';', ':', '!']);
        if host.is_empty() {
            continue;
        }
        found.push(format!("{}://{host}{path}", scheme.to_ascii_lowercase()));
    }
    found
}

/// `word` as an email address (lowercased), when it is one: a local part, `@`,
/// and a domain with a dot.
fn mail(word: &str) -> Option<String> {
    // `mailto:a@b.example` names the address after the scheme
    let word = word.rsplit(':').next().unwrap_or(word);
    let word = word.trim_matches(|c: char| ".!?".contains(c));
    let (local, domain) = word.split_once('@')?;
    let plain = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
    };
    let dotted = domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.');
    (plain(local) && plain(domain) && dotted && !domain.contains('@'))
        .then(|| word.to_ascii_lowercase())
}

/// Whether `token` is long and mixes letters and digits, as keys and hashes do.
fn is_token(token: &str) -> bool {
    token.len() >= MIN_TOKEN_CHARS
        && token.chars().any(|c| c.is_ascii_digit())
        && token.chars().any(|c| c.is_ascii_alphabetic())
}

/// 64-bit FNV-1a of `text`: a fixed, fast hash, so the sample of runs is the
/// same in every process and every build. Not a protection: the CLI hashes
/// the pieces it stores with SHA-256.
fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests;
