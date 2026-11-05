//! The audit log's writes of a repository's files, as the core attributes
//! them (ADR-056).
//!
//! The record of each session's newest write of a file (ADR-039) gives the
//! session, the event and the content hashes. Whether the session had read
//! untrusted content before the write comes from two places: its own calls
//! before the write that read some ([`CompiledPolicy::untrusted_read`], the
//! same atoms session taint counts), and the tainted-write row the hook
//! recorded with the write (ADR-029), which also covers a file of tainted
//! provenance the session read.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_audit::{EventId, RecordedWrite, Store};
use openmoat_core::attribution::{AgentWrite, ChangedFile, Commit, Untrusted};
use openmoat_core::{CompiledPolicy, UntrustedKind, Verdict};
use openmoat_hosts::Host;

use crate::context;
use crate::realpath::FsPathResolver;
use crate::taint;
use crate::taint::provenance::key;

/// Longest untrusted-content source a note keeps.
const MAX_SOURCE_CHARS: usize = 200;

/// How many events of a session are read at a time.
const PAGE_LEN: usize = 512;

/// One commit as git has it, ready to attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitFacts {
    /// The full hash.
    pub commit: String,
    /// The first parent's committer time (ms); `None` for a root commit.
    pub parent_ms: Option<i64>,
    /// The committer time (ms).
    pub commit_ms: i64,
    /// What it changes, with repository paths.
    pub files: Vec<ChangedFile>,
}

impl CommitFacts {
    /// The commit as the core attributes it.
    pub fn as_commit(&self) -> Commit<'_> {
        Commit {
            parent_ms: self.parent_ms,
            commit_ms: self.commit_ms,
            files: &self.files,
        }
    }
}

/// The repository's root as the hook records paths under it: as git names
/// it and with its links resolved, in the lookup form ([`key`]).
#[derive(Debug, Clone)]
pub struct Root {
    prefixes: Vec<String>,
    case_insensitive: bool,
}

impl Root {
    /// `toplevel` (and `real`, its resolved spelling) on a file system that
    /// ignores case when `case_insensitive`.
    pub fn new(toplevel: &str, real: Option<&str>, case_insensitive: bool) -> Self {
        let mut prefixes = Vec::new();
        for root in std::iter::once(toplevel).chain(real) {
            let mut prefix = key(root.trim_end_matches('/'), case_insensitive);
            prefix.push('/');
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
        Self {
            prefixes,
            case_insensitive,
        }
    }

    /// The repository path of `stored` (a lookup-form absolute path), if it
    /// is under the root.
    fn relative<'a>(&self, stored: &'a str) -> Option<&'a str> {
        self.prefixes
            .iter()
            .find_map(|p| stored.strip_prefix(p.as_str()))
            .filter(|rel| !rel.is_empty())
    }
}

/// The recorded writes of the files `commits` change, up to `until_ms`, with
/// the commit's own spelling of each path. `policy` classifies the sessions'
/// earlier calls; `cwd` stands in for a call recorded without one.
pub fn writes(
    store: &Store,
    policy: &CompiledPolicy<'_>,
    root: &Root,
    commits: &[CommitFacts],
    until_ms: i64,
) -> Result<Vec<AgentWrite>> {
    let mut wanted: BTreeMap<String, &str> = BTreeMap::new();
    for file in commits.iter().flat_map(|c| &c.files) {
        wanted.insert(key(&file.path, root.case_insensitive), &file.path);
    }
    let recorded = store
        .writes_up_to(until_ms)
        .context("reading the files agent sessions wrote from the audit log")?;
    let mut sessions = Sessions {
        store,
        policy,
        cwd: policy.context().cwd.clone(),
        first: HashMap::new(),
    };
    let mut out = Vec::new();
    for write in recorded {
        let Some(path) = root
            .relative(&write.written.path)
            .and_then(|r| wanted.get(r))
        else {
            continue;
        };
        let untrusted = sessions.untrusted_before(&write)?;
        out.push(AgentWrite {
            path: (*path).to_owned(),
            host: write.host,
            session: write.session_id,
            event: write.written.event_id.0,
            ts_ms: write.written.ts_ms,
            sha256: write.written.sha256,
            before: write.written.before,
            untrusted,
        });
    }
    Ok(out)
}

/// The first untrusted read of each session, looked up once.
struct Sessions<'a> {
    store: &'a Store,
    policy: &'a CompiledPolicy<'a>,
    cwd: String,
    first: HashMap<(String, String), Option<(EventId, Untrusted)>>,
}

impl Sessions<'_> {
    /// What untrusted content the session had read before `write`.
    fn untrusted_before(&mut self, write: &RecordedWrite) -> Result<Option<Untrusted>> {
        let event = write.written.event_id;
        let slot = (write.host.clone(), write.session_id.clone());
        let first = if let Some(first) = self.first.get(&slot) {
            first.clone()
        } else {
            let first = self.first_read(&write.host, &write.session_id)?;
            self.first.insert(slot, first.clone());
            first
        };
        if let Some((read, untrusted)) = first
            && read.0 < event.0
        {
            return Ok(Some(untrusted));
        }
        // the hook's own record: it also knows the tainted files the session read
        let recorded = self
            .store
            .tainted_write_at(event, &write.written.path)
            .context("reading file provenance from the audit log")?;
        Ok(recorded.map(|source| Untrusted {
            kind: UntrustedKind::File,
            source: clip(&source),
        }))
    }

    /// The session's first call that ran and read untrusted content.
    fn first_read(&self, host: &str, session: &str) -> Result<Option<(EventId, Untrusted)>> {
        let known: Option<Host> = host.parse().ok();
        let mut after = EventId(0);
        loop {
            let events = self
                .store
                .session_page(session, after, PAGE_LEN)
                .context("reading a session from the audit log")?;
            for event in &events {
                let ran = match known {
                    Some(h) => taint::ran(h, event.verdict),
                    None => event.verdict != Verdict::Deny,
                };
                let (true, true, Some(action)) = (event.host == host, ran, &event.action) else {
                    continue;
                };
                let cwd = event
                    .cwd
                    .as_deref()
                    .map_or_else(|| self.cwd.clone(), |c| context::path_string(Path::new(c)));
                if let Some((kind, what)) =
                    self.policy.untrusted_read(action, &cwd, &FsPathResolver)
                {
                    let source = clip(&openmoat_audit::redact(&what));
                    return Ok(Some((event.id, Untrusted { kind, source })));
                }
            }
            match events.last() {
                Some(last) if events.len() == PAGE_LEN => after = last.id,
                _ => return Ok(None),
            }
        }
    }
}

/// `text` redacted as the audit log redacts, and cut to [`MAX_SOURCE_CHARS`].
fn clip(text: &str) -> String {
    let text = openmoat_audit::redact(text);
    match text.char_indices().nth(MAX_SOURCE_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}
