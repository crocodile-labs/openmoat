//! `moat report`: how the policy behaved over a window.

use std::collections::BTreeSet;
use std::io::{self, Write as _};

use anyhow::Result;
use openmoat_audit::{ExportFilter, Store, Summary};
use openmoat_core::STAGING_ATOM;
use openmoat_hosts::Host;
use serde::Serialize;

use crate::cli::{Format, ReportArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn run(args: &ReportArgs) -> Result<Code> {
    let (summary, staging) = build(args)?;
    match args.format {
        Format::Json => render::json(&Report {
            summary: &summary,
            staging: &staging,
        })?,
        Format::Text => {
            render::report(&summary, &args.since)?;
            if staging.sends > 0 {
                let centi = staging.per_active_hour_centi;
                writeln!(
                    io::stdout().lock(),
                    "sends after collecting outside the project (@staging-egress, recorded): {} in \
                     {} sessions, {}.{:02} per active hour; up to {} files and {} folders read \
                     outside, {} files packed",
                    staging.sends,
                    staging.sessions,
                    centi / 100,
                    centi % 100,
                    staging.most_outside_reads,
                    staging.most_outside_folders,
                    staging.most_staged,
                )?;
            }
        }
    }
    Ok(Code::Ok)
}

/// The window's summary and staging counts, from the audit log read-only.
fn build(args: &ReportArgs) -> Result<(Summary, StagingCounts)> {
    let since = time::parse_since(&args.since, time::now_ms())?;
    let store = Home::locate()?.open_audit()?;
    let host = args.host.map(Host::id);
    let summary = store.summary(since, host)?;
    let staging = staging(&store, since, host, summary.active_hours)?;
    Ok((summary, staging))
}

/// The report `--format json` prints, which `openmoat serve` sends too.
pub(super) fn json(args: &ReportArgs) -> Result<serde_json::Value> {
    let (summary, staging) = build(args)?;
    Ok(serde_json::to_value(Report {
        summary: &summary,
        staging: &staging,
    })?)
}

/// The summary, with the staging counts beside it.
#[derive(Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    summary: &'a Summary,
    staging: &'a StagingCounts,
}

/// The calls of the window that carried `@staging-egress` (ADR-061, proposed),
/// read back from their recorded reasons: how often a send of data followed
/// collection outside the project, to set the thresholds from before any rule
/// decides it.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct StagingCounts {
    /// Calls with at least one `@staging-egress` reason.
    sends: u64,
    /// Sessions they were in.
    sessions: u64,
    /// `sends` per active hour of the window, times 100.
    per_active_hour_centi: u64,
    /// The most outside reads, outside folders and packed files behind one of them.
    most_outside_reads: u64,
    most_outside_folders: u64,
    most_staged: u64,
}

fn staging(
    store: &Store,
    since_ms: i64,
    host: Option<&str>,
    active_hours: u64,
) -> Result<StagingCounts> {
    let events = store.export(&ExportFilter {
        since_ms,
        host,
        session_id: None,
    })?;
    let marker = format!("{STAGING_ATOM} ");
    let mut out = StagingCounts::default();
    let mut sessions = BTreeSet::new();
    for event in events {
        let reasons: Vec<String> = serde_json::from_str(event.reasons.get()).unwrap_or_default();
        let staging_reasons: Vec<&String> =
            reasons.iter().filter(|r| r.contains(&marker)).collect();
        if staging_reasons.is_empty() {
            continue;
        }
        out.sends += 1;
        sessions.insert((event.host, event.session_id));
        for (reads, folders, staged) in staging_reasons.iter().filter_map(|r| counts(r)) {
            out.most_outside_reads = out.most_outside_reads.max(reads);
            out.most_outside_folders = out.most_outside_folders.max(folders);
            out.most_staged = out.most_staged.max(staged);
        }
    }
    out.sessions = u64::try_from(sessions.len()).unwrap_or(u64::MAX);
    out.per_active_hour_centi = out.sends.saturating_mul(100) / active_hours.max(1);
    Ok(out)
}

/// The counts a `@staging-egress` reason ends with:
/// `[outside reads 31, folders 2, staged 1]`.
fn counts(reason: &str) -> Option<(u64, u64, u64)> {
    let (_, tail) = reason.rsplit_once("[outside reads ")?;
    let inside = tail.split(']').next()?;
    let mut parts = inside.split(", ");
    let reads = parts.next()?.trim().parse().ok()?;
    let folders = parts.next()?.strip_prefix("folders ")?.parse().ok()?;
    let staged = parts.next()?.strip_prefix("staged ")?.parse().ok()?;
    Some((reads, folders, staged))
}

#[cfg(test)]
mod tests {
    use super::counts;

    #[test]
    fn the_counts_are_read_back_from_a_reason() {
        let reason = "@staging-egress api.github.com: sends data after this session read 31 files \
                      and 2 folders outside the project, e.g. /h/a, /h/b [outside reads 31, folders \
                      2, staged 1]; recorded only, no rule decides it";
        assert_eq!(counts(reason), Some((31, 2, 1)));
        assert_eq!(counts("no counts here"), None);
    }
}
