//! `moat audit anchor` and `moat audit verify --against` (ADR-031).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

use crate::anchor::{self, Failed, Last, Place, Record};
use crate::cli::{AnchorArgs, Format};
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::render::{self, Deferred};
use crate::time;

/// Person-only: an agent that could anchor whenever it liked could also choose
/// what the person's record says the log was.
pub fn run(args: &AnchorArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat audit anchor")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat audit anchor` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    let place = match (&args.git, &args.file) {
        (Some(repo), _) => Place::Git(context::absolute(repo)?),
        (None, Some(file)) => Place::File(context::absolute(file)?),
        (None, None) => bail!("give --git <repo> or --file <path>"),
    };
    let store = home.open_audit()?;
    let chain = store.verify_chain()?;
    if let Some(broken) = &chain.broken {
        bail!(
            "refusing to anchor a broken log: the hash chain breaks at event {}: {}; \
             keep the file as evidence",
            broken.id,
            broken.kind.describe()
        );
    }
    let head = store
        .head()?
        .context("the audit log has no chained events yet; nothing to anchor")?;
    let record = Record::new(&head, time::now_ms());
    let commit = place.append(&record, &git(&home)?)?;
    Last {
        anchored_ms: record.anchored_ms,
        event: record.event,
        to: place.describe(),
    }
    .save(&home)?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "✔ anchored event {} ({})  hash {}",
        record.event,
        time::timestamp(record.event_ms),
        record.hash
    )?;
    match (&place, commit) {
        (Place::Git(repo), Some(commit)) => {
            writeln!(
                out,
                "  committed {commit} on {} in {}",
                anchor::git::REF,
                repo.display()
            )?;
            writeln!(
                out,
                "  nothing was pushed; to keep a copy off this machine: git -C {} push <remote> {}",
                repo.display(),
                anchor::git::REF
            )?;
        }
        _ => writeln!(
            out,
            "  appended to {}; nothing was sent anywhere, so copy it off this machine yourself",
            place.describe()
        )?,
    }
    writeln!(
        out,
        "  check the log later with `openmoat audit verify --against {}`",
        match &place {
            Place::Git(path) | Place::File(path) => path.display(),
        }
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// git as the environment snapshot resolves it.
fn git(home: &Home) -> Result<PathBuf> {
    crate::environment::program(home, "git").context(
        "git was not found on the search path `openmoat init` recorded; install git or use --file",
    )
}

#[derive(Serialize)]
struct Report {
    anchors: usize,
    events: u64,
    head: Option<String>,
    failed: Option<Failed>,
}

/// Exit 0 when every anchor still matches the log, else 64.
pub fn verify_against(path: &Path, format: Format) -> Result<Code> {
    let home = Home::locate()?;
    let place = Place::of(&context::absolute(path)?);
    let git = match &place {
        Place::Git(_) => git(&home)?,
        Place::File(_) => PathBuf::from("git"),
    };
    let records = place.records(&git)?;
    let store = home.open_audit()?;
    let chain = store.verify_chain()?;
    let failed = anchor::check(&records, &chain, |id| Ok(store.hash_of(id)?))?;
    let code = if failed.is_none() {
        Code::Ok
    } else {
        Code::Usage
    };
    let report = Report {
        anchors: records.len(),
        events: chain.events,
        head: chain.head,
        failed,
    };
    if format == Format::Json {
        render::json(&report)?;
        return Ok(code);
    }
    let mut out = Deferred::default();
    match &report.failed {
        None => {
            let newest = records
                .last()
                .map(|r| r.event.to_string())
                .unwrap_or_default();
            writeln!(
                out,
                "✔ {} anchor(s) from {} hold: the log still holds each anchored event with its hash \
                 (newest anchored: event {newest}; {} events now)",
                report.anchors,
                place.describe(),
                report.events
            )?;
        }
        Some(failed) => {
            let record = &failed.record;
            writeln!(
                out,
                "⛔ anchor {} of {} (event {}, anchored {}) no longer matches: {}",
                failed.number,
                report.anchors,
                record.event,
                time::timestamp(record.anchored_ms),
                failed.why.describe()
            )?;
            writeln!(out, "   anchored hash {}", record.hash)?;
        }
    }
    out.finish()?;
    Ok(code)
}
