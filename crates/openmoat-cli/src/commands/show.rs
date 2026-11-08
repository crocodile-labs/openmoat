//! `moat show`: inspect audit events.

use anyhow::{Result, bail};
use openmoat_audit::{Event, EventId};

use crate::cli::{Format, ShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn run(args: &ShowArgs) -> Result<Code> {
    let events = events(args)?;
    match args.format {
        Format::Json => render::json(&events)?,
        Format::Text if args.id.is_some() => render::event_detail(&events[0])?,
        Format::Text => render::event_table(&events)?,
    }
    Ok(Code::Ok)
}

/// The events `args` names: what `--format json` prints and `openmoat serve`
/// sends. With an id, exactly one event or an error.
pub(super) fn events(args: &ShowArgs) -> Result<Vec<Event>> {
    let store = Home::locate()?.open_audit()?;
    Ok(if let Some(id) = &args.id {
        let id: EventId = id.parse()?;
        match store.get(id)? {
            Some(event) => vec![event],
            None => bail!("no event {id}"),
        }
    } else if let Some(session) = &args.session {
        store.session(session)?
    } else if let Some(since) = &args.since {
        store.since(time::parse_since(since, time::now_ms())?, None)?
    } else {
        store.recent(args.recent)?
    })
}
