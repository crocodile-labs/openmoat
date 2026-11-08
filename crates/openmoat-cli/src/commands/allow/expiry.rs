//! `openmoat allow --for` and `--prune`: standing grants that end, and
//! removing those that did (ADR-007, amendment of 2026-11-08).

use std::io::Write as _;

use anyhow::{Result, bail};

use crate::approvals::{GRANT_TTL_MS, Overlay, State, Window};
use crate::cli::AllowArgs;
use crate::home::Home;
use crate::render::{self, Deferred};
use crate::time;

/// `--for` ends a standing grant only: a session grant already ends.
pub(super) fn check_for(args: &AllowArgs) -> Result<()> {
    if args.for_ms.is_some() && !(args.always || args.site.is_some() || args.dir.is_some()) {
        bail!(
            "--for ends an --always, --site or --dir grant; a session grant already ends {} \
             after it is given",
            time::duration(GRANT_TTL_MS)
        );
    }
    Ok(())
}

/// Give the entry `id` its end: after `for_ms` from now, or none. Granting
/// the same thing again comes here too, so the end is always the one just
/// asked for. The line that says when it ends.
pub(super) fn set(overlay: &mut Overlay, id: &str, for_ms: Option<i64>) -> String {
    let now = time::now_ms();
    let window = for_ms.map(|span| Window::starting(now, span));
    let line = match window.as_ref().map(|w| w.state(now)) {
        Some(State::Holds { until_ms }) => format!(
            "ends {} (in {}); `openmoat allow --prune` removes it after that",
            time::timestamp(until_ms),
            time::duration(until_ms.saturating_sub(now))
        ),
        Some(_) => "ends now".to_owned(),
        None => "lasts until you remove it".to_owned(),
    };
    overlay.set_window(id, window);
    line
}

/// Remove the grants whose `--for` ended, or whose end cannot be read, and
/// say which; `false` when there were none and nothing was written.
pub(super) fn prune(home: &Home, out: &mut Deferred) -> Result<bool> {
    let path = home.overlay_path();
    let mut overlay = Overlay::load(&path)?;
    let before = overlay.clone();
    let removed = overlay.prune(time::now_ms());
    if overlay == before {
        writeln!(
            out,
            "nothing to prune: no grant in {} has ended",
            path.display()
        )?;
        return Ok(false);
    }
    overlay.save(&path)?;
    if let Err(error) = home.load_policy() {
        before.save(&path)?;
        return Err(error.context(format!("{} left unchanged", path.display())));
    }
    writeln!(out, "✔ removed from {}:", path.display())?;
    if removed.is_empty() {
        writeln!(out, "    only `expires` entries that name no grant")?;
        return Ok(true);
    }
    for line in openmoat_core::yaml::to_string(&removed)?.lines() {
        render::line(out, &format!("    {line}"))?;
    }
    Ok(true)
}
