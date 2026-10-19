//! What `moat init` would change in one agent's files, shown before it asks.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use similar::{Algorithm, udiff::unified_diff};

use crate::home::Home;
use crate::install::HostConfig;
use crate::render::Deferred;
use crate::sandbox::{self, Plan};

/// One file `init` would write: its path, its text now and after.
struct Change {
    path: PathBuf,
    before: String,
    after: String,
}

/// Print, as unified diffs, every change `init` would make to `config`'s host:
/// its hooks and, with `plan`, its sandbox settings, combined where they share
/// a file (Claude Code's `settings.json`). Writes nothing.
pub(super) fn show(
    home: &Home,
    config: &HostConfig,
    binary: &Path,
    plan: Option<&Plan>,
    out: &mut Deferred,
) -> Result<()> {
    let changes = changes(home, config, binary, plan)?;
    if changes.is_empty() {
        writeln!(out, "  no change to {}'s files", config.host.display_name())?;
    }
    for change in &changes {
        let name = change.path.display().to_string();
        let diff = unified_diff(
            Algorithm::Myers,
            &change.before,
            &change.after,
            3,
            Some((
                &format!("{name} (now)"),
                &format!("{name} (after moat init)"),
            )),
        );
        write!(out, "{diff}")?;
    }
    Ok(())
}

fn changes(
    home: &Home,
    config: &HostConfig,
    binary: &Path,
    plan: Option<&Plan>,
) -> Result<Vec<Change>> {
    let path = config.settings_path.clone();
    let before = sandbox::install::read_text(&path)?;
    let after = config
        .render(binary, &before)?
        .unwrap_or_else(|| before.clone());
    let mut changes = vec![Change {
        path,
        before,
        after,
    }];
    let host = config.host;
    if let Some(plan) = plan
        && sandbox::install::format(host).is_some()
    {
        let path = sandbox::install::settings_path(home, host)?;
        if let Some(shared) = changes.iter_mut().find(|c| c.path == path) {
            if let Some(r) = sandbox::install::render(home, host, plan, &shared.after)? {
                shared.after = r.text;
            }
        } else {
            let before = sandbox::install::read_text(&path)?;
            let after = sandbox::install::render(home, host, plan, &before)?
                .map_or_else(|| before.clone(), |r| r.text);
            changes.push(Change {
                path,
                before,
                after,
            });
        }
    }
    changes.retain(|c| c.before != c.after);
    Ok(changes)
}
