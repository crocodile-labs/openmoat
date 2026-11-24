//! The packages a lockfile change resolves (ADR-125): each new or changed
//! entry's name, checked as a direct dependency's is (a near miss of a
//! popular name), and an install script the lockfile records for it.
//!
//! A lockfile lists every package the install fetches, the transitive ones
//! included, so a look-alike that a dependency pulls in, or a package that
//! starts running a script at install, shows here and in no manifest.

use std::collections::BTreeSet;

use super::super::files::Lock;
use super::super::{Change, Hit, INSTALL_SCRIPT, Level, PACKAGE_NEAR_MISS, shown};
use crate::packages::near_miss;

/// The name of the package whose entry `text` opens or names, if it does.
pub(super) fn name(lock: Lock, text: &str) -> Option<String> {
    let t = text.trim();
    let name = match lock {
        // `"node_modules/a/node_modules/@scope/b": {`
        Lock::Npm => {
            let key = t.strip_prefix('"')?.split('"').next()?;
            let (_, last) = key.rsplit_once("node_modules/")?;
            t[key.len() + 2..]
                .trim_start()
                .starts_with(':')
                .then_some(last)?
        }
        // v6 `/name@1.2.3:`, `/@scope/name@1.2.3(peer@1):`; v9 `name@1.2.3:`, `'@scope/name@1.2.3':`
        Lock::Pnpm => {
            let indent = text.len() - text.trim_start().len();
            let key = t.strip_suffix(':')?.trim_matches(['\'', '"']);
            let key = key.strip_prefix('/').unwrap_or(key);
            (indent == 2).then_some(())?;
            before_version(key)?
        }
        // `name@^1, name@^1.2:`, `"@scope/name@npm:^1.2.3":` at the start of a line
        Lock::Yarn => {
            (!text.starts_with([' ', '\t', '#'])).then_some(())?;
            let first = t
                .strip_suffix(':')?
                .split(',')
                .next()?
                .trim()
                .trim_matches('"');
            before_version(first)?
        }
        // `name = "serde"` in a `[[package]]` table
        Lock::Cargo | Lock::Python => {
            let value = t.strip_prefix("name = \"")?.strip_suffix('"')?;
            (!value.is_empty()).then_some(value)?
        }
        // `module v1.2.3 h1:…` and `module v1.2.3/go.mod h1:…`
        Lock::Go => {
            let mut words = t.split_whitespace();
            let module = words.next()?;
            words.next()?.starts_with('v').then_some(module)?
        }
    };
    Some(name.to_owned())
}

/// `name@range` → `name`, keeping a scope's leading `@`.
fn before_version(key: &str) -> Option<&str> {
    let at = key.get(1..)?.find('@')? + 1;
    Some(&key[..at])
}

/// One finding per new or changed entry whose name is a near miss of a
/// popular package's, and per entry the change marks as running an install
/// script (npm's `"hasInstallScript": true`, pnpm's `requiresBuild: true`).
pub(super) fn scan(lock: Lock, change: &Change<'_>, hits: &mut Vec<Hit>) {
    let ecosystem = lock.ecosystem();
    let mut seen = BTreeSet::new();
    // the entry the added lines are in, while they follow on from its name
    let mut entry: Option<String> = None;
    let mut previous = None;
    for (line, text) in change.added {
        if previous.is_none_or(|p: usize| p + 1 != *line) {
            entry = None;
        }
        previous = Some(*line);
        if let Some(name) = name(lock, text) {
            if seen.insert(name.clone())
                && let Some(popular) = near_miss(ecosystem, &name)
            {
                hits.push(Hit::new(
                    PACKAGE_NEAR_MISS,
                    Level::Review,
                    *line,
                    format!(
                        "locks the {} package `{}`, one typo or trick away from the popular \
                         `{popular}`: a dependency may pull in a look-alike that no manifest \
                         names; check which one is meant",
                        ecosystem.id(),
                        shown(&name)
                    ),
                ));
            }
            entry = Some(name);
        }
        if runs_script(lock, text) {
            let what = entry.as_deref().map_or_else(
                || "a locked package".to_owned(),
                |n| format!("`{}`", shown(n)),
            );
            hits.push(Hit::new(
                INSTALL_SCRIPT,
                Level::Review,
                *line,
                format!(
                    "records an install script for {what}: the next install runs it, for a \
                     package a dependency pulls in too"
                ),
            ));
        }
    }
}

fn runs_script(lock: Lock, text: &str) -> bool {
    let t = text.trim().trim_end_matches(',');
    match lock {
        Lock::Npm => t == "\"hasInstallScript\": true",
        Lock::Pnpm => t == "requiresBuild: true",
        Lock::Yarn | Lock::Cargo | Lock::Python | Lock::Go => false,
    }
}
