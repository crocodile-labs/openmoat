//! `go.sum` (ADR-125): one line per module version, `module version h1:hash`
//! (and `module version/go.mod h1:hash` for its `go.mod`). A line removed and
//! added back with the same module and version but another hash makes the next
//! build accept other code under that version; Go's checksum database would
//! refuse it only where it is consulted (not for a module `GOPRIVATE` or
//! `GONOSUMDB` names, nor with `GOSUMDB=off`).

use super::super::{Change, Hit, LOCK_INTEGRITY, Level, shown};

/// `module version` and its hash, from one `go.sum` line.
fn entry(text: &str) -> Option<(&str, &str, &str)> {
    let mut words = text.split_whitespace();
    let (module, version, hash) = (words.next()?, words.next()?, words.next()?);
    (version.starts_with('v') && hash.contains(':') && words.next().is_none())
        .then_some((module, version, hash))
}

/// One finding per module version whose hash a block changes.
pub(super) fn scan(change: &Change<'_>, hits: &mut Vec<Hit>) {
    for block in change.blocks {
        let removed: Vec<_> = block.removed.iter().filter_map(|t| entry(t)).collect();
        for (line, text) in change.added_in(block) {
            let Some((module, version, hash)) = entry(text) else {
                continue;
            };
            let changed = removed
                .iter()
                .any(|(m, v, h)| *m == module && *v == version && *h != hash);
            if changed {
                hits.push(Hit::new(
                    LOCK_INTEGRITY,
                    Level::Deny,
                    *line,
                    format!(
                        "changes the hash of `{} {}` while its version stays: the next build \
                         accepts other code under the same version where Go's checksum database \
                         is not consulted",
                        shown(module),
                        shown(version)
                    ),
                ));
            }
        }
    }
}
