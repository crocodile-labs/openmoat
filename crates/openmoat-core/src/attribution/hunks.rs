//! The added lines of each file in a `git diff -U0` patch, from its hunk
//! headers (`@@ -a,b +c,d @@`). A file whose name git quoted (it holds a
//! tab, a newline or a quote) is left out: its lines are not claimed.

use std::collections::BTreeMap;

use super::LineRange;

/// The lines each file of `patch` adds, by its path in the new tree.
#[must_use]
pub fn added_lines(patch: &str) -> BTreeMap<String, Vec<LineRange>> {
    let mut out: BTreeMap<String, Vec<LineRange>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            current = None;
        } else if let Some(name) = line.strip_prefix("+++ ") {
            current = name
                .strip_prefix("b/")
                .filter(|_| !name.starts_with('"'))
                .map(str::to_owned);
        } else if let (Some(path), Some(header)) = (&current, line.strip_prefix("@@ "))
            && let Some(range) = new_range(header)
        {
            out.entry(path.clone()).or_default().push(range);
        }
    }
    out
}

/// The `+c,d` part of a hunk header as lines; `None` when it adds none.
fn new_range(header: &str) -> Option<LineRange> {
    let plus = header.split(' ').find_map(|w| w.strip_prefix('+'))?;
    let (start, count) = match plus.split_once(',') {
        Some((start, count)) => (start.parse::<u32>().ok()?, count.parse::<u32>().ok()?),
        None => (plus.parse::<u32>().ok()?, 1),
    };
    if count == 0 || start == 0 {
        return None;
    }
    Some(LineRange {
        start,
        end: start.saturating_add(count - 1),
    })
}
