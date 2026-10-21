//! The three-way line merge behind `moat policy upgrade`, as `diff3` does it.
//!
//! `base` is the shipped default a policy started from, `yours` the policy as it
//! is now, `new` this release's default. A stretch where `new` differs from
//! `base` is taken only where `yours` still has `base`'s lines; where both
//! changed the same lines, or lines next to each other, `yours` stays and the
//! stretch is reported instead.

use std::ops::Range;

use similar::{Algorithm, DiffTag, capture_diff_slices};

/// One stretch where the new default differs from the base and the policy does
/// not have that difference yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The policy still had the base's lines there, so the change was applied.
    pub clean: bool,
    /// 1-based line of the policy where the stretch starts.
    pub line: usize,
    /// The policy's lines there (empty where the default adds lines).
    pub yours: String,
    /// The new default's lines there.
    pub default: String,
}

/// The policy with every clean change applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    pub text: String,
    /// The base to compare with next time: the new default, but the old base
    /// where a change was not applied, so that change is reported again.
    pub base: String,
    pub changes: Vec<Change>,
    /// How many of the base's lines the policy still has unchanged.
    pub kept: usize,
    /// How many lines the base has.
    pub base_lines: usize,
}

impl Merge {
    /// The changes [`Merge::text`] applied.
    pub fn applied(&self) -> impl Iterator<Item = &Change> {
        self.changes.iter().filter(|c| c.clean)
    }

    /// The changes left out because the policy changed those lines.
    pub fn conflicts(&self) -> impl Iterator<Item = &Change> {
        self.changes.iter().filter(|c| !c.clean)
    }
}

/// Where one side differs from the base: base lines `base` became `side`.
struct Hunk {
    base: Range<usize>,
    side: Range<usize>,
}

/// A stretch of the base that one side or both changed.
struct Chunk<'h> {
    base: Range<usize>,
    yours: Vec<&'h Hunk>,
    new: Vec<&'h Hunk>,
}

/// [`merge_once`] until no clean change is left. A default's stretch that
/// touches one the person changed is held back with it, and the recorded base
/// keeps the old lines there; the next diff can then line that stretch up on
/// its own, as clean. Merging again here takes it now, so one upgrade leaves
/// nothing to offer next time but the stretches the person changed.
pub fn merge(base: &str, yours: &str, new: &str) -> Merge {
    let mut merged = merge_once(base, yours, new);
    // Each pass applies at least one change; a few are enough in practice.
    for _ in 0..8 {
        let next = merge_once(&merged.base, &merged.text, new);
        if next.applied().next().is_none() {
            break;
        }
        let earlier = merged.changes.into_iter().filter(|c| c.clean);
        merged = Merge {
            changes: earlier.chain(next.changes).collect(),
            text: next.text,
            base: next.base,
            ..merged
        };
    }
    merged
}

fn merge_once(base: &str, yours: &str, new: &str) -> Merge {
    let base_lines: Vec<&str> = base.split_inclusive('\n').collect();
    let your_lines: Vec<&str> = yours.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let your_hunks = hunks(&base_lines, &your_lines);
    let new_hunks = hunks(&base_lines, &new_lines);
    let changed: usize = your_hunks.iter().map(|h| h.base.len()).sum();

    let mut merged = Merge {
        text: String::new(),
        base: String::new(),
        changes: Vec::new(),
        kept: base_lines.len() - changed,
        base_lines: base_lines.len(),
    };
    let mut at = 0;
    let mut line = 1;
    for chunk in chunks(&your_hunks, &new_hunks) {
        let same = base_lines[at..chunk.base.start].concat();
        merged.text.push_str(&same);
        merged.base.push_str(&same);
        line += chunk.base.start - at;
        let original = base_lines[chunk.base.clone()].concat();
        let (mine, mine_count) = side(&base_lines, &your_lines, &chunk.yours, &chunk.base);
        let (theirs, _) = side(&base_lines, &new_lines, &chunk.new, &chunk.base);
        // Only the person changed it, or both made the same change: theirs stays.
        let clean = chunk.yours.is_empty() && !chunk.new.is_empty();
        if chunk.new.is_empty() {
            merged.base.push_str(&original);
        } else if mine == theirs {
            merged.base.push_str(&theirs);
        } else {
            merged
                .base
                .push_str(if clean { &theirs } else { &original });
            merged.changes.push(Change {
                clean,
                line,
                yours: mine.clone(),
                default: theirs.clone(),
            });
        }
        merged.text.push_str(if clean { &theirs } else { &mine });
        line += mine_count;
        at = chunk.base.end;
    }
    let rest = base_lines[at..].concat();
    merged.text.push_str(&rest);
    merged.base.push_str(&rest);
    merged
}

fn hunks(base: &[&str], side: &[&str]) -> Vec<Hunk> {
    capture_diff_slices(Algorithm::Myers, base, side)
        .iter()
        .filter_map(|op| {
            let (tag, base, side) = op.as_tag_tuple();
            (tag != DiffTag::Equal).then_some(Hunk { base, side })
        })
        .collect()
}

/// Both sides' hunks grouped into chunks: hunks that overlap or touch, even
/// across sides, share one, so a change next to a line the person edited is
/// never applied blind.
fn chunks<'h>(yours: &'h [Hunk], new: &'h [Hunk]) -> Vec<Chunk<'h>> {
    let mut all: Vec<(bool, &Hunk)> = yours
        .iter()
        .map(|h| (true, h))
        .chain(new.iter().map(|h| (false, h)))
        .collect();
    all.sort_by_key(|(_, h)| (h.base.start, h.base.end));
    let mut chunks: Vec<Chunk<'h>> = Vec::new();
    for (mine, hunk) in all {
        let joins = chunks
            .last()
            .is_some_and(|last| hunk.base.start <= last.base.end);
        if !joins {
            chunks.push(Chunk {
                base: hunk.base.clone(),
                yours: Vec::new(),
                new: Vec::new(),
            });
        }
        let Some(chunk) = chunks.last_mut() else {
            continue;
        };
        chunk.base.end = chunk.base.end.max(hunk.base.end);
        if mine {
            chunk.yours.push(hunk);
        } else {
            chunk.new.push(hunk);
        }
    }
    chunks
}

/// One side's text for the base lines `range`, and its number of lines: the
/// base's lines with that side's `hunks` (all inside `range`) put in.
fn side(base: &[&str], side: &[&str], hunks: &[&Hunk], range: &Range<usize>) -> (String, usize) {
    let mut text = String::new();
    let mut count = 0;
    let mut at = range.start;
    for hunk in hunks {
        text.push_str(&base[at..hunk.base.start].concat());
        text.push_str(&side[hunk.side.clone()].concat());
        count += hunk.base.start - at + hunk.side.len();
        at = hunk.base.end;
    }
    text.push_str(&base[at..range.end].concat());
    (text, count + range.end - at)
}
