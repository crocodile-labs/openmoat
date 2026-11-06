//! What this release's default policy adds to a person's policy.
//!
//! `moat init` keeps an existing `policy.yaml`, so a new default reaches a person
//! only through `moat policy upgrade`. It merges the changes between the default
//! the policy started from (`policy.base.yaml`) and this release's default into
//! the policy, three ways (`merge.rs`), and leaves every line the person changed.
//! It also renames `ask`, the name `review` had before 0.14.0 (`rename.rs`).

use anyhow::Result;
use openmoat_core::DEFAULT_POLICY;

use crate::context::read_policy;
use crate::home::Home;

mod merge;
mod rename;

pub use merge::{Change, Merge};

/// The default OpenMoat 0.1.1 to 0.3.0 wrote: what a policy created before
/// `policy.base.yaml` existed is compared with. A policy 0.4.0 wrote has the
/// 0.4.0 changes already, which the merge counts as made.
const DEFAULT_V0_3_0: &str = include_str!("upgrade/default-v0.3.0.yaml");

/// Where the base of the comparison came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// `policy.base.yaml`, written by `moat init` or the last upgrade.
    Recorded,
    /// No record: the policy predates it and is compared with the 0.3.0 default.
    Assumed,
    /// No record, and the policy shares under half of the 0.3.0 default's lines:
    /// it was not made from a default, so no change is offered.
    Unrelated,
}

pub struct Plan {
    pub base: Base,
    /// The policy as it is.
    pub current: String,
    pub merge: Merge,
    /// The policy said `ask` where it now says `review` (ADR-053), and the
    /// merged text renames it.
    pub renamed: bool,
}

impl Plan {
    pub fn for_home(home: &Home) -> Result<Self> {
        let current = read_policy(&home.policy_path())?;
        let base_path = home.policy_base_path();
        let (base, source) = if base_path.is_file() {
            (read_policy(&base_path)?, Base::Recorded)
        } else {
            (DEFAULT_V0_3_0.to_owned(), Base::Assumed)
        };
        // Both sides renamed first, so the merge lines the renamed key up with
        // the default's `review:` instead of seeing a change next to it.
        let (yours, renamed) = rename::old_names(&current);
        let base = rename::old_names(&line_endings_of(&current, &base)).0;
        let new = line_endings_of(&current, DEFAULT_POLICY);
        let mut merge = merge::merge(&base, &yours, &new);
        let source = if source == Base::Assumed && merge.kept * 2 < merge.base_lines {
            merge = merge::merge(&base, &yours, &base);
            Base::Unrelated
        } else {
            source
        };
        Ok(Self {
            base: source,
            current,
            merge,
            renamed,
        })
    }

    /// How many changes applying would make: the default's, and the rename.
    pub fn applicable(&self) -> usize {
        self.merge.applied().count() + usize::from(self.renamed)
    }
}

/// "N changes from the OpenMoat X default", which `moat`, `moat init` and `moat
/// doctor` show while the policy can take changes; `None` when it has none or
/// cannot be read (the commands that load it report that themselves).
pub fn available(home: &Home) -> Option<String> {
    let count = Plan::for_home(home).ok()?.applicable();
    (count > 0).then(|| {
        let plural = if count == 1 { "" } else { "s" };
        let version = crate::VERSION;
        format!("{count} change{plural} from the OpenMoat {version} default")
    })
}

/// `text` with `like`'s line endings: a policy saved with CRLF still lines up
/// with the shipped default, which is LF.
fn line_endings_of(like: &str, text: &str) -> String {
    let lf = text.replace("\r\n", "\n");
    if like.contains("\r\n") {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

#[cfg(test)]
mod tests;
