//! Published security advisories of a host's own releases, which `moat doctor`
//! and `moat status` warn about when the version on the search path is
//! affected. OpenMoat checks tool calls; a flaw inside the agent's own process
//! (an OAuth sign-in, a trust dialog) runs where no hook sees it, so the one
//! thing OpenMoat can do is say that the agent needs an upgrade.

/// A version as `(major, minor, patch)`.
pub type Version = (u64, u64, u64);

/// The operating system an agent runs on, as far as an advisory names one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS.
    MacOs,
    /// Linux other than the Windows Subsystem for Linux.
    Linux,
    /// Linux under the Windows Subsystem for Linux.
    Wsl,
    /// Windows.
    Windows,
}

/// A host's advisories and the program whose `--version` says whether one
/// applies ([`crate::HostSpec::advisories`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct Advisories {
    /// The host's program, looked for on the search path and run with
    /// `--version`; empty when the host has no advisories.
    pub program: &'static str,
    /// The advisories, the one to name first in a warning first.
    pub list: &'static [Advisory],
}

impl Advisories {
    /// No advisories: what a spec takes when it names none.
    pub const BASE: Advisories = Advisories {
        program: "",
        list: &[],
    };

    /// The advisories that apply to `version` on `platform`, in list order.
    pub fn affecting(
        &self,
        version: Version,
        platform: Platform,
    ) -> impl Iterator<Item = &'static Advisory> {
        self.list
            .iter()
            .filter(move |a| a.affects(version, platform))
    }
}

/// One published advisory: only ones with a source and a fixed version.
#[derive(Debug)]
#[non_exhaustive]
pub struct Advisory {
    /// The advisory's identifier (a CVE or GHSA id, or the publisher's name
    /// when it has neither).
    pub id: &'static str,
    /// What it is, in a few words.
    pub summary: &'static str,
    /// The first affected version.
    pub from: Version,
    /// The first version with the fix; versions from it on are not affected.
    pub fixed: Version,
    /// The systems it applies to; empty when the advisory names none.
    pub platforms: &'static [Platform],
    /// Where it is published.
    pub source: &'static str,
}

impl Advisory {
    /// An advisory `id` of `summary` for versions `from` up to, not
    /// including, `fixed` on `platforms` (every system when empty).
    #[must_use]
    pub const fn new(
        id: &'static str,
        summary: &'static str,
        (from, fixed): (Version, Version),
        platforms: &'static [Platform],
        source: &'static str,
    ) -> Self {
        Self {
            id,
            summary,
            from,
            fixed,
            platforms,
            source,
        }
    }

    /// Whether `version` on `platform` is affected.
    #[must_use]
    pub fn affects(&self, version: Version, platform: Platform) -> bool {
        self.from <= version
            && version < self.fixed
            && (self.platforms.is_empty() || self.platforms.contains(&platform))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS_ONLY: Advisory = Advisory::new(
        "X",
        "x",
        ((1, 0, 137), (1, 18, 33)),
        &[Platform::Windows, Platform::Wsl],
        "https://example.invalid/x",
    );

    #[test]
    fn a_range_takes_its_first_version_and_not_its_fixed_one() {
        let on = |v| WINDOWS_ONLY.affects(v, Platform::Windows);
        assert!(!on((1, 0, 136)));
        assert!(on((1, 0, 137)));
        assert!(on((1, 18, 32)));
        assert!(!on((1, 18, 33)));
        assert!(!on((2, 0, 0)));
    }

    #[test]
    fn a_platform_list_limits_it_and_an_empty_one_does_not() {
        assert!(WINDOWS_ONLY.affects((1, 5, 0), Platform::Wsl));
        assert!(!WINDOWS_ONLY.affects((1, 5, 0), Platform::Linux));
        assert!(!WINDOWS_ONLY.affects((1, 5, 0), Platform::MacOs));
        let any = Advisory::new("Y", "y", ((0, 0, 0), (0, 39, 1)), &[], "s");
        assert!(any.affects((0, 39, 0), Platform::MacOs));
        assert!(!any.affects((0, 39, 1), Platform::Linux));
    }
}
