//! Which `AppArmor` profile applies to `/usr/bin/bwrap` (#784): the kernel's
//! list of loaded profiles where this user may read it, else the profiles
//! `AppArmor` loads at boot from `/etc/apparmor.d/`. Read without privileges;
//! where neither can be read, nothing is known.
//!
//! Ubuntu's `bwrap-userns-restrict` profile (in the `apparmor` package from
//! 25.04, `apparmor-profiles` before) defines `bwrap` for `/usr/bin/bwrap` and
//! stacks what bubblewrap starts into `unpriv_bwrap`, which denies every
//! capability. Claude Code's sandboxing documentation instead gives a profile
//! `bwrap` for `/usr/bin/bwrap` with `flags=(unconfined)` and `userns`, in
//! `/etc/apparmor.d/bwrap`. Both name their profile `bwrap`, so only one of
//! them applies.

use std::path::Path;

use serde::Serialize;

/// The kernel's list of loaded profiles, one `name (mode)` per line; only a
/// user who may view the policy (root, as a rule) can read it.
pub const LOADED: &str = "/sys/kernel/security/apparmor/profiles";
/// Where `AppArmor`'s service loads profiles from at boot.
pub const PROFILE_DIR: &str = "/etc/apparmor.d";
/// Ubuntu's profile's file name, in [`PROFILE_DIR`] and in the packages.
pub const USERNS_RESTRICT: &str = "bwrap-userns-restrict";
/// The file Claude Code's documentation writes its profile to.
const DOCUMENTED_FILE: &str = "bwrap";

/// The profile that applies to `/usr/bin/bwrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BwrapProfile {
    /// No profile named `bwrap`.
    None,
    /// Ubuntu's `bwrap-userns-restrict`: `bwrap`, with `unpriv_bwrap` for
    /// what it starts.
    UsernsRestrict,
    /// `bwrap` with `flags=(unconfined)`, as Claude Code's documentation
    /// gives it.
    Unconfined,
    /// Some other profile named `bwrap`.
    Other,
}

/// Where [`BwrapProfileSeen::profile`] was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Seen {
    /// In the kernel's list of loaded profiles.
    Loaded,
    /// In [`PROFILE_DIR`], which `AppArmor` loads at boot.
    Installed,
}

/// The profile for `/usr/bin/bwrap`, and where that was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BwrapProfileSeen {
    /// The profile.
    pub profile: BwrapProfile,
    /// Where it was read.
    pub seen: Seen,
}

impl BwrapProfileSeen {
    /// This machine's, read without privileges; `None` where neither the
    /// kernel's list nor [`PROFILE_DIR`] can be read.
    pub fn here() -> Option<Self> {
        if let Ok(list) = std::fs::read_to_string(LOADED) {
            return Some(Self {
                profile: from_loaded(&list),
                seen: Seen::Loaded,
            });
        }
        let dir = Path::new(PROFILE_DIR);
        let names = file_names(dir)?;
        let disabled = file_names(&dir.join("disable")).unwrap_or_default();
        let documented = std::fs::read_to_string(dir.join(DOCUMENTED_FILE)).ok();
        Some(Self {
            profile: from_installed(&names, &disabled, documented.as_deref()),
            seen: Seen::Installed,
        })
    }
}

fn file_names(dir: &Path) -> Option<Vec<String>> {
    let entries = std::fs::read_dir(dir).ok()?;
    Some(
        entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
    )
}

/// The profile for `/usr/bin/bwrap` in the kernel's list (`name (mode)` per
/// line). `bwrap` in mode `unconfined` is the documented one, even where an
/// `unpriv_bwrap` it replaced is still loaded.
pub fn from_loaded(list: &str) -> BwrapProfile {
    let mut bwrap = None;
    let mut unpriv = false;
    for line in list.lines() {
        let (name, mode) = line
            .trim()
            .rsplit_once(" (")
            .map_or((line.trim(), ""), |(n, m)| (n, m.trim_end_matches(')')));
        match name {
            "bwrap" => bwrap = Some(mode.to_owned()),
            "unpriv_bwrap" => unpriv = true,
            _ => {}
        }
    }
    match bwrap.as_deref() {
        None => BwrapProfile::None,
        Some("unconfined") => BwrapProfile::Unconfined,
        Some(_) if unpriv => BwrapProfile::UsernsRestrict,
        Some(_) => BwrapProfile::Other,
    }
}

/// The profile for `/usr/bin/bwrap` among the files in [`PROFILE_DIR`]
/// (`names`) less those its `disable/` folder names, with the text of the
/// documented profile's file where there is one. Ubuntu's file wins: with
/// both, which `bwrap` the kernel holds depends on load order, and the fix is
/// the same.
pub fn from_installed(
    names: &[String],
    disabled: &[String],
    documented: Option<&str>,
) -> BwrapProfile {
    let has = |name: &str| names.iter().any(|n| n == name) && !disabled.iter().any(|n| n == name);
    if has(USERNS_RESTRICT) {
        return BwrapProfile::UsernsRestrict;
    }
    match documented.filter(|_| has(DOCUMENTED_FILE)) {
        None => BwrapProfile::None,
        Some(text) if text.contains("flags=(unconfined)") && text.contains("userns") => {
            BwrapProfile::Unconfined
        }
        Some(_) => BwrapProfile::Other,
    }
}
