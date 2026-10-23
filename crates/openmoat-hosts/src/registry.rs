//! Which [`HostSpec`] describes each supported host, and which
//! [`HostAdapter`] reads its format: all of it comes from the one list of
//! hosts in `host.rs`, which this module's [`hosts!`] macro expands.

use crate::Host;
#[cfg(doc)]
use crate::contract::{HostAdapter, HostSpec};
use crate::host::LISTED;
pub(crate) use crate::host::{adapter, spec};

/// Expands the host list in `host.rs`. Each line is
/// `Variant => module` or `Variant => module speaks Other`, with the
/// variant's doc comment above it, and gives:
///
/// - `pub(crate) mod module;` (the file `host/<module>.rs`);
/// - the [`Host`] variant;
/// - `spec(Host::Variant)`, which is `&module::SPEC`;
/// - `adapter(Host::Variant)`, which is `&module::ADAPTER`, or for a host that
///   `speaks` another's format, that host's adapter.
///
/// [`Host::EVERY`] and [`Host::ALL`] are built from the list below.
macro_rules! hosts {
    ($(
        $(#[doc = $doc:literal])*
        $variant:ident => $module:ident $(speaks $wire:ident)?,
    )*) => {
        $(pub(crate) mod $module;)*

        /// Agents with a supported integration.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Host {
            $($(#[doc = $doc])* $variant,)*
        }

        /// Every host, in the order of the list.
        pub(crate) const LISTED: &[Host] = &[$(Host::$variant),*];

        /// The facts about `host`, from its module under `host/`.
        pub(crate) const fn spec(host: Host) -> &'static $crate::HostSpec {
            match host {
                $(Host::$variant => &$module::SPEC,)*
            }
        }

        impl Host {
            /// The host's module under `openmoat-hosts/src/host/`, whose
            /// folder holds its fixtures (`host/<module>/fixtures/`).
            #[must_use]
            pub const fn module(self) -> &'static str {
                match self {
                    $(Host::$variant => stringify!($module),)*
                }
            }
        }

        /// The adapter for the format `host` sends: its own, or the one of
        /// the host it speaks.
        pub(crate) fn adapter(host: Host) -> &'static dyn $crate::contract::HostAdapter {
            match host {
                $(Host::$variant => $crate::registry::adapter_of!($module $(speaks $wire)?),)*
            }
        }
    };
}

/// One arm of `adapter`: the module's own adapter, or the adapter of the host
/// whose format it speaks.
macro_rules! adapter_of {
    ($module:ident) => {
        &$module::ADAPTER
    };
    ($module:ident speaks $wire:ident) => {
        adapter(Host::$wire)
    };
}

pub(crate) use {adapter_of, hosts};

/// How many listed hosts have a hook to install ([`HostSpec::install`]).
const INSTALLABLE: usize = count(true);

impl Host {
    /// Every host with a hook to install, in the order commands list them.
    pub const ALL: [Host; INSTALLABLE] = pick(true);

    /// Every host OpenMoat knows: [`Host::ALL`] and the hosts that only speak
    /// another's format ([`HostSpec::speaks`]). Tests that must cover every
    /// host iterate this, so a new host is checked without editing them.
    pub const EVERY: [Host; LISTED.len()] = pick(false);
}

/// Whether `host` is kept: every host, or only one with a hook to install.
const fn kept(host: Host, installable_only: bool) -> bool {
    !installable_only || spec(host).install.is_some()
}

/// How many listed hosts are kept.
const fn count(installable_only: bool) -> usize {
    let (mut at, mut kept_hosts) = (0, 0);
    while at < LISTED.len() {
        if kept(LISTED[at], installable_only) {
            kept_hosts += 1;
        }
        at += 1;
    }
    kept_hosts
}

/// The kept hosts, in the order of the list. `N` is [`count`] of the same
/// filter, so every slot is filled; evaluated only in the constants above, a
/// mismatch fails to compile.
const fn pick<const N: usize>(installable_only: bool) -> [Host; N] {
    let mut picked = [LISTED[0]; N];
    let (mut at, mut filled) = (0, 0);
    while at < LISTED.len() {
        if kept(LISTED[at], installable_only) {
            picked[filled] = LISTED[at];
            filled += 1;
        }
        at += 1;
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::{adapter, spec};
    use crate::Host;

    /// A host spec takes [`HostSpec::BASE`](crate::HostSpec::BASE) only for
    /// optional fields: every host names its own required ones.
    #[test]
    fn every_host_names_its_required_spec_fields() {
        for host in Host::EVERY {
            let spec = spec(host);
            for (field, value) in [
                ("id", spec.id),
                ("display_name", spec.display_name),
                ("on_hook_failure", spec.on_hook_failure),
                ("gaps", spec.gaps),
            ] {
                assert!(!value.is_empty(), "{host:?} names no {field}");
            }
            if let Some(install) = &spec.install {
                for (field, value) in [
                    ("dir_variable", install.dir_variable),
                    ("dir_name", install.dir_name),
                    ("config_file", install.config_file),
                ] {
                    assert!(!value.is_empty(), "{host:?} install names no {field}");
                }
                assert!(!install.hooks.is_empty(), "{host:?} installs no hook");
            }
        }
    }

    /// `Host::EVERY` is `Host::ALL` and the hosts that speak another's format.
    #[test]
    fn every_is_all_and_the_hosts_that_speak_another_format() {
        for host in Host::ALL {
            assert!(Host::EVERY.contains(&host), "{host:?}");
        }
        for host in Host::EVERY {
            let installs = Host::ALL.contains(&host);
            assert_eq!(installs, spec(host).speaks.is_none(), "{host:?}");
        }
    }

    /// A host's adapter is its own, or the one of the host it speaks; the
    /// list's `speaks` and the spec's agree.
    #[test]
    fn each_host_reads_the_format_its_spec_names() {
        for host in Host::EVERY {
            let format = spec(host).speaks.unwrap_or(host);
            assert_eq!(adapter(host).spec().id, format.id(), "{host:?}");
            assert!(std::ptr::eq(adapter(host).spec(), spec(format)), "{host:?}");
        }
    }

    /// The lists keep the order of the host list, and `ALL` keeps every host
    /// with an install, so commands list the hosts as before.
    #[test]
    fn the_lists_keep_the_order_of_the_host_list() {
        let ids = |hosts: &[Host]| hosts.iter().map(|h| h.id()).collect::<Vec<_>>();
        assert_eq!(
            ids(&Host::EVERY),
            [
                "claude-code",
                "codex",
                "cursor",
                "continue",
                "openclaw",
                "copilot-cli",
                "pi",
                "gemini-cli"
            ]
        );
        let installs: Vec<Host> = Host::EVERY
            .into_iter()
            .filter(|h| h.spec().install.is_some())
            .collect();
        assert_eq!(Host::ALL.to_vec(), installs);
    }
}
