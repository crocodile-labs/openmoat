//! The protection score of a run (ADR-108): each kernel feature `openmoat run`
//! can use on the platform carries a weight, the weights of one platform add up
//! to 100, and the score is the sum of the weights of the features in force.
//! Every feature that is not in force is named with what would bring it, so
//! the number never stands alone.
//!
//! A score compares runs on one operating system, not operating systems: each
//! platform's 100 is everything OpenMoat's sandbox there can enforce. A
//! session without `openmoat run` and without a sandbox of the agent's own
//! scores 0 (the hook alone). `sandbox.strict: true` refuses a run whose score
//! is below 100 ([`ProtectionScore::complete`]).

use serde::{Deserialize, Serialize};

use super::{EffectiveBoundary, Mechanism, Restriction, Weaker};

/// The weights on Linux: files and the seccomp filter first, then the network
/// (port rule, namespace), the view of the machine, and the newer Landlock
/// steps that stand beside the seccomp filter.
pub const WEIGHTS_LINUX: [(Mechanism, u32); 9] = [
    (Mechanism::LandlockFilesystem, 25),
    (Mechanism::LandlockTcpPort, 10),
    (Mechanism::Seccomp, 15),
    (Mechanism::NoNewPrivs, 5),
    (Mechanism::LandlockScopes, 5),
    (Mechanism::LandlockResolveUnix, 5),
    (Mechanism::LandlockUdp, 5),
    (Mechanism::NetworkNamespace, 15),
    (Mechanism::IsolatedView, 15),
];

/// The weights on macOS: the Seatbelt profile holds files, the network (the
/// proxy's address alone) and the Mach services in one.
pub const WEIGHTS_MACOS: [(Mechanism, u32); 1] = [(Mechanism::Seatbelt, 100)];

/// The weights on Windows (ADR-115): the write-restricted token holds writes,
/// the job object the process tree. The network and reads carry weight too.
/// A run under the token has neither (a write-restricted token does not
/// restrict reads), so it scores at most 55; a run as the agent account
/// (ADR-129) holds writes by the account (which stands in for the token, see
/// [`stand_in`]) and reads by its deny entries, and scores at most 70 until
/// the network filter is built: the number says how much of a full boundary
/// is missing, not only what is there.
pub const WEIGHTS_WINDOWS: [(Mechanism, u32); 4] = [
    (Mechanism::RestrictedToken, 45),
    (Mechanism::JobObject, 10),
    (Mechanism::WfpNetwork, 30),
    (Mechanism::WindowsReadDeny, 15),
];

/// The weights of `os` (`std::env::consts::OS`); empty where `openmoat run`
/// has no sandbox.
#[must_use]
pub fn weights(os: &str) -> &'static [(Mechanism, u32)] {
    match os {
        "linux" => &WEIGHTS_LINUX,
        "macos" => &WEIGHTS_MACOS,
        "windows" => &WEIGHTS_WINDOWS,
        _ => &[],
    }
}

/// Whether OpenMoat's sandbox has `name` at all: the Windows network filter
/// is weighted but not built (ADR-129's second step), so it is named as such
/// rather than as something this system lacks.
fn built(name: Mechanism) -> bool {
    name != Mechanism::WfpNetwork && !super::vm::is_vm(name)
}

/// The mechanism that holds what `name` weighs for in a run that has it in
/// place of `name`: on Windows the agent account holds writes where the
/// write-restricted token would (ADR-129), so a run has one or the other.
fn stand_in(name: Mechanism) -> Option<Mechanism> {
    (name == Mechanism::RestrictedToken).then_some(Mechanism::AgentAccount)
}

/// A run's score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionScore {
    /// 0 to 100.
    pub points: u32,
    /// Every weighted feature of the platform, in the table's order.
    pub items: Vec<ScoreItem>,
}

/// One feature of the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreItem {
    /// Which.
    pub name: Mechanism,
    /// Its share of 100.
    pub weight: u32,
    /// Planned: it will apply. Once the agent started: it was confirmed.
    pub in_force: bool,
    /// Why it is not in force and what would bring it; `None` when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
}

impl ProtectionScore {
    /// Whether every feature of the platform is in force: what
    /// `sandbox.strict: true` requires. A platform without a sandbox is never
    /// complete.
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.items.is_empty() && self.items.iter().all(|i| i.in_force)
    }

    /// `name (why)` for each feature not in force, in the table's order.
    #[must_use]
    pub fn missing(&self) -> Vec<String> {
        self.items
            .iter()
            .filter_map(|i| Some(format!("{} ({})", i.name.id(), i.missing.as_ref()?)))
            .collect()
    }

    /// One line: `75/100`, then what is missing.
    #[must_use]
    pub fn line(&self) -> String {
        let missing = self.missing();
        if self.items.is_empty() {
            return "0/100: `openmoat run` has no sandbox on this system".to_owned();
        }
        if missing.is_empty() {
            return format!(
                "{}/100: every kernel feature it uses is in force",
                self.points
            );
        }
        format!("{}/100; missing: {}", self.points, missing.join("; "))
    }
}

/// What brings `name` where it is missing.
fn needs(name: Mechanism) -> &'static str {
    match name {
        Mechanism::LandlockFilesystem | Mechanism::LandlockTcpPort => {
            "needs Landlock ABI 4, Linux 6.7"
        }
        Mechanism::LandlockScopes => "needs Landlock ABI 6, Linux 6.12",
        Mechanism::LandlockResolveUnix => "needs Landlock ABI 9, Linux 7.1",
        Mechanism::LandlockUdp => {
            "needs Landlock ABI 10, Linux 7.2; the seccomp filter still refuses UDP sockets"
        }
        Mechanism::Seccomp => "needs seccomp",
        Mechanism::NoNewPrivs => "needs `no_new_privs`",
        Mechanism::NetworkNamespace => {
            "needs bubblewrap that can make a user namespace; `openmoat doctor` names the fix"
        }
        Mechanism::IsolatedView => "needs the Isolated tier: bubblewrap, `openmoat run --isolate`",
        Mechanism::Seatbelt => "needs `sandbox-exec`",
        Mechanism::RestrictedToken => "needs `CreateRestrictedToken` and `CreateProcessAsUserW`",
        Mechanism::JobObject => "needs a job object the agent can be put in",
        Mechanism::AgentAccount => {
            "needs `openmoat agent-account setup`, once, from an administrator terminal (ADR-129)"
        }
        Mechanism::WfpNetwork => {
            "a Windows Filtering Platform filter for the agent account, the next step of ADR-129; \
             until then the network goes through the proxy only for programs that honour \
             HTTP_PROXY and HTTPS_PROXY"
        }
        Mechanism::WindowsReadDeny => {
            "needs the agent account: `openmoat agent-account setup`, once, from an administrator \
             terminal (ADR-129); a write-restricted token does not restrict reads, so without it \
             the hook decides every read"
        }
        Mechanism::VmHypervisor
        | Mechanism::VmProjectOnly
        | Mechanism::VmProxyNetwork
        | Mechanism::VmGuardRelay
        | Mechanism::VmImagePinned => super::vm::needs(name),
    }
}

/// Whether the launch confirmed `r`. Seatbelt reports nothing back, but
/// `sandbox-exec` does not start the program when it cannot apply the profile,
/// so a started agent has it.
fn confirmed(r: &Restriction) -> bool {
    r.name == Mechanism::Seatbelt || r.applied == Some(true) || r.tested == Some(true)
}

/// The score of `record`.
pub(super) fn of(record: &EffectiveBoundary) -> ProtectionScore {
    let launched = record.launch.is_some();
    let failed = record.launch.as_ref().is_some_and(|l| l.failure.is_some());
    let tier_chosen_away = record
        .downgrades
        .iter()
        .any(|d| d.what == Weaker::Tier && d.chosen);
    let bubblewrap = |name| matches!(name, Mechanism::IsolatedView | Mechanism::NetworkNamespace);
    let items: Vec<ScoreItem> = weights(&record.os)
        .iter()
        .map(|&(weighed, weight)| {
            let found = record
                .restriction(weighed)
                .or_else(|| stand_in(weighed).and_then(|other| record.restriction(other)));
            let name = found.map_or(weighed, |r| r.name);
            let missing = match found {
                None => Some("not part of this run's sandbox".to_owned()),
                Some(_) if !built(name) => Some(format!(
                    "not in OpenMoat's Windows tier yet: {}",
                    needs(name)
                )),
                // `--no-isolate` gives the tier's namespace and view up on purpose.
                Some(r) if !r.available && tier_chosen_away && bubblewrap(name) => {
                    Some(format!("this run does not ask for it: {}", needs(name)))
                }
                Some(r) if !r.available => Some(format!("not on this system: {}", needs(name))),
                Some(r) if !r.configured => {
                    Some(format!("this run does not ask for it: {}", needs(name)))
                }
                Some(r) if r.applied == Some(false) || r.tested == Some(false) => {
                    Some("reported not in force after the start".to_owned())
                }
                Some(_) if failed => Some("the start failed".to_owned()),
                Some(r) if launched && !confirmed(r) => {
                    Some("not confirmed in force after the start".to_owned())
                }
                Some(_) => None,
            };
            ScoreItem {
                name,
                weight,
                in_force: missing.is_none(),
                missing,
            }
        })
        .collect();
    let points = items.iter().filter(|i| i.in_force).map(|i| i.weight).sum();
    ProtectionScore { points, items }
}
