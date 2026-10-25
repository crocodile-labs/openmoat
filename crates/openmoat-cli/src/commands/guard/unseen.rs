//! Whether the host would approve an `ask` without a person seeing it, from
//! what the hook's process can see ([`openmoat_hosts::Asks::unseen`]): Hermes
//! Agent in YOLO mode (`HERMES_YOLO_MODE`, which `--yolo` sets) or with
//! `approvals.mode: off`. A call there is [`HookEvent::PreToolUseNoAsk`], so
//! its `ask` reaches the host as a deny that says how to approve it.
//!
//! The settings are read from the hook file `moat init` set up and from the
//! one this hook's environment names (the profile the host runs it for); one
//! that cannot be read counts as approving unseen, so an ask is never let
//! through on a guess.

use anyhow::Result;
use openmoat_hosts::{HookEvent, HookRequest, Host, Unseen};
use serde_json::Value;

use crate::home::Home;
use crate::install::HostConfig;

/// Mark `request` as a call whose `ask` no person would see, where `host`
/// would approve it unseen.
pub(super) fn mark(host: Host, request: &mut HookRequest) {
    if request.event != HookEvent::PreToolUse {
        return;
    }
    let Some(unseen) = &host.spec().asks.unseen else {
        return;
    };
    let get = |name: &str| std::env::var(name).ok();
    if approves(unseen, &get, &configs(host)) {
        request.event = HookEvent::PreToolUseNoAsk;
    }
}

/// `host`'s hook files parsed: where `init` set it up, and where this
/// environment names it.
fn configs(host: Host) -> Vec<Result<Value>> {
    let Ok(home) = Home::locate() else {
        return vec![Err(anyhow::Error::msg("no OpenMoat home"))];
    };
    [
        HostConfig::for_host(&home, host),
        HostConfig::for_init(&home, host),
    ]
    .into_iter()
    .map(|config| config.and_then(|c| c.read()))
    .collect()
}

/// Whether `unseen` holds for the variables `get` reads and the hook files
/// `configs`; a file that could not be read holds it.
fn approves(
    unseen: &Unseen,
    get: &dyn Fn(&str) -> Option<String>,
    configs: &[Result<Value>],
) -> bool {
    unseen
        .env
        .iter()
        .any(|name| get(name).is_some_and(|value| Unseen::truthy(&value)))
        || configs.iter().any(|config| match config {
            Ok(doc) => (unseen.config)(doc).is_some(),
            Err(_) => true,
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn hermes_unseen() -> &'static Unseen {
        Host::ALL
            .into_iter()
            .find_map(|h| h.spec().asks.unseen.as_ref())
            .unwrap()
    }

    #[test]
    fn yolo_mode_an_off_mode_or_an_unreadable_file_approve_unseen() {
        let unseen = hermes_unseen();
        let manual = || vec![Ok(json!({ "approvals": { "mode": "manual" } }))];
        let none = |_: &str| None;
        assert!(!approves(unseen, &none, &manual()));
        let yolo = |name: &str| (name == "HERMES_YOLO_MODE").then(|| "True".to_owned());
        assert!(approves(unseen, &yolo, &manual()));
        let zero = |name: &str| (name == "HERMES_YOLO_MODE").then(|| "0".to_owned());
        assert!(!approves(unseen, &zero, &manual()));
        let off = vec![
            manual().remove(0),
            Ok(json!({ "approvals": { "mode": "off" } })),
        ];
        assert!(approves(unseen, &none, &off));
        assert!(approves(
            unseen,
            &none,
            &[Err(anyhow::Error::msg("broken"))]
        ));
    }
}
