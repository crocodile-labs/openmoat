//! `openmoat inventory --deliver` (ADR-119): the inventory's OCSF events to
//! each sink of the accepted delivery configuration (ADR-081) that says
//! `inventory: true`, in the sink's format, masked as audit events are: the
//! policy's brokered secrets and the sink's own key and header values.
//! Nothing is sent without such a sink: the inventory leaves the machine only
//! where a person configured it to.

use std::io::Write as _;

use anyhow::{Context as _, Result};
use openmoat_audit::KnownSecrets;
use openmoat_audit::delivery::Origin;
use serde_json::Value;

use crate::delivery::{Ready, Sent};
use crate::exit::Code;
use crate::home::Home;
use crate::render::Deferred;

/// Send `events` (redacted already); exit 64 when a sink did not accept them.
pub fn run(home: &Home, events: &[Value], now_ms: i64) -> Result<Code> {
    let (config, _) = crate::delivery::load_pinned(home)?.with_context(|| {
        format!(
            "no delivery is configured ({}): nothing is sent",
            home.delivery_config_path().display()
        )
    })?;
    let sinks: Vec<_> = config.sinks.iter().filter(|s| s.inventory).collect();
    anyhow::ensure!(
        !sinks.is_empty(),
        "no sink of {} says `inventory: true`: nothing is sent",
        home.delivery_config_path().display()
    );
    let user_home = crate::home::user_home()?.to_string_lossy().into_owned();
    // Fail closed: without the policy's secrets the events cannot be masked.
    let policy = home.load_policy()?;
    let policy_values = crate::secrets::known_values(&policy.secrets, &user_home);
    let origin = Origin {
        machine: &config.machine,
        version: env!("CARGO_PKG_VERSION"),
    };
    let mut out = Deferred::default();
    let mut all = true;
    for sink in sinks {
        let ready = Ready::new(sink, &user_home)?;
        let known = KnownSecrets::new(
            policy_values
                .iter()
                .map(|v| v.as_str())
                .chain(ready.values()),
        )?;
        let masked = mask(&known, events);
        let line = match ready.send_inventory(sink, origin, &masked, now_ms)? {
            Sent::Accepted | Sent::Partial(_) => format!("✔ {}: inventory accepted", sink.id),
            Sent::TooLarge => {
                all = false;
                format!("✖ {}: the sink refused it as too large", sink.id)
            }
            Sent::Retry { why, .. } | Sent::Refused { why } => {
                all = false;
                format!("✖ {}: {why}", sink.id)
            }
        };
        writeln!(out, "{line}")?;
    }
    out.finish()?;
    Ok(if all { Code::Ok } else { Code::Usage })
}

/// `events` with every text `known` masks, masked.
pub fn mask(known: &KnownSecrets, events: &[Value]) -> Vec<Value> {
    events
        .iter()
        .map(|e| known.redact_value(e.clone()))
        .collect()
}
