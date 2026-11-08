//! A layer's status in the proof report, and how the evidence of several runs
//! folds into it. A layer is PASS only when every piece of evidence for it was
//! exercised here and held: anything that did not run makes it NOT TESTED HERE,
//! never PASS, and any evidence that broke makes it FAIL.

use serde::Serialize;

/// Where a promise is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// The engine's decision on the call, read back from the audit log.
    Policy,
    /// The host's payload shape and its reading of the hook's reply.
    Hook,
    /// The OS sandbox `openmoat run` generates from the policy, running the attack.
    OsSandbox,
    /// The egress proxy's decision on a request.
    Network,
}

impl Layer {
    /// The column the text and Markdown reports show.
    pub fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy decision",
            Self::Hook => "host hook",
            Self::OsSandbox => "OS sandbox",
            Self::Network => "network boundary",
        }
    }
}

/// One piece of evidence for a layer: a scenario on one host, or one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// It ran here and the layer held.
    Held,
    /// It ran here and the layer did not hold; why.
    Broken(String),
    /// It could not run here; why. Never counts as held.
    Unexercised(String),
}

/// What the report says of one layer of one promise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "reason", rename_all = "kebab-case")]
pub enum Status {
    /// Exercised here, and every run held.
    Pass,
    /// Exercised here, and a run did not hold.
    Fail(String),
    /// Not exercised here, and why. CI and people must not read it as a pass.
    #[serde(rename = "not-tested-here")]
    NotTested(String),
}

impl Status {
    /// The word the text and Markdown reports show.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail(_) => "FAIL",
            Self::NotTested(_) => "NOT TESTED HERE",
        }
    }

    /// Why, for a status that is not a pass.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Pass => None,
            Self::Fail(why) | Self::NotTested(why) => Some(why),
        }
    }

    /// Fold `evidence` into one status: FAIL when any broke, else NOT TESTED
    /// HERE when any did not run, else PASS when at least one held. No evidence
    /// at all is NOT TESTED HERE with `none` as the reason.
    pub fn of(evidence: impl IntoIterator<Item = Evidence>, none: &str) -> Self {
        let (mut held, mut broken, mut missing) = (0usize, Vec::new(), Vec::new());
        for item in evidence {
            match item {
                Evidence::Held => held += 1,
                Evidence::Broken(why) => push_unique(&mut broken, why),
                Evidence::Unexercised(why) => push_unique(&mut missing, why),
            }
        }
        if !broken.is_empty() {
            Self::Fail(broken.join("; "))
        } else if !missing.is_empty() {
            Self::NotTested(missing.join("; "))
        } else if held == 0 {
            Self::NotTested(none.to_owned())
        } else {
            Self::Pass
        }
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}
