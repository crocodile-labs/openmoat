//! The evidence itself: the window's events counted per rule group, per
//! control and per unmapped rule, with sample rows. Pure: everything it reads
//! is passed in, so the tests build it from a fixture log.

use std::collections::{BTreeMap, BTreeSet};

use openmoat_audit::{ChainReport, Event, EventId};
use openmoat_core::Verdict;
use serde::Serialize;

use crate::compliance::{self, Control, Framework, Group};
use crate::render;

/// What the report says about itself, in both formats.
pub const STATEMENT: &str = "Evidence, not a certification. This report lists what OpenMoat \
     recorded about an agent's tool calls on this machine and which framework controls those \
     records relate to. It does not show that any control is met, and using OpenMoat does not \
     make anyone compliant.";

/// The verdicts every count lists, least strict first.
pub const VERDICTS: [Verdict; 4] = [
    Verdict::Allow,
    Verdict::Defer,
    Verdict::Review,
    Verdict::Deny,
];

/// Decisions, and decisions by verdict (keyed by the verdict's own name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub decisions: u64,
    pub verdicts: BTreeMap<Verdict, u64>,
}

impl Default for Counts {
    fn default() -> Self {
        Self {
            decisions: 0,
            verdicts: VERDICTS.into_iter().map(|v| (v, 0)).collect(),
        }
    }
}

impl Counts {
    fn add(&mut self, verdict: Verdict) {
        self.decisions += 1;
        *self.verdicts.entry(verdict).or_default() += 1;
    }

    pub fn of(&self, verdict: Verdict) -> u64 {
        self.verdicts.get(&verdict).copied().unwrap_or(0)
    }
}

/// Whether a mapped rule id can fire under the policy in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleStatus {
    /// A rule of the default policy that the policy in force also has.
    InPolicy,
    /// A rule of the default policy that the policy in force lacks: it cannot fire.
    NotInPolicy,
    /// A rule the code adds itself (`docs/POLICY.md` §5.1).
    BuiltIn,
    /// The policy in force could not be read, so this is not known.
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct RuleEvidence {
    pub rule: String,
    pub status: RuleStatus,
    #[serde(flatten)]
    pub counts: Counts,
}

#[derive(Debug, Serialize)]
pub struct UnmappedRule {
    pub rule: String,
    #[serde(flatten)]
    pub counts: Counts,
}

/// One recorded event, as stored: redacted before it was written.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub id: EventId,
    pub time: String,
    pub host: String,
    pub session_id: String,
    pub tool: String,
    pub verdict: Verdict,
    pub rules: Vec<String>,
    pub action: String,
    pub reasons: Vec<String>,
    pub hash: Option<String>,
}

impl Sample {
    fn of(event: &Event) -> Self {
        Self {
            id: event.id,
            time: crate::time::rfc3339(event.ts_ms),
            host: event.host.clone(),
            session_id: event.session_id.clone(),
            tool: event.tool.clone(),
            verdict: event.verdict,
            rules: event.rules.clone(),
            action: render::describe(event),
            reasons: event.reasons.clone(),
            hash: event.hash.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GroupEvidence {
    pub id: &'static str,
    pub title: &'static str,
    pub does: &'static str,
    pub controls: Vec<&'static str>,
    /// Events in which a rule of the group fired, each counted once.
    pub counts: Counts,
    pub rules: Vec<RuleEvidence>,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Serialize)]
pub struct ControlEvidence {
    pub framework: Framework,
    pub framework_name: &'static str,
    pub id: &'static str,
    pub title: &'static str,
    pub groups: Vec<&'static str>,
    /// Events in which a rule of one of the groups fired, each counted once.
    pub counts: Counts,
    pub samples: Vec<Sample>,
}

/// The audit log's state: the whole chain, and where the window sits in it.
#[derive(Debug, Serialize)]
pub struct Log {
    pub chain: ChainReport,
    pub first_id: Option<EventId>,
    pub last_id: Option<EventId>,
    /// The chain hash of the window's newest event: `openmoat audit verify
    /// --anchor` finds it in an export that covers the window.
    pub last_hash: Option<String>,
}

/// What the evidence is built from, besides the events.
pub struct Inputs<'a> {
    pub chain: ChainReport,
    /// The rule ids of the policy in force, `None` when it cannot be read.
    pub in_force: Option<&'a BTreeSet<String>>,
    /// The `deny` and `review` rule ids of the shipped default policy.
    pub default_ids: &'a BTreeSet<String>,
    pub samples: usize,
}

pub struct Built {
    pub totals: Counts,
    pub log: Log,
    pub controls: Vec<ControlEvidence>,
    pub groups: Vec<GroupEvidence>,
    pub unmapped_rules: Vec<UnmappedRule>,
}

/// Count `events` (oldest first) against the map.
pub fn build(events: &[Event], inputs: Inputs<'_>) -> Built {
    let mut totals = Counts::default();
    let mut rule_counts: BTreeMap<&str, Counts> = BTreeMap::new();
    for event in events {
        totals.add(event.verdict);
        // A rule named twice in one decision is counted once.
        let rules: BTreeSet<&str> = event.rules.iter().map(String::as_str).collect();
        for rule in rules {
            rule_counts.entry(rule).or_default().add(event.verdict);
        }
    }
    let groups: Vec<GroupEvidence> = compliance::GROUPS
        .iter()
        .map(|group| group_evidence(group, events, &rule_counts, &inputs))
        .collect();
    let controls = compliance::CONTROLS
        .iter()
        .map(|control| control_evidence(control, events, inputs.samples))
        .collect();
    let mut unmapped_rules: Vec<UnmappedRule> = rule_counts
        .iter()
        .filter(|(rule, _)| compliance::group_of(rule).is_none())
        .map(|(rule, counts)| UnmappedRule {
            rule: (*rule).to_owned(),
            counts: counts.clone(),
        })
        .collect();
    unmapped_rules.sort_by_key(|r| std::cmp::Reverse(r.counts.decisions));
    let log = Log {
        chain: inputs.chain,
        first_id: events.first().map(|e| e.id),
        last_id: events.last().map(|e| e.id),
        last_hash: events.last().and_then(|e| e.hash.clone()),
    };
    Built {
        totals,
        log,
        controls,
        groups,
        unmapped_rules,
    }
}

fn group_evidence(
    group: &'static Group,
    events: &[Event],
    rule_counts: &BTreeMap<&str, Counts>,
    inputs: &Inputs<'_>,
) -> GroupEvidence {
    let matching: Vec<&Event> = events.iter().filter(|e| group.matches(&e.rules)).collect();
    let rules = group
        .rule_ids()
        .iter()
        .map(|rule| RuleEvidence {
            rule: (*rule).to_owned(),
            status: status(rule, inputs),
            counts: rule_counts.get(rule).cloned().unwrap_or_default(),
        })
        .collect();
    GroupEvidence {
        id: group.id,
        title: group.title,
        does: group.does,
        controls: group.controls.iter().map(|c| c.id).collect(),
        counts: counted(&matching),
        rules,
        samples: samples(&matching, inputs.samples),
    }
}

fn control_evidence(control: &'static Control, events: &[Event], n: usize) -> ControlEvidence {
    let groups: Vec<&'static Group> = compliance::groups_for(control).collect();
    let matching: Vec<&Event> = events
        .iter()
        .filter(|e| groups.iter().any(|g| g.matches(&e.rules)))
        .collect();
    ControlEvidence {
        framework: control.framework,
        framework_name: control.framework.name(),
        id: control.id,
        title: control.title,
        groups: groups.iter().map(|g| g.id).collect(),
        counts: counted(&matching),
        samples: samples(&matching, n),
    }
}

fn status(rule: &str, inputs: &Inputs<'_>) -> RuleStatus {
    if !inputs.default_ids.contains(rule) {
        return RuleStatus::BuiltIn;
    }
    match inputs.in_force {
        Some(ids) if ids.contains(rule) => RuleStatus::InPolicy,
        Some(_) => RuleStatus::NotInPolicy,
        None => RuleStatus::Unknown,
    }
}

fn counted(events: &[&Event]) -> Counts {
    let mut counts = Counts::default();
    for event in events {
        counts.add(event.verdict);
    }
    counts
}

/// Up to `n` events, newest first, denies and reviews before the rest: they show
/// a control stopping something, an allow only that the call was recorded.
fn samples(events: &[&Event], n: usize) -> Vec<Sample> {
    let mut picked: Vec<&Event> = events.to_vec();
    picked.sort_by_key(|e| {
        let restrictive = !matches!(e.verdict, Verdict::Allow | Verdict::Defer);
        std::cmp::Reverse((restrictive, e.ts_ms, e.id.0))
    });
    picked.into_iter().take(n).map(Sample::of).collect()
}
