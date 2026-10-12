//! The bundled `MoatBench` scenarios (`docs/MOATBENCH.md`, "Scenario format").

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::Verdict;
use serde::Deserialize;
use serde_json::Value;

/// The bundled scenarios, one file per category (`moatbench/<category>.yaml`).
pub const CATEGORIES: [(&str, &str); 9] = [
    ("benign", include_str!("../../../moatbench/benign.yaml")),
    (
        "destructive",
        include_str!("../../../moatbench/destructive.yaml"),
    ),
    (
        "exfiltration",
        include_str!("../../../moatbench/exfiltration.yaml"),
    ),
    ("mcp", include_str!("../../../moatbench/mcp.yaml")),
    (
        "obfuscation",
        include_str!("../../../moatbench/obfuscation.yaml"),
    ),
    (
        "persistence",
        include_str!("../../../moatbench/persistence.yaml"),
    ),
    (
        "self-protection",
        include_str!("../../../moatbench/self-protection.yaml"),
    ),
    (
        "supply-chain",
        include_str!("../../../moatbench/supply-chain.yaml"),
    ),
    (
        "workflows",
        include_str!("../../../moatbench/workflows.yaml"),
    ),
];

/// One scenario of `moatbench/<category>.yaml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    /// `T1`…`T12` from `docs/THREAT_MODEL.md` §3; benign scenarios name the
    /// threat whose rules they must not trip.
    threat: String,
    /// What the agent was steered into doing, and why the verdict is right.
    why: String,
    /// A tracked bypass or false positive of OpenMoat (`"#123"`): `expect` is the
    /// secure verdict, and a mismatch is reported as a known gap instead.
    #[serde(default)]
    pub gap: Option<String>,
    pub steps: Vec<Step>,
}

/// One tool call: exactly one of `shell`, `read`, `write`, `edit`, `fetch`, `mcp`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    shell: Option<String>,
    read: Option<String>,
    write: Option<String>,
    edit: Option<String>,
    fetch: Option<String>,
    mcp: Option<Mcp>,
    pub expect: Verdict,
    /// A rule id that must be in OpenMoat's decision.
    #[serde(default)]
    pub rule: Option<String>,
    /// The scenario-level `gap` for one step, so the other steps still count.
    #[serde(default)]
    pub gap: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mcp {
    server: String,
    tool: String,
    #[serde(default)]
    args: Value,
}

/// A tool call, independent of the host that makes it.
pub enum Call {
    Shell(String),
    Read(String),
    Write(String),
    Edit(String),
    Fetch(String),
    Mcp {
        server: String,
        tool: String,
        args: Value,
    },
}

impl Step {
    pub fn call(&self) -> Result<Call> {
        let mut calls = [
            self.shell.clone().map(Call::Shell),
            self.read.clone().map(Call::Read),
            self.write.clone().map(Call::Write),
            self.edit.clone().map(Call::Edit),
            self.fetch.clone().map(Call::Fetch),
            self.mcp.as_ref().map(|m| Call::Mcp {
                server: m.server.clone(),
                tool: m.tool.clone(),
                args: m.args.clone(),
            }),
        ]
        .into_iter()
        .flatten();
        match (calls.next(), calls.next()) {
            (Some(call), None) => Ok(call),
            _ => bail!("a step names exactly one tool call"),
        }
    }
}

/// Every bundled scenario with its category, checked.
pub fn scenarios() -> Result<Vec<(&'static str, Scenario)>> {
    let mut ids = BTreeSet::new();
    let mut all = Vec::new();
    for (category, text) in CATEGORIES {
        let list: Vec<Scenario> = openmoat_core::yaml::from_str(text)
            .with_context(|| format!("moatbench/{category}.yaml"))?;
        for s in list {
            let threat = s
                .threat
                .strip_prefix('T')
                .and_then(|n| n.parse::<u8>().ok());
            ensure!(ids.insert(s.id.clone()), "duplicate scenario id {}", s.id);
            ensure!(
                threat.is_some_and(|n| (1..=12).contains(&n)),
                "{}: threat must be T1…T12",
                s.id
            );
            ensure!(
                !s.why.trim().is_empty() && !s.steps.is_empty(),
                "{}: why and steps",
                s.id
            );
            ensure!(
                s.gap.is_none() || s.steps.iter().all(|step| step.gap.is_none()),
                "{}: a gap on the scenario or on its steps, not both",
                s.id
            );
            for step in &s.steps {
                step.call().with_context(|| s.id.clone())?;
            }
            all.push((category, s));
        }
    }
    Ok(all)
}
