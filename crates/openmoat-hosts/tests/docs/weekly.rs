//! What the weekly `latest agents` job proves for each agent, from its records
//! (`scripts/ci/latest-agents/agents.json`): the claims a passing run asserts
//! against the real agent (`proves`), on which runners, and the golden payload
//! fixture it sends `openmoat guard`. `check.py records` (in the quality gate)
//! checks the same fields from the job's side.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::cfg::Os;
use crate::marks::Claim;

/// The file the records are in, from the repository root.
pub const RECORDS: &str = "scripts/ci/latest-agents/agents.json";

/// One agent record of the weekly job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's key (`opencode-1`): one host can have several.
    pub agent: String,
    /// The host id it runs.
    pub host: String,
    /// The OSes of its runners.
    pub oses: Vec<Os>,
    /// What a passing run asserts against the real agent.
    pub proves: Vec<Claim>,
    /// Why it proves less than the hook, when it does.
    pub why: Option<String>,
    /// The golden payload fixture, under `crates/openmoat-hosts/src/host/`.
    pub fixture: Option<String>,
}

/// The records of `text`, or why they cannot be read.
pub fn parse(text: &str) -> Result<Vec<Record>, String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("{RECORDS}: {e}"))?;
    let Some(entries) = doc.as_object() else {
        return Err(format!("{RECORDS}: not an object"));
    };
    let mut out = Vec::new();
    for (agent, entry) in entries.iter().filter(|(k, _)| !k.starts_with('_')) {
        let field = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_owned);
        let host = field("host").ok_or(format!("{RECORDS}: {agent}: no `host`"))?;
        let list = |key: &str| -> Result<Vec<String>, String> {
            entry
                .get(key)
                .and_then(Value::as_array)
                .ok_or(format!("{RECORDS}: {agent}: no `{key}` list"))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(format!("{RECORDS}: {agent}: `{key}` holds a non-string"))
                })
                .collect()
        };
        let oses = list("runners")?
            .iter()
            .map(|r| Os::of_runner(r).ok_or(format!("{RECORDS}: {agent}: unknown runner `{r}`")))
            .collect::<Result<Vec<_>, _>>()?;
        let proves = list("proves")?
            .iter()
            .map(|c| match Claim::of(c) {
                Some(claim @ (Claim::Hook | Claim::HookFailure | Claim::Mcp)) => Ok(claim),
                _ => Err(format!("{RECORDS}: {agent}: `proves` names `{c}`")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let why = field("why");
        if !proves.contains(&Claim::Hook) && why.is_none() {
            return Err(format!(
                "{RECORDS}: {agent}: proves no hook call and gives no `why`"
            ));
        }
        out.push(Record {
            agent: agent.clone(),
            host,
            oses,
            proves,
            why,
            fixture: entry
                .pointer("/payload/fixture")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(out)
}

/// The records in the repository at `root`.
pub fn records(root: &Path) -> Result<Vec<Record>, String> {
    let text = fs::read_to_string(root.join(RECORDS)).map_err(|e| format!("{RECORDS}: {e}"))?;
    parse(&text)
}

#[test]
fn a_record_names_its_claims_runners_and_fixture() {
    let text = r#"{"_comment": "x",
        "a-1": {"host": "a", "runners": ["ubuntu-latest", "macos-15"],
                "proves": ["hook", "hook-failure"], "payload": {"fixture": "a/fixtures/b.json"}},
        "a-2": {"host": "a", "runners": ["ubuntu-latest"], "proves": [], "why": "no model call"}}"#;
    let got = parse(text).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].oses, [Os::Linux, Os::Mac]);
    assert_eq!(got[0].proves, [Claim::Hook, Claim::HookFailure]);
    assert_eq!(got[0].fixture.as_deref(), Some("a/fixtures/b.json"));
    assert_eq!(got[1].why.as_deref(), Some("no model call"));
}

#[test]
fn a_record_that_claims_what_the_job_cannot_check_is_refused() {
    for text in [
        r#"{"a": {"host": "a", "runners": ["ubuntu-latest"], "proves": ["sandbox"]}}"#,
        r#"{"a": {"host": "a", "runners": ["ubuntu-latest"], "proves": []}}"#,
        r#"{"a": {"host": "a", "runners": ["plan9"], "proves": ["hook"]}}"#,
        r#"{"a": {"host": "a", "runners": ["ubuntu-latest"]}}"#,
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}
