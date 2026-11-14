//! What the weekly `latest agents` job proves for each agent, from its records
//! (`scripts/ci/latest-agents/agents.json`): the claims a passing run asserts
//! against the real agent (`proves`), on which runners, and the golden payload
//! fixture it sends `openmoat guard`. `check.py records` (in the quality gate)
//! checks the same fields from the job's side.
//!
//! The records are written from each host's [`HostSpec::weekly`]
//! ([`generated`]); every host of [`Host::EVERY`] has one or its spec says why
//! not, and each record has its own script for the steps no fact can say,
//! `scripts/ci/latest-agents/hosts/<agent>.sh`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use openmoat_hosts::{
    ConfigFormat, Host, HostSpec, Location, Proves, WeeklyInstall, WeeklyRun, WeeklyRuns,
};
use serde_json::{Value, json};

use crate::cfg::Os;
use crate::marks::Claim;

/// The file the records are in, from the repository root.
pub const RECORDS: &str = "scripts/ci/latest-agents/agents.json";

/// The directory of the records' own scripts, from the repository root.
const SCRIPTS: &str = "scripts/ci/latest-agents/hosts";

/// The library that keeps the job in its throwaway home.
const THROWAWAY: &str = "scripts/ci/lib/throwaway.sh";

const COMMENT: &str = "Generated from each host's spec (`weekly`, crates/openmoat-hosts/src/host/\
    <module>/weekly.rs) by `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs`; \
    do not edit. The agents the weekly latest-agent check installs (scripts/ci/latest-agents.sh), \
    each run by the steps of its script (script). _env is what the job sets for every agent so \
    none finds state outside the throwaway home ({HOME}, {ROOT} its root). binary is relative \
    to the install directory ({platform} is node's process.platform-process.arch); for Claude \
    Code and OpenCode the npm bin is a stub that only the postinstall replaces, so the platform \
    package's own binary is used. dir is the directory the agent's first start makes. \
    checked.version is the release the adapter was last checked against, and checked.source \
    the file that says so; `check.py records` (in the quality gate) fails when that file no \
    longer names the version. payload is the host's golden shell payload, with the JSON \
    pointers of its command and of the verdict in the hook's reply. proves lists what a \
    passing run asserts against the real agent (hook: a call decided by OpenMoat's hook and \
    held; hook-failure: the hook-failure step's comparison; mcp: an MCP call decided by the \
    hook), which docs/PROTECTION.md shows as evidence per runner; why says why a record \
    proves no hook call; values are what a record's script reads.";

/// Each host's weekly records, in [`Host::EVERY`] order.
fn runs() -> Vec<(&'static HostSpec, &'static WeeklyRun)> {
    let mut out = Vec::new();
    for host in Host::EVERY {
        let spec = host.spec();
        if let WeeklyRuns::Runs(runs) = spec.weekly.runs {
            out.extend(runs.iter().map(|run| (spec, run)));
        }
    }
    out
}

/// The host's directory as `{VARIABLE}`, for a host whose location is one
/// directory: what the job expands in its environment.
fn one_dir(spec: &HostSpec) -> Option<String> {
    let install = spec.install.as_ref()?;
    if !matches!(install.location, Location::OneDir) {
        return None;
    }
    let variable = install.dir_variable;
    Some(if install.dir_variable_is_home {
        format!("{{{variable}}}/{}", install.dir_name)
    } else {
        format!("{{{variable}}}")
    })
}

/// What the job exports for every agent: each one-directory host's variable,
/// then what each spec adds.
fn env() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for host in Host::EVERY {
        let spec = host.spec();
        if let (Some(install), Some(_)) = (&spec.install, one_dir(spec))
            && install.dir_variable != "HOME"
        {
            let value = if install.dir_variable_is_home {
                "{HOME}".to_owned()
            } else {
                format!("{{HOME}}/{}", install.dir_name)
            };
            out.push((install.dir_variable.to_owned(), value));
        }
        for (name, value) in spec.weekly.env {
            out.push(((*name).to_owned(), (*value).to_owned()));
        }
    }
    out
}

/// One record as `agents.json` holds it, its fields in a fixed order.
fn record(spec: &HostSpec, run: &WeeklyRun) -> Vec<(&'static str, Value)> {
    let mut fields = vec![
        ("host", json!(spec.id)),
        ("name", json!(spec.display_name)),
        ("script", json!(format!("{SCRIPTS}/{}.sh", run.agent))),
        ("install", json!(run.install.kind())),
    ];
    match run.install {
        WeeklyInstall::Npm { package, binary } => {
            fields.push(("package", json!(package)));
            fields.push(("binary", json!(binary)));
        }
        WeeklyInstall::NpmPack { package } => fields.push(("package", json!(package))),
        WeeklyInstall::Script { binary, .. } => fields.push(("binary", json!(binary))),
    }
    let mut checked = json!({"version": run.checked.version, "source": run.checked.source});
    if let Some(note) = run.checked.note {
        checked["note"] = json!(note);
    }
    fields.push(("checked", checked));
    if let Some(dir) = run.dir.map(str::to_owned).or_else(|| one_dir(spec)) {
        fields.push(("dir", json!(dir)));
    }
    if !run.config.is_empty() {
        let config: Vec<Value> = run
            .config
            .iter()
            .map(|(path, format)| json!([path, format.name()]))
            .collect();
        fields.push(("config", Value::Array(config)));
    }
    if let Some(payload) = &run.payload {
        let mut doc = json!({
            "fixture": payload.fixture, "command": payload.command, "verdict": payload.verdict,
        });
        if payload.allow_is_silent {
            doc["allow_is_silent"] = json!(true);
        }
        fields.push(("payload", doc));
    }
    let proves: Vec<&str> = run.proves.iter().map(|p| p.name()).collect();
    fields.push(("proves", json!(proves)));
    if let Some(why) = run.why {
        fields.push(("why", json!(why)));
    }
    let runners: Vec<&str> = run.runners.iter().map(|r| r.label()).collect();
    fields.push(("runners", json!(runners)));
    if !run.values.is_empty() {
        let values: serde_json::Map<String, Value> = run
            .values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), json!(value)))
            .collect();
        fields.push(("values", Value::Object(values)));
    }
    fields
}

/// `agents.json` as the specs say it: one line per field, the records in
/// [`Host::EVERY`] order, so the job's matrix keeps that order.
pub fn generated() -> String {
    let compact = |value: &Value| serde_json::to_string(value).unwrap();
    let env: Vec<Value> = env().iter().map(|(n, v)| json!([n, v])).collect();
    let mut entries = vec![
        format!("  \"_comment\": {}", compact(&json!(COMMENT))),
        format!("  \"_env\": {}", compact(&Value::Array(env))),
    ];
    for (spec, run) in runs() {
        let fields: Vec<String> = record(spec, run)
            .iter()
            .map(|(key, value)| format!("    \"{key}\": {}", compact(value)))
            .collect();
        entries.push(format!(
            "  {}: {{\n{}\n  }}",
            compact(&json!(run.agent)),
            fields.join(",\n")
        ));
    }
    format!("{{\n{}\n}}\n", entries.join(",\n"))
}

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

/// `agents.json` is what the specs say; `OPENMOAT_TEST_UPDATE_DOCS=1`
/// rewrites it.
#[test]
fn the_weekly_records_are_written_from_the_specs() {
    let path = crate::repo_root().join(RECORDS);
    let want = generated();
    let current = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    if std::env::var_os(crate::UPDATE).is_some() && want != current {
        fs::write(&path, &want).unwrap();
        return;
    }
    assert!(
        want == current,
        "{RECORDS} differs from the host specs; run \
         `{}=1 cargo test -p openmoat-hosts --test docs`",
        crate::UPDATE
    );
    // What the specs write reads back as the records the docs are built from.
    let parsed = parse(&want).unwrap();
    assert_eq!(parsed.len(), runs().len());
}

/// Every host the registry knows is run by the weekly job, or its spec says
/// why not; no two records share a name.
#[test]
fn every_host_is_run_weekly_or_says_why_not() {
    let records = parse(&generated()).unwrap();
    let hosts: BTreeSet<&str> = records.iter().map(|r| r.host.as_str()).collect();
    for host in Host::EVERY {
        let spec = host.spec();
        match spec.weekly.runs {
            WeeklyRuns::Runs(_) => assert!(hosts.contains(spec.id), "{host:?} has no record"),
            WeeklyRuns::NotRun(why) => {
                assert!(
                    !why.is_empty(),
                    "{host:?} is not run weekly and says not why"
                );
                assert!(!hosts.contains(spec.id), "{host:?}");
            }
        }
    }
    let agents: BTreeSet<&str> = records.iter().map(|r| r.agent.as_str()).collect();
    assert_eq!(agents.len(), records.len(), "two records share a name");
}

/// The shell functions `script` defines (`name() {` at the start of a line).
fn functions(script: &str) -> BTreeSet<String> {
    script
        .lines()
        .filter_map(|line| line.strip_suffix("() {"))
        .filter(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .map(str::to_owned)
        .collect()
}

/// Each record has its script, and no script is left without a record. A
/// script defines what the job calls for its record and nothing it does not:
/// `install_agent` for an install of its own, `canary` for a package only
/// read, `load_hook` otherwise, `probe_agent` exactly when the record proves
/// the hook-failure comparison, and `check_config_format` exactly when a
/// config file is the agent's own format.
#[test]
fn each_record_has_its_script_with_the_steps_it_needs() {
    let dir = crate::repo_root().join(SCRIPTS);
    let mut files: BTreeSet<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    for (spec, run) in runs() {
        let file = format!("{}.sh", run.agent);
        assert!(files.remove(&file), "{}: no {SCRIPTS}/{file}", spec.id);
        let defined = functions(&fs::read_to_string(dir.join(&file)).unwrap());
        let canary = matches!(run.install, WeeklyInstall::NpmPack { .. });
        let wanted = [
            (
                "install_agent",
                matches!(run.install, WeeklyInstall::Script { .. }),
            ),
            ("canary", canary),
            ("load_hook", !canary),
            ("probe_agent", run.proves.contains(&Proves::HookFailure)),
            (
                "check_config_format",
                run.config
                    .iter()
                    .any(|(_, f)| matches!(f, ConfigFormat::Agent(_))),
            ),
        ];
        for (function, needed) in wanted {
            assert_eq!(
                defined.contains(function),
                needed,
                "{file}: `{function}` (needed: {needed})"
            );
        }
    }
    assert!(files.is_empty(), "scripts without a record: {files:?}");
}

/// What the job sets lives in its throwaway home: every variable is one
/// `throwaway.sh` refuses to let point outside it, each set once. A
/// one-directory host's directory is the spec's, never restated in its
/// record, and its hook file is among the files the job checks.
#[test]
fn the_job_keeps_every_host_in_its_throwaway_home() {
    let throwaway = fs::read_to_string(crate::repo_root().join(THROWAWAY)).unwrap();
    let kept = throwaway
        .split_once("THROWAWAY_VARIABLES=(")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(list, _)| list.split_whitespace().collect::<BTreeSet<_>>())
        .unwrap();
    let env = env();
    let names: BTreeSet<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names.len(), env.len(), "a variable is set twice: {env:?}");
    for (name, value) in &env {
        assert!(
            kept.contains(name.as_str()),
            "{THROWAWAY} does not keep {name}"
        );
        assert!(
            value.starts_with("{HOME}") || value.starts_with("{ROOT}/"),
            "{name}={value}"
        );
    }
    for (spec, run) in runs() {
        let (Some(dir), Some(install)) = (one_dir(spec), &spec.install) else {
            continue;
        };
        assert_eq!(run.dir, None, "{}: the spec gives the directory", run.agent);
        let hook_file = format!("{dir}/{}", install.config_file);
        assert!(
            run.config.iter().any(|(path, _)| *path == hook_file),
            "{}: {hook_file} is not checked",
            run.agent
        );
    }
}
