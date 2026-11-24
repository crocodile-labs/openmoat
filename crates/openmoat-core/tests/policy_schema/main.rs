//! The JSON Schemas of policy schema version 1
//! (`policies/policy-v1.schema.json`, `policies/repo-policy-v1.schema.json`)
//! against the Rust model, which is the source of truth (ADR-103).
//!
//! The schemas are written by hand. These tests keep them honest without a
//! schema crate: every closed object of a schema is compared with the fields
//! serde names when the model meets an unknown key there, every choice and
//! enum with the variants serde names, and the bundled policies and the
//! examples in docs/POLICY.md must fit the schemas (`docs.rs`).

mod docs;
mod validator;
mod walk;

use std::collections::BTreeSet;

use openmoat_core::{Kind, Policy, RepoPolicy, Verdict};
use serde_json::{Value, json};

use validator::{POLICY, REPO, Schemas, required};
use walk::{Change, Shape, Step};

/// A key and a word no schema version will ever have.
const UNKNOWN: &str = "zz_unknown";

/// The full parse of a document for `file`'s schema, lint included.
fn parse(file: &str, text: &str) -> Result<(), String> {
    match file {
        POLICY => Policy::parse(text).map(drop),
        _ => RepoPolicy::parse(text).map(drop),
    }
    .map_err(|e| e.to_string())
}

/// Only the model's serde shape, without the lint, which checks more than a
/// schema of shapes can (patterns, unique ids, rules between keys).
fn serde_only(file: &str, text: &str) -> Result<(), String> {
    match file {
        POLICY => openmoat_core::yaml::from_str::<Policy>(text).map(drop),
        _ => openmoat_core::yaml::from_str::<RepoPolicy>(text).map(drop),
    }
    .map_err(|e| e.to_string())
}

/// The names serde lists after `marker` in an error: `unknown field `x`,
/// expected one of a, b`.
fn listed(message: &str, marker: &str) -> Option<BTreeSet<String>> {
    let rest = &message[message.find(marker)? + marker.len()..];
    let rest = rest
        .strip_prefix("expected one of ")
        .or_else(|| rest.strip_prefix("expected "))?;
    let list = rest.split(" at line ").next()?;
    Some(
        list.split(", ")
            .map(|s| s.trim_matches('`').to_owned())
            .collect(),
    )
}

fn keys(node: &Value, keyword: &str) -> BTreeSet<String> {
    node[keyword]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.clone())
        .collect()
}

fn name(file: &str, steps: &[Step]) -> String {
    format!("{file} {steps:?}")
}

fn check_closed(schemas: &Schemas, file: &str, steps: &[Step], failures: &mut Vec<String>) {
    let here = name(file, steps);
    let (_, node) = walk::at(schemas, file, steps);
    let declared = keys(node, "properties");
    let unknown = walk::build(schemas, file, steps, &Change::AddKey(UNKNOWN));
    match parse(file, &unknown.to_string()) {
        Ok(()) => failures.push(format!("{here}: the model accepts an unknown key")),
        Err(e) => match listed(&e, &format!("unknown field `{UNKNOWN}`, ")) {
            Some(fields) if fields == declared => {}
            Some(fields) => failures.push(format!(
                "{here}: the model reads {:?} the schema lacks; the schema has {:?} the model lacks",
                fields.difference(&declared).collect::<Vec<_>>(),
                declared.difference(&fields).collect::<Vec<_>>(),
            )),
            None => failures.push(format!("{here}: no field list in `{e}`")),
        },
    }
    let smallest = walk::build(schemas, file, steps, &Change::None);
    if let Err(e) = serde_only(file, &smallest.to_string()) {
        failures.push(format!("{here}: the model refuses {smallest}: {e}"));
    }
    for key in required(node) {
        let without = walk::build(schemas, file, steps, &Change::RemoveKey(key));
        match serde_only(file, &without.to_string()) {
            Err(e) if e.contains(&format!("missing field `{key}`")) => {}
            other => failures.push(format!("{here}: `{key}` is required, the model: {other:?}")),
        }
    }
}

fn check_choice(schemas: &Schemas, file: &str, steps: &[Step], failures: &mut Vec<String>) {
    let here = name(file, steps);
    let (_, node) = walk::at(schemas, file, steps);
    let (bad, declared): (Value, BTreeSet<String>) = if node.get("oneOf").is_some() {
        let branches = node["oneOf"].as_array().unwrap();
        // A struct variant's name is its one key, a unit variant's its `const`.
        let names = branches
            .iter()
            .flat_map(|b| keys(b, "properties"))
            .chain(
                branches
                    .iter()
                    .filter_map(|b| b["const"].as_str().map(str::to_owned)),
            )
            .collect();
        (json!({ UNKNOWN: "x" }), names)
    } else {
        let values = node["enum"].as_array().unwrap();
        for value in values {
            let doc = walk::build(schemas, file, steps, &Change::Replace(value.clone()));
            if let Err(e) = serde_only(file, &doc.to_string()) {
                failures.push(format!("{here}: the model refuses {value}: {e}"));
            }
        }
        let names = values
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        (json!(UNKNOWN), names)
    };
    let doc = walk::build(schemas, file, steps, &Change::Replace(bad));
    match parse(file, &doc.to_string()) {
        Ok(()) => failures.push(format!("{here}: the model accepts `{UNKNOWN}`")),
        Err(e) => match listed(&e, &format!("unknown variant `{UNKNOWN}`, ")) {
            Some(variants) if variants == declared => {}
            Some(variants) => {
                failures.push(format!("{here}: model {variants:?}, schema {declared:?}"));
            }
            // Inside an untagged choice (`defaults`) serde names no variant;
            // `verdicts_match_the_model` checks those.
            None if steps
                .iter()
                .any(|s| matches!(s, Step::Prop(p) if p == "defaults")) => {}
            None => failures.push(format!("{here}: no variant list in `{e}`")),
        },
    }
}

#[test]
fn the_schemas_use_only_keywords_the_validator_implements() {
    let schemas = Schemas::load();
    let mut unknown = Vec::new();
    for (file, schema) in schemas.files() {
        validator::unknown_keywords(schema, file, &mut unknown);
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{file}"
        );
        let id = schema["$id"].as_str().unwrap();
        assert!(
            id.ends_with(&format!("/crates/openmoat-core/policies/{file}")),
            "{file}: $id {id} is not where the file is"
        );
    }
    assert!(unknown.is_empty(), "{}", unknown.join("\n"));
}

#[test]
fn every_closed_object_lists_the_fields_the_model_reads() {
    let schemas = Schemas::load();
    let mut failures = Vec::new();
    for (file, at_least) in [(POLICY, 15), (REPO, 7)] {
        let closed: Vec<_> = walk::places(&schemas, file)
            .into_iter()
            .filter(|p| p.shape == Shape::Closed)
            .collect();
        assert!(
            closed.len() >= at_least,
            "{file}: only {} closed objects",
            closed.len()
        );
        for place in closed {
            check_closed(&schemas, file, &place.steps, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_choice_and_enum_lists_the_variants_the_model_reads() {
    let schemas = Schemas::load();
    let mut failures = Vec::new();
    for file in [POLICY, REPO] {
        for place in walk::places(&schemas, file) {
            if matches!(place.shape, Shape::Tagged | Shape::Enum) {
                check_choice(&schemas, file, &place.steps, &mut failures);
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn verdicts_match_the_model() {
    let schemas = Schemas::load();
    let verdict = &schemas.root(POLICY)["$defs"]["verdict"]["anyOf"];
    let mut declared: BTreeSet<String> = verdict[0]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(verdict[1]["const"], "ask");
    assert_eq!(verdict[1]["deprecated"], true);
    declared.insert("ask".to_owned());
    let e = openmoat_core::yaml::from_str::<Verdict>(UNKNOWN)
        .unwrap_err()
        .to_string();
    assert_eq!(
        listed(&e, &format!("unknown variant `{UNKNOWN}`, ")),
        Some(declared)
    );
}

#[test]
fn defaults_name_every_kind() {
    let schemas = Schemas::load();
    let per_kind = &schemas.root(POLICY)["$defs"]["defaults"]["anyOf"][1];
    let mut kinds: BTreeSet<String> = Kind::ALL.iter().map(|k| k.as_str().to_owned()).collect();
    kinds.insert("*".to_owned());
    assert_eq!(keys(per_kind, "properties"), kinds);
    // A scalar is one verdict for everything; a map, a verdict per kind.
    for defaults in [json!("deny"), json!({ "net": "deny", "other": "allow" })] {
        let doc = json!({ "version": 1, "defaults": defaults });
        let errors = schemas.validate(POLICY, schemas.root(POLICY), &doc, "");
        assert_eq!(errors, Vec::<String>::new(), "{doc}");
        assert!(parse(POLICY, &doc.to_string()).is_ok(), "{doc}");
    }
}

#[test]
fn check_diff_levels_name_every_content_check() {
    let schemas = Schemas::load();
    let names =
        &schemas.root(POLICY)["$defs"]["checkDiff"]["properties"]["levels"]["propertyNames"];
    let declared: BTreeSet<&str> = names["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let rules: BTreeSet<&str> = openmoat_core::diffscan::RULES
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(declared, rules);
}

/// The validator itself refuses what the model refuses, so a passing
/// document test means something.
#[test]
fn the_schemas_refuse_what_the_model_refuses() {
    let schemas = Schemas::load();
    let cases = [
        (POLICY, json!({ "defaults": "deny" })),
        (POLICY, json!({ "version": 2 })),
        (POLICY, json!({ "version": 1, "denny": [] })),
        (POLICY, json!({ "version": 1, "ask": [], "review": [] })),
        (POLICY, json!({ "version": 1, "defaults": "maybe" })),
        (
            POLICY,
            json!({ "version": 1, "deny": [{ "id": "a", "shell": "x" }] }),
        ),
        (
            POLICY,
            json!({ "version": 1, "sandbox": { "proxy_port": 0 } }),
        ),
        (
            POLICY,
            json!({ "version": 1, "check_diff": { "levels": { "diff-nope": "off" } } }),
        ),
        (
            POLICY,
            json!({ "version": 1, "secrets": [{ "id": "a", "host": "h", "header": "x",
                "source": { "env": "A", "file": "/f" } }] }),
        ),
        (REPO, json!({ "version": 1, "defaults": "deny" })),
        (REPO, json!({ "version": 1, "unattended": "review" })),
        (
            POLICY,
            json!({ "version": 1, "hooks": { "foreign": "ask" } }),
        ),
        (
            POLICY,
            json!({ "version": 1, "hooks": { "other": "hold" } }),
        ),
        (
            REPO,
            json!({ "version": 1, "hooks": { "foreign": "hold" } }),
        ),
        (
            REPO,
            json!({ "version": 1, "requests": [{ "id": "a", "host": "h", "allow": ["GET /"] }] }),
        ),
    ];
    for (file, doc) in cases {
        assert!(
            !schemas
                .validate(file, schemas.root(file), &doc, "")
                .is_empty(),
            "{file} accepts {doc}"
        );
        assert!(
            parse(file, &doc.to_string()).is_err(),
            "the model accepts {doc}"
        );
    }
}
