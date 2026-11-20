//! The bundled policies, the packs and the examples in docs/POLICY.md fit
//! the schemas, and POLICY.md §1 names every key the schema has.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

use crate::validator::{POLICY, REPO, Schemas};
use crate::{keys, serde_only, walk};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn yaml(text: &str) -> Value {
    openmoat_core::yaml::from_str::<Value>(text).unwrap()
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(ROOT).join(relative)).unwrap()
}

fn assert_fits(schemas: &Schemas, file: &str, doc: &Value, what: &str) {
    let errors = schemas.validate(file, schemas.root(file), doc, "");
    assert!(
        errors.is_empty(),
        "{what} does not fit {file}:\n{}",
        errors.join("\n")
    );
    if let Err(e) = serde_only(file, &doc.to_string()) {
        panic!("{what} fits {file} but the model refuses it: {e}");
    }
}

#[test]
fn the_bundled_policies_and_packs_fit_the_schemas() {
    let schemas = Schemas::load();
    assert_fits(
        &schemas,
        POLICY,
        &yaml(openmoat_core::DEFAULT_POLICY),
        "the default policy",
    );
    // The default an early release wrote, which `policy upgrade` starts from:
    // it still says `ask:`.
    let old = "../openmoat-cli/src/upgrade/default-v0.3.0.yaml";
    assert_fits(&schemas, POLICY, &yaml(&read(old)), old);
    let mut packs = 0;
    for entry in std::fs::read_dir(Path::new(ROOT).join("policies/packs")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_fits(&schemas, REPO, &yaml(&text), &path.display().to_string());
        packs += 1;
    }
    assert!(packs > 0, "no bundled pack found");
}

/// A fenced YAML block of POLICY.md, with the `## ` section it is in.
struct Block {
    line: usize,
    section: String,
    text: String,
}

fn policy_md_blocks() -> Vec<Block> {
    let doc = read("../../docs/POLICY.md");
    let mut blocks = Vec::new();
    let mut section = String::new();
    let mut open: Option<Block> = None;
    let mut other_fence = false;
    for (i, line) in doc.lines().enumerate() {
        if other_fence {
            other_fence = !line.starts_with("```");
        } else if let Some(block) = open.as_mut() {
            if line.starts_with("```") {
                blocks.extend(open.take());
            } else {
                block.text.push_str(line);
                block.text.push('\n');
            }
        } else if line.starts_with("## ") {
            line.clone_into(&mut section);
        } else if line == "```yaml" {
            open = Some(Block {
                line: i + 1,
                section: section.clone(),
                text: String::new(),
            });
        } else if line.starts_with("```") {
            other_fence = true;
        }
    }
    blocks
}

/// The first block of §1, the policy's whole shape with `<rule group>`
/// placeholders: checked by its keys, not as a policy.
fn is_shape(block: &Block) -> bool {
    block.section == "## 1. Shape" && block.text.starts_with("version: 1 ")
}

/// Every policy example in POLICY.md fits the schema it is written for: a
/// list is a list of rule groups, a section about repository policies or
/// packs holds repository policies, and `version: 1` is added to a fragment.
#[test]
fn the_examples_in_policy_md_fit_the_schemas() {
    let schemas = Schemas::load();
    let mut checked = 0;
    let mut approvals = 0;
    for block in policy_md_blocks().into_iter().filter(|b| !is_shape(b)) {
        let what = format!("docs/POLICY.md line {}", block.line);
        let mut doc = match yaml(&block.text) {
            Value::Array(groups) => json!({ "deny": groups }),
            // `openmoat allow`'s own file (§8.2), not a policy.
            Value::Object(map) if map.contains_key("expires") => {
                approvals += 1;
                continue;
            }
            other => other,
        };
        let object = doc
            .as_object_mut()
            .unwrap_or_else(|| panic!("{what}: not a mapping"));
        object.entry("version").or_insert(json!(1));
        let file = if block.section.starts_with("## 10.") || block.section.starts_with("## 11.") {
            REPO
        } else {
            POLICY
        };
        assert_fits(&schemas, file, &doc, &what);
        checked += 1;
    }
    assert_eq!(approvals, 1, "one example is the approvals file");
    assert!(checked >= 15, "only {checked} examples checked");
}

/// §1 shows every key of the schema, and every key of each section with a
/// fixed set of keys. `approval`, `scope` and the old `ask` are described in
/// the text under it instead.
#[test]
fn policy_md_section_1_names_every_key() {
    let schemas = Schemas::load();
    let blocks = policy_md_blocks();
    let shapes: Vec<&Block> = blocks.iter().filter(|b| is_shape(b)).collect();
    assert_eq!(shapes.len(), 1, "POLICY.md §1 shows the shape once");
    let shape = shapes[0];
    let shown = yaml(&shape.text);
    let mut top: BTreeSet<String> = shown.as_object().unwrap().keys().cloned().collect();
    top.extend(["approval", "scope", "ask"].map(str::to_owned));
    let root = schemas.root(POLICY);
    assert_eq!(
        top,
        keys(root, "properties"),
        "POLICY.md §1 against the schema"
    );
    for (key, value) in shown.as_object().unwrap() {
        let (_, node) = walk::at(&schemas, POLICY, &[walk::Step::Prop(key.clone())]);
        if value.is_object() && node.get("additionalProperties") == Some(&Value::Bool(false)) {
            let listed: BTreeSet<String> = value.as_object().unwrap().keys().cloned().collect();
            assert_eq!(listed, keys(node, "properties"), "POLICY.md §1 `{key}:`");
        }
    }
}

/// POLICY.md says where the schemas are, by their `$id`.
#[test]
fn policy_md_names_the_schemas() {
    let doc = read("../../docs/POLICY.md");
    let schemas = Schemas::load();
    for (file, schema) in schemas.files() {
        let id = schema["$id"].as_str().unwrap();
        assert!(
            doc.contains(id),
            "docs/POLICY.md does not name {file} by {id}"
        );
    }
}
