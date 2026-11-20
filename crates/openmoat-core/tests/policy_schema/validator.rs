//! A JSON Schema validator for exactly the keywords the policy schemas use.
//!
//! The core takes no new dependency for a test (AGENTS §4), and the schemas
//! use a small part of draft 2020-12. [`unknown_keywords`] fails the suite
//! when a schema starts using a keyword this file does not implement, so the
//! schema can never say more than the test checks.

use serde_json::Value;

/// Keywords [`Schemas::validate`] implements.
const IMPLEMENTED: &[&str] = &[
    "$ref",
    "$defs",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "propertyNames",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "anyOf",
    "oneOf",
    "not",
];

/// Keywords that only describe and never change whether a document is valid.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "$comment",
    "title",
    "description",
    "deprecated",
];

/// The person's policy schema.
pub const POLICY: &str = "policy-v1.schema.json";
/// The repository policy and pack schema.
pub const REPO: &str = "repo-policy-v1.schema.json";

/// The committed schema files, by file name.
pub struct Schemas {
    files: Vec<(&'static str, Value)>,
}

impl Schemas {
    pub fn load() -> Self {
        let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
        Self {
            files: vec![
                (
                    POLICY,
                    parse(include_str!("../../policies/policy-v1.schema.json")),
                ),
                (
                    REPO,
                    parse(include_str!("../../policies/repo-policy-v1.schema.json")),
                ),
            ],
        }
    }

    pub fn files(&self) -> impl Iterator<Item = (&'static str, &Value)> {
        self.files.iter().map(|(name, v)| (*name, v))
    }

    pub fn root(&self, file: &str) -> &Value {
        &self.files.iter().find(|(n, _)| *n == file).unwrap().1
    }

    /// The schema a `$ref` names, and the file it is in: `#/$defs/x` in `file`,
    /// or `other.schema.json#/$defs/x` beside it.
    pub fn resolve<'a>(&'a self, file: &'a str, reference: &str) -> (&'a str, &'a Value) {
        let (target, pointer) = reference.split_once('#').unwrap();
        let target = if target.is_empty() {
            file
        } else {
            self.files.iter().find(|(n, _)| *n == target).unwrap().0
        };
        let node = self.root(target).pointer(pointer);
        (target, node.unwrap_or_else(|| panic!("no {reference}")))
    }

    /// `node` with every `$ref` followed: where a schema's keywords live.
    pub fn deref<'a>(&'a self, file: &'a str, node: &'a Value) -> (&'a str, &'a Value) {
        match node.get("$ref").and_then(Value::as_str) {
            Some(r) => {
                let (f, n) = self.resolve(file, r);
                self.deref(f, n)
            }
            None => (file, node),
        }
    }

    /// Every way `instance` breaks `schema` (of `file`), each with its path.
    pub fn validate(&self, file: &str, schema: &Value, instance: &Value, at: &str) -> Vec<String> {
        let mut errors = Vec::new();
        self.check(file, schema, instance, at, &mut errors);
        errors
    }

    fn check(&self, file: &str, schema: &Value, v: &Value, at: &str, out: &mut Vec<String>) {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let (f, target) = self.resolve(file, r);
            self.check(f, target, v, at, out);
        }
        if let Some(t) = schema.get("type") {
            let names: Vec<&str> = match t {
                Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
                other => vec![other.as_str().unwrap()],
            };
            if !names.iter().any(|n| has_type(v, n)) {
                out.push(format!("{at}: {v} is not of type {t}"));
                return;
            }
        }
        if let Some(Value::Array(values)) = schema.get("enum")
            && !values.contains(v)
        {
            out.push(format!("{at}: {v} is not one of {values:?}"));
        }
        if let Some(c) = schema.get("const")
            && c != v
        {
            out.push(format!("{at}: {v} is not {c}"));
        }
        if let Some(n) = v.as_f64() {
            let min = schema.get("minimum").and_then(Value::as_f64);
            let max = schema.get("maximum").and_then(Value::as_f64);
            if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                out.push(format!("{at}: {n} is out of range"));
            }
        }
        if let Some(object) = v.as_object() {
            let properties = schema.get("properties").and_then(Value::as_object);
            for name in required(schema) {
                if !object.contains_key(name) {
                    out.push(format!("{at}: missing `{name}`"));
                }
            }
            for (key, value) in object {
                let here = format!("{at}.{key}");
                if let Some(names) = schema.get("propertyNames") {
                    self.check(file, names, &Value::String(key.clone()), &here, out);
                }
                match (
                    properties.and_then(|p| p.get(key)),
                    schema.get("additionalProperties"),
                ) {
                    (Some(sub), _) => self.check(file, sub, value, &here, out),
                    (None, Some(Value::Bool(false))) => out.push(format!("{here}: not allowed")),
                    (None, Some(sub)) if sub.is_object() => {
                        self.check(file, sub, value, &here, out);
                    }
                    _ => {}
                }
            }
        }
        if let (Some(items), Some(list)) = (schema.get("items"), v.as_array()) {
            for (i, item) in list.iter().enumerate() {
                self.check(file, items, item, &format!("{at}[{i}]"), out);
            }
        }
        let passes = |s: &Value| self.validate(file, s, v, at).is_empty();
        if let Some(Value::Array(any)) = schema.get("anyOf")
            && !any.iter().any(passes)
        {
            out.push(format!("{at}: {v} matches no anyOf branch"));
        }
        if let Some(Value::Array(one)) = schema.get("oneOf") {
            let matched = one.iter().filter(|s| passes(s)).count();
            if matched != 1 {
                out.push(format!(
                    "{at}: {v} matches {matched} oneOf branches, not one"
                ));
            }
        }
        if let Some(not) = schema.get("not")
            && passes(not)
        {
            out.push(format!("{at}: matches what `not` forbids"));
        }
    }
}

/// The names `schema`'s `required` lists.
pub fn required(schema: &Value) -> impl Iterator<Item = &str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn has_type(v: &Value, name: &str) -> bool {
    match name {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "integer" => v.is_i64() || v.is_u64(),
        "number" => v.is_number(),
        other => panic!("unknown type {other}"),
    }
}

/// Every keyword of `schema` this validator neither implements nor knows to
/// be an annotation, with where it is.
pub fn unknown_keywords(schema: &Value, at: &str, out: &mut Vec<String>) {
    let Some(object) = schema.as_object() else {
        out.push(format!("{at}: a schema that is not an object"));
        return;
    };
    for (key, value) in object {
        let here = format!("{at}/{key}");
        match key.as_str() {
            "properties" | "$defs" => {
                for (name, sub) in value.as_object().into_iter().flatten() {
                    unknown_keywords(sub, &format!("{here}/{name}"), out);
                }
            }
            "anyOf" | "oneOf" => {
                for (i, sub) in value.as_array().into_iter().flatten().enumerate() {
                    unknown_keywords(sub, &format!("{here}/{i}"), out);
                }
            }
            "additionalProperties" if value.is_boolean() => {}
            "items" | "not" | "propertyNames" | "additionalProperties" => {
                unknown_keywords(value, &here, out);
            }
            k if IMPLEMENTED.contains(&k) || ANNOTATIONS.contains(&k) => {}
            k => out.push(format!(
                "{here}: keyword `{k}` is not implemented by the test"
            )),
        }
    }
}
