//! Places in a schema the drift test checks against the Rust model, and the
//! smallest document the schema accepts that reaches each of them.

use serde_json::{Map, Value, json};

use crate::validator::{Schemas, required};

/// One step from a schema to the one inside it.
#[derive(Debug, Clone)]
pub enum Step {
    /// A property of an object.
    Prop(String),
    /// An item of an array.
    Item,
    /// A value of a map (`additionalProperties`), under the key `x`.
    AnyKey,
    /// One branch of `anyOf` or `oneOf`.
    Branch(usize),
}

/// What the drift test checks at a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// An object with `additionalProperties: false`: a struct with
    /// `deny_unknown_fields`.
    Closed,
    /// A `oneOf` of objects with one required key each: an externally tagged enum.
    Tagged,
    /// An `enum` of strings: a unit-variant enum.
    Enum,
}

/// A place in a schema: the steps from the root, and what is there.
#[derive(Debug, Clone)]
pub struct Place {
    pub steps: Vec<Step>,
    pub shape: Shape,
}

/// How the document differs from the smallest one at the place.
pub enum Change<'a> {
    None,
    /// Add an unknown key to the object.
    AddKey(&'a str),
    /// Drop a required key from the object.
    RemoveKey(&'a str),
    /// Put this value there instead.
    Replace(Value),
}

/// Every place of `file`'s schema the drift test checks.
pub fn places(schemas: &Schemas, file: &str) -> Vec<Place> {
    let mut out = Vec::new();
    visit(
        schemas,
        file,
        schemas.root(file),
        &mut Vec::new(),
        false,
        &mut out,
    );
    out
}

fn visit(
    schemas: &Schemas,
    file: &str,
    node: &Value,
    steps: &mut Vec<Step>,
    tagged_branch: bool,
    out: &mut Vec<Place>,
) {
    assert!(steps.len() < 12, "the schema nests too deep: a $ref loop?");
    let (file, node) = schemas.deref(file, node);
    let mut place = |shape| {
        out.push(Place {
            steps: steps.clone(),
            shape,
        });
    };
    if node.get("additionalProperties") == Some(&Value::Bool(false)) && !tagged_branch {
        place(Shape::Closed);
    }
    if node
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().all(Value::is_string))
    {
        place(Shape::Enum);
    }
    let tagged = node.get("oneOf").is_some_and(is_tagged);
    if tagged {
        place(Shape::Tagged);
    }
    let mut descend = |step: Step, sub: &Value, tagged_branch: bool| {
        steps.push(step);
        visit(schemas, file, sub, steps, tagged_branch, out);
        steps.pop();
    };
    for (name, sub) in node
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        descend(Step::Prop(name.clone()), sub, false);
    }
    if let Some(sub) = node.get("items") {
        descend(Step::Item, sub, false);
    }
    if let Some(sub) = node.get("additionalProperties").filter(|v| v.is_object()) {
        descend(Step::AnyKey, sub, false);
    }
    for key in ["anyOf", "oneOf"] {
        for (i, sub) in node
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            descend(Step::Branch(i), sub, tagged && key == "oneOf");
        }
    }
}

/// A `oneOf` whose every branch is a closed object with one key it requires:
/// how serde's externally tagged enums look (`source: { env: NAME }`).
fn is_tagged(one_of: &Value) -> bool {
    one_of.as_array().is_some_and(|branches| {
        branches.iter().all(|b| {
            let props = b.get("properties").and_then(Value::as_object);
            b.get("additionalProperties") == Some(&Value::Bool(false))
                && props.is_some_and(|p| p.len() == 1)
                && required(b).eq(props.into_iter().flat_map(|p| p.keys().map(String::as_str)))
        })
    })
}

/// The schema at the end of `steps`, with its file.
pub fn at<'a>(schemas: &'a Schemas, file: &'a str, steps: &[Step]) -> (&'a str, &'a Value) {
    let (mut file, mut node) = schemas.deref(file, schemas.root(file));
    for step in steps {
        (file, node) = step_into(schemas, file, node, step);
    }
    (file, node)
}

/// The schema one `step` inside `node` (already dereferenced).
fn step_into<'a>(
    schemas: &'a Schemas,
    file: &'a str,
    node: &'a Value,
    step: &Step,
) -> (&'a str, &'a Value) {
    let next = match step {
        Step::Prop(name) => &node["properties"][name],
        Step::Item => &node["items"],
        Step::AnyKey => &node["additionalProperties"],
        Step::Branch(i) => node
            .get("anyOf")
            .or_else(|| node.get("oneOf"))
            .map(|b| &b[*i])
            .unwrap(),
    };
    schemas.deref(file, next)
}

/// The smallest document `file`'s schema accepts that reaches the end of
/// `steps`, with `change` made there.
pub fn build(schemas: &Schemas, file: &str, steps: &[Step], change: &Change) -> Value {
    let (file, node) = schemas.deref(file, schemas.root(file));
    build_at(schemas, file, node, steps, change)
}

fn build_at(schemas: &Schemas, file: &str, node: &Value, steps: &[Step], change: &Change) -> Value {
    let Some((step, rest)) = steps.split_first() else {
        let mut value = minimal(schemas, file, node);
        match change {
            Change::None => {}
            Change::AddKey(key) => {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert((*key).into(), json!("x"));
            }
            Change::RemoveKey(key) => {
                value.as_object_mut().unwrap().remove(*key);
            }
            Change::Replace(v) => value = v.clone(),
        }
        return value;
    };
    let (f, sub) = step_into(schemas, file, node, step);
    let inner = build_at(schemas, f, sub, rest, change);
    match step {
        Step::Prop(name) => {
            let mut value = minimal(schemas, file, node);
            value.as_object_mut().unwrap().insert(name.clone(), inner);
            value
        }
        Step::Item => json!([inner]),
        Step::AnyKey => json!({ "x": inner }),
        Step::Branch(_) => inner,
    }
}

/// The smallest value `node` accepts: required keys only, empty lists, the
/// first of a choice.
pub fn minimal(schemas: &Schemas, file: &str, node: &Value) -> Value {
    let (file, node) = schemas.deref(file, node);
    if let Some(c) = node.get("const") {
        return c.clone();
    }
    if let Some(first) = node.get("enum").and_then(|e| e.get(0)) {
        return first.clone();
    }
    if let Some(first) = node
        .get("anyOf")
        .or_else(|| node.get("oneOf"))
        .and_then(|b| b.get(0))
    {
        return minimal(schemas, file, first);
    }
    match node.get("type").and_then(Value::as_str) {
        Some("object") => {
            let mut object = Map::new();
            for name in required(node) {
                object.insert(
                    name.into(),
                    minimal(schemas, file, &node["properties"][name]),
                );
            }
            Value::Object(object)
        }
        Some("array") => json!([]),
        Some("string") => json!("x"),
        Some("integer") => node.get("minimum").cloned().unwrap_or(json!(0)),
        Some("boolean") => json!(false),
        other => panic!("no smallest value for type {other:?} in {node}"),
    }
}
