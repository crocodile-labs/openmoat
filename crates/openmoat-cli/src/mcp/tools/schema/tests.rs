use serde_json::{Value, json};

use super::*;

fn tool(input: Value) -> Value {
    let mut tool = json!({"name": "execute_sql", "description": "Run SQL"});
    tool["inputSchema"] = input;
    tool
}

/// The specification's own example: one string parameter as a header.
fn spec_example() -> Value {
    json!({"type": "object", "properties": {
        "region": {"type": "string", "x-mcp-header": "Region"},
        "query": {"type": "string"}}})
}

#[test]
fn the_specifications_example_maps_one_header() {
    assert_eq!(refusal(&tool(spec_example())), None);
    assert_eq!(
        mappings(&spec_example()),
        [Mapping {
            path: vec!["region".to_owned()],
            header: "Region".to_owned()
        }]
    );
    // Nested objects through `properties` alone are allowed.
    let nested = json!({"type": "object", "properties": {"target": {"type": "object",
        "properties": {"tenant": {"type": "integer", "x-mcp-header": "Tenant"}}}}});
    assert_eq!(refusal(&tool(nested.clone())), None);
    assert_eq!(mappings(&nested)[0].path, ["target", "tenant"]);
}

#[test]
fn a_property_named_like_the_keyword_is_not_a_mapping() {
    let schema = json!({"type": "object", "properties": {
        "x-mcp-header": {"type": "string"}},
        "default": {"x-mcp-header": "Nope"}});
    assert_eq!(refusal(&tool(schema.clone())), None);
    assert_eq!(mappings(&schema), Vec::<Mapping>::new());
}

#[test]
fn mappings_that_break_the_rules_refuse_the_tool() {
    let cases = [
        // Not a header token, a line break in it, empty.
        json!({"properties": {"a": {"type": "string", "x-mcp-header": "Bad Name"}}}),
        json!({"properties": {"a": {"type": "string", "x-mcp-header": "X\r\nHost: evil"}}}),
        json!({"properties": {"a": {"type": "string", "x-mcp-header": ""}}}),
        // The same name twice, in another case.
        json!({"properties": {"a": {"type": "string", "x-mcp-header": "Region"},
            "b": {"type": "string", "x-mcp-header": "region"}}}),
        // A number, an object, no type.
        json!({"properties": {"a": {"type": "number", "x-mcp-header": "A"}}}),
        json!({"properties": {"a": {"type": "object", "x-mcp-header": "A"}}}),
        json!({"properties": {"a": {"x-mcp-header": "A"}}}),
        // Reached through `items`, `anyOf`, `$defs`, or at the root.
        json!({"properties": {"a": {"type": "array", "items": {"type": "string",
            "x-mcp-header": "A"}}}}),
        json!({"anyOf": [{"properties": {"a": {"type": "string", "x-mcp-header": "A"}}}]}),
        json!({"$defs": {"a": {"type": "string", "x-mcp-header": "A"}}}),
        json!({"type": "string", "x-mcp-header": "A"}),
    ];
    for schema in cases {
        assert!(refusal(&tool(schema.clone())).is_some(), "{schema}");
    }
    let output = json!({"name": "t", "inputSchema": {"type": "object"},
        "outputSchema": spec_example()});
    assert!(refusal(&output).unwrap().contains("input schema only"));
}

#[test]
fn local_refs_resolve_and_others_refuse_the_tool() {
    let fine = json!({"type": "object", "$defs": {"id": {"type": "string"}},
        "properties": {"a": {"$ref": "#/$defs/id"}, "b": {"$ref": "#/$defs/id"}}});
    assert_eq!(refusal(&tool(fine)), None);
    for target in [
        "https://169.254.169.254/latest/meta-data",
        "other.json#/x",
        "#/$defs/missing",
        "#anchor",
    ] {
        let schema = json!({"properties": {"a": {"$ref": target}}});
        assert!(refusal(&tool(schema)).is_some(), "{target}");
    }
}

#[test]
fn a_ref_loop_refuses_the_tool() {
    let tree = json!({"type": "object", "$defs": {"node": {"type": "object",
        "properties": {"child": {"$ref": "#/$defs/node"}}}},
        "properties": {"root": {"$ref": "#/$defs/node"}}});
    assert!(refusal(&tool(tree)).unwrap().contains("loop"));
    let root = json!({"properties": {"again": {"$ref": "#"}}});
    assert!(refusal(&tool(root)).unwrap().contains("loop"));
    let mutual = json!({"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}}});
    assert!(refusal(&tool(mutual)).unwrap().contains("loop"));
}

#[test]
fn a_ref_chain_or_nesting_past_the_bounds_refuses_the_tool() {
    let mut defs = serde_json::Map::new();
    for i in 0..=MAX_REF_DEPTH + 1 {
        defs.insert(
            format!("d{i}"),
            json!({"$ref": format!("#/$defs/d{}", i + 1)}),
        );
    }
    defs.insert(format!("d{}", MAX_REF_DEPTH + 2), json!({"type": "string"}));
    let deep = json!({"$defs": defs, "properties": {"a": {"$ref": "#/$defs/d0"}}});
    assert!(refusal(&tool(deep)).unwrap().contains("deeper"));
    // A diamond (two paths to one definition) is not a loop.
    let diamond = json!({"$defs": {"leaf": {"type": "string"},
        "l": {"properties": {"x": {"$ref": "#/$defs/leaf"}}},
        "r": {"properties": {"x": {"$ref": "#/$defs/leaf"}}}},
        "properties": {"a": {"$ref": "#/$defs/l"}, "b": {"$ref": "#/$defs/r"}}});
    assert_eq!(refusal(&tool(diamond)), None);

    let mut nested = json!({"type": "string"});
    for _ in 0..=MAX_DEPTH + 1 {
        nested = json!({"type": "object", "properties": {"n": nested}});
    }
    assert!(refusal(&tool(nested)).unwrap().contains("deeper"));
    let wide: serde_json::Map<String, Value> = (0..=MAX_NODES)
        .map(|i| (format!("p{i}"), json!({"type": "string"})))
        .collect();
    let wide = json!({"type": "object", "properties": wide});
    assert!(refusal(&tool(wide)).unwrap().contains("schema objects"));
}
