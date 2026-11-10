use serde_json::json;

use super::{parse_or_empty, read, read_for_edit};
use crate::json5::parse;

#[test]
fn no_text_is_an_empty_object_only_where_a_file_may_be_absent() {
    assert!(parse("  ").is_err());
    let parsed = parse_or_empty("  \n").unwrap();
    assert_eq!(parsed.value, json!({}));
    assert!(!parsed.comments);
}

#[test]
fn a_file_with_comments_is_refused_for_an_edit_and_read_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, "// mine\n{ a: 1 }").unwrap();
    assert_eq!(read(&path).unwrap(), json!({"a": 1}));
    let refused = read_for_edit(&path).unwrap_err().to_string();
    assert!(refused.contains("has comments"), "{refused}");
    assert_eq!(
        read_for_edit(&dir.path().join("none.json")).unwrap(),
        json!({})
    );
}
