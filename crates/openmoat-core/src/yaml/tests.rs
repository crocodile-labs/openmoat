use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{from_str, to_string};
use crate::{Policy, PolicyError, SecretSource};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Doc {
    #[serde(default)]
    flag: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    list: Vec<String>,
    #[serde(default)]
    map: BTreeMap<String, String>,
    #[serde(default)]
    source: Option<SecretSource>,
}

fn err(yaml: &str) -> String {
    from_str::<Doc>(yaml).unwrap_err().to_string()
}

#[test]
fn yaml_1_1_booleans_are_not_booleans() {
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "ON"] {
        let e = err(&format!("flag: {word}\n"));
        assert!(e.contains("line 1, column 7"), "{word}: {e}");
    }
    let doc: Doc = from_str("flag: false\nname: yes\nlist: [no, on, 0123]\n").unwrap();
    assert_eq!(doc.flag, Some(false));
    assert_eq!(
        doc.name.as_deref(),
        Some("yes"),
        "a string field keeps `yes` as text"
    );
    assert_eq!(doc.list, ["no", "on", "0123"]);
}

#[test]
fn repeated_keys_are_errors_in_structs_and_maps() {
    assert!(err("name: a\nname: b\n").contains("duplicate mapping key: name"));
    assert!(err("map: {a: x, a: y}\n").contains("duplicate mapping key: a"));
    // A reader sees `deny` first; "last one wins" would make it `allow`.
    let twice = "version: 1\ndefaults:\n  net: deny\n  net: allow\n";
    assert!(matches!(Policy::parse(twice), Err(PolicyError::Parse(_))));
}

#[test]
fn merge_keys_unknown_tags_and_unknown_fields_are_errors() {
    assert!(err("map: &m {a: x}\nother:\n  <<: *m\n").contains("unknown field `other`"));
    assert!(err("map:\n  <<: {a: x}\n").contains("merge keys"));
    assert!(err("source: !env TOKEN\n").contains("unsupported tag `!env`"));
    assert!(err("bogus: 1\n").contains("unknown field `bogus`"));
}

#[test]
fn binary_tags_are_not_decoded() {
    let doc: Doc = from_str("name: !!binary fi8uc3No\n").unwrap();
    assert_eq!(doc.name.as_deref(), Some("fi8uc3No"));
}

#[test]
fn anchors_flow_and_block_scalars_parse() {
    let doc: Doc =
        from_str("list: &paths [\"~/.ssh/**\", x] # c\nmap: { a: b }\nname: |\n  one\n  two\n")
            .unwrap();
    assert_eq!(doc.list, ["~/.ssh/**", "x"]);
    assert_eq!(doc.name.as_deref(), Some("one\ntwo\n"));
    let p = Policy::parse(
        "version: 1\ndeny:\n  - { id: a, fs.read: &s [\"~/.ssh/**\"] }\n  - { id: b, fs.write: *s }\n",
    )
    .unwrap();
    assert_eq!(p.deny.len(), 2);
}

#[test]
fn a_secret_source_is_a_one_key_mapping_both_ways() {
    let doc: Doc = from_str("source: { env: TOKEN }\n").unwrap();
    assert_eq!(doc.source, Some(SecretSource::Env("TOKEN".to_owned())));
    let text = to_string(&doc).unwrap();
    assert!(text.contains("source:\n  env: TOKEN\n"), "{text}");
    assert_eq!(from_str::<Doc>(&text).unwrap(), doc);
}

#[test]
fn written_strings_read_back_as_the_same_strings() {
    let list = ["yes", "1", "a: b", "", "~", "null", "#x", "- y", "!z", "*w"].map(str::to_owned);
    let doc = Doc {
        list: list.to_vec(),
        ..from_str("{}").unwrap()
    };
    assert_eq!(from_str::<Doc>(&to_string(&doc).unwrap()).unwrap(), doc);
}

#[test]
fn policy_parse_errors_are_one_line_with_a_position() {
    let Err(PolicyError::Parse(e)) = Policy::parse("version: 1\ndeny:\n  - id: a\n   x: [y]\n")
    else {
        panic!("a malformed policy must not parse");
    };
    let text = e.to_string();
    assert!(!text.contains('\n'), "{text}");
    assert!(text.contains("line 4, column 4"), "{text}");
}
