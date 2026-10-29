//! The few JSON values a response holds, written by hand: strings, arrays of
//! strings, numbers and objects of those. The module carries no JSON
//! library (ADR-046); requests are read by the core's YAML 1.2 reader, of which
//! JSON is a subset.

use std::fmt::Write as _;

/// A JSON object under construction.
#[derive(Debug)]
pub struct Object(String);

impl Object {
    /// `{`.
    pub fn new() -> Self {
        Self(String::from("{"))
    }

    fn key(&mut self, key: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        string(&mut self.0, key);
        self.0.push(':');
    }

    /// `"key": "value"`.
    pub fn string(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        string(&mut self.0, value);
        self
    }

    /// `"key": n`.
    pub fn number(mut self, key: &str, value: u32) -> Self {
        self.key(key);
        let _ = write!(self.0, "{value}");
        self
    }

    /// `"key": true` or `false`.
    pub fn boolean(mut self, key: &str, value: bool) -> Self {
        self.key(key);
        self.0.push_str(if value { "true" } else { "false" });
        self
    }

    /// `"key": ["a", "b"]`.
    pub fn strings(mut self, key: &str, values: &[String]) -> Self {
        self.key(key);
        self.0.push('[');
        for (n, value) in values.iter().enumerate() {
            if n > 0 {
                self.0.push(',');
            }
            string(&mut self.0, value);
        }
        self.0.push(']');
        self
    }

    /// `"key": {…}`.
    pub fn object(mut self, key: &str, value: Self) -> Self {
        self.key(key);
        self.0.push_str(&value.finish());
        self
    }

    /// `}`, and the text.
    pub fn finish(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

/// `value` as a JSON string: quotes, backslashes and every character YAML 1.2
/// does not allow unescaped escaped, everything else as UTF-8. The JavaScript
/// side escapes the same set ([`not_yaml_printable`]), so a string reads back
/// the same through either parser.
fn string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if not_yaml_printable(c) => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Characters a YAML 1.2 stream may not hold unescaped, though JSON may:
/// C0 controls, DEL, C1 controls, the byte-order mark, U+FFFE and U+FFFF.
fn not_yaml_printable(c: char) -> bool {
    matches!(u32::from(c), 0..0x20 | 0x7f..=0x9f | 0xfeff | 0xfffe | 0xffff)
}

#[cfg(test)]
mod tests {
    use super::Object;

    #[test]
    fn writes_escaped_strings_arrays_and_nested_objects() {
        let text = Object::new()
            .string("a", "q\"b\\n\nt\tc\u{1}é")
            .strings("r", &["x".into(), "y".into()])
            .strings("e", &[])
            .number("n", 7)
            .boolean("b", false)
            .object("o", Object::new())
            .finish();
        assert_eq!(
            text,
            r#"{"a":"q\"b\\n\nt\tc\u0001é","r":["x","y"],"e":[],"n":7,"b":false,"o":{}}"#
        );
    }

    /// What the writer escapes, the module's request reader reads back as it
    /// was, so a string makes the round trip through JavaScript unchanged.
    #[test]
    fn the_request_reader_reads_back_what_the_writer_wrote() {
        #[derive(serde::Deserialize)]
        struct Shape {
            a: String,
            r: Vec<String>,
            o: std::collections::BTreeMap<String, String>,
        }
        let tricky =
            "q\"b\\n\nt\tc\u{1}\u{7f}\u{85}\u{9f}\u{feff}\u{fffe}\u{ffff}é \u{2028} '#: - [x] 😀";
        let text = Object::new()
            .string("a", tricky)
            .strings("r", &["*".into(), "~".into()])
            .object("o", Object::new())
            .finish();
        let back: Shape = openmoat_core::yaml::from_str(&text).unwrap();
        assert_eq!(back.a, tricky);
        assert_eq!(back.r, ["*", "~"]);
        assert!(back.o.is_empty());
    }
}
