//! Canonicalization of IR documents.
//!
//! Output conforms to RFC 8785 (JSON Canonicalization Scheme). v0 IR uses
//! only integer numeric types, which sidesteps the main JCS complexity
//! (ECMA-262 number serialization). If floats are ever admitted to the IR,
//! this module must be extended to perform JCS number canonicalization.

use serde::Serialize;
use serde_json::Value;

pub fn canonicalize<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let json = serde_json::to_value(value)?;
    let mut out = String::new();
    write_canonical(&mut out, &json);
    Ok(out)
}

fn write_canonical(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(out, key);
                out.push(':');
                write_canonical(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({ "b": 1, "a": 2 });
        assert_eq!(canonicalize(&v).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn preserves_array_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonicalize(&v).unwrap(), "[3,1,2]");
    }

    #[test]
    fn nested_objects_sort_recursively() {
        let v = json!({ "z": { "b": 1, "a": 2 }, "a": 3 });
        assert_eq!(canonicalize(&v).unwrap(), r#"{"a":3,"z":{"a":2,"b":1}}"#);
    }

    #[test]
    fn escapes_control_characters() {
        let v = json!({ "s": "a\nb\tc\"d" });
        assert_eq!(canonicalize(&v).unwrap(), r#"{"s":"a\nb\tc\"d"}"#);
    }

    #[test]
    fn emits_no_whitespace() {
        let v = json!({ "a": [1, 2, { "b": "c" }] });
        let canonical = canonicalize(&v).unwrap();
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
    }

    #[test]
    fn idempotent() {
        let v = json!({ "b": [2, 1], "a": { "y": 1, "x": 2 } });
        let once = canonicalize(&v).unwrap();
        let parsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonicalize(&parsed).unwrap();
        assert_eq!(once, twice);
    }
}
