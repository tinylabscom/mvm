//! `mvmforge explain` — describe a stable error code from the registry.
//!
//! Every error mvmforge emits carries a stable string ID (ADR-0004,
//! `schema/error-codes.json`). This command surfaces that registry so
//! users don't need to grep the repo:
//!
//!   - `mvmforge explain E_FOO` — description + applicable fields + docs link
//!   - `mvmforge explain --list` — every known code, one line each
//!   - `--json` (either form) — machine-readable for CI / IDEs
//!
//! Single source of truth: `schema/error-codes.json`, embedded at compile
//! time. The `mvmforge-ir` crate's `ErrorCode` enum has a registry
//! conformance test, so any code emitted by validation is guaranteed to
//! be explainable here.

use serde::Serialize;
use serde_json::Value;

const ERROR_CODES_JSON: &str = include_str!("../../schema/error-codes.json");
const DOCS_URL: &str = "https://mvm.dev/reference/error-codes/";

#[derive(Debug, Clone, Serialize)]
struct CodeEntry {
    code: String,
    description: String,
    applicable_fields: Vec<String>,
    docs_url: &'static str,
}

#[derive(Debug, Serialize)]
struct ListPayload<'a> {
    codes: &'a [CodeEntry],
}

#[derive(Debug, Serialize)]
struct UnknownCodePayload<'a> {
    error: &'static str,
    code: &'a str,
    suggestions: Vec<&'a str>,
    docs_url: &'static str,
}

pub fn run(code: Option<&str>, list: bool, json: bool) -> i32 {
    let entries = match load_entries() {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("mvmforge explain: {msg}");
            return 2;
        }
    };

    if list {
        return print_list(&entries, json);
    }

    let normalized = match code {
        Some(c) => normalize_code(c),
        None => {
            print_usage_hint();
            return 2;
        }
    };

    match entries.iter().find(|e| e.code == normalized) {
        Some(entry) => {
            if json {
                println!("{}", serde_json::to_string_pretty(entry).unwrap());
            } else {
                print_entry(entry);
            }
            0
        }
        None => {
            print_unknown_code(&normalized, &entries, json);
            1
        }
    }
}

fn load_entries() -> Result<Vec<CodeEntry>, String> {
    let value: Value = serde_json::from_str(ERROR_CODES_JSON)
        .map_err(|e| format!("error-codes.json could not be parsed: {e}"))?;
    let codes = value
        .get("codes")
        .and_then(Value::as_object)
        .ok_or_else(|| "error-codes.json missing `codes` object".to_string())?;
    let mut entries: Vec<CodeEntry> = codes
        .iter()
        .map(|(name, body)| CodeEntry {
            code: name.clone(),
            description: body
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            applicable_fields: body
                .get("applicable_fields")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            docs_url: DOCS_URL,
        })
        .collect();
    entries.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(entries)
}

fn normalize_code(s: &str) -> String {
    let upper = s.trim().to_uppercase();
    if upper.starts_with("E_") || upper.is_empty() {
        upper
    } else {
        format!("E_{upper}")
    }
}

fn print_entry(entry: &CodeEntry) {
    println!("{}\n", entry.code);
    for line in wrap(&entry.description, 76) {
        println!("  {line}");
    }
    if !entry.applicable_fields.is_empty() {
        println!("\nApplicable fields:");
        for f in &entry.applicable_fields {
            println!("  - {f}");
        }
    }
    println!("\nDocs: {}", entry.docs_url);
}

fn print_list(entries: &[CodeEntry], json: bool) -> i32 {
    if json {
        let payload = ListPayload { codes: entries };
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return 0;
    }
    println!("mvmforge error codes ({} total)\n", entries.len());
    let max_len = entries.iter().map(|e| e.code.len()).max().unwrap_or(0);
    for e in entries {
        let summary = first_sentence(&e.description, 80 - max_len.min(40));
        println!(
            "  {code:<width$}  {summary}",
            code = e.code,
            width = max_len
        );
    }
    println!("\nRun `mvmforge explain <CODE>` for the full description.");
    0
}

fn print_unknown_code(code: &str, entries: &[CodeEntry], json: bool) {
    let suggestions = suggest_close_codes(code, entries, 5);
    if json {
        let payload = UnknownCodePayload {
            error: "unknown_code",
            code,
            suggestions: suggestions.clone(),
            docs_url: DOCS_URL,
        };
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }
    eprintln!("mvmforge explain: unknown error code `{code}`.");
    if !suggestions.is_empty() {
        eprintln!("\nDid you mean:");
        for s in &suggestions {
            eprintln!("  - {s}");
        }
    }
    eprintln!("\nRun `mvmforge explain --list` to see every known code.");
}

fn print_usage_hint() {
    eprintln!("mvmforge explain — look up an error code emitted by mvmforge.\n");
    eprintln!("Usage:");
    eprintln!("  mvmforge explain <CODE>      Show description + applicable fields.");
    eprintln!("  mvmforge explain --list      List every known error code.");
    eprintln!("\nAdd --json to either form for machine-readable output (CI / IDEs).");
}

fn suggest_close_codes<'a>(code: &str, entries: &'a [CodeEntry], limit: usize) -> Vec<&'a str> {
    let needle = code.trim_start_matches("E_");
    if needle.is_empty() {
        return Vec::new();
    }
    let mut suggestions: Vec<&str> = entries
        .iter()
        .map(|e| e.code.as_str())
        .filter(|name| name.contains(needle) || needle.contains(name.trim_start_matches("E_")))
        .take(limit)
        .collect();
    if suggestions.is_empty() {
        let prefix: String = needle.chars().take(4).collect();
        if !prefix.is_empty() {
            suggestions = entries
                .iter()
                .map(|e| e.code.as_str())
                .filter(|name| name.trim_start_matches("E_").starts_with(&prefix))
                .take(limit)
                .collect();
        }
    }
    suggestions
}

fn first_sentence(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    let end = trimmed.find(". ").map(|i| i + 1).unwrap_or(trimmed.len());
    let sentence = &trimmed[..end];
    truncate_chars(sentence, max_chars)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let take = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_ir::ErrorCode;

    #[test]
    fn loads_every_entry_from_registry() {
        let entries = load_entries().expect("load_entries");
        assert!(
            entries.len() >= 50,
            "expected ≥50 codes, got {}",
            entries.len()
        );
        for e in &entries {
            assert!(e.code.starts_with("E_"), "{} missing E_ prefix", e.code);
            assert!(
                !e.description.is_empty(),
                "{} has empty description",
                e.code
            );
        }
    }

    #[test]
    fn entries_sorted_by_code() {
        let entries = load_entries().unwrap();
        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| a.code.cmp(&b.code));
        assert_eq!(
            entries.iter().map(|e| &e.code).collect::<Vec<_>>(),
            sorted.iter().map(|e| &e.code).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_ir_error_code_is_explainable() {
        let entries = load_entries().unwrap();
        let known: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.code.as_str()).collect();
        let ir_codes = [
            ErrorCode::FunctionNotFound,
            ErrorCode::SecretsNotImplemented,
            ErrorCode::AddonLockfileMissing,
            ErrorCode::UnsupportedLanguage,
            ErrorCode::AddonNotFound,
        ];
        for code in ir_codes {
            assert!(
                known.contains(code.as_str()),
                "registry missing IR code {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn normalize_handles_case_and_prefix() {
        assert_eq!(
            normalize_code("E_FUNCTION_NOT_FOUND"),
            "E_FUNCTION_NOT_FOUND"
        );
        assert_eq!(
            normalize_code("e_function_not_found"),
            "E_FUNCTION_NOT_FOUND"
        );
        assert_eq!(normalize_code("function_not_found"), "E_FUNCTION_NOT_FOUND");
        assert_eq!(normalize_code("  E_INVALID_ID  "), "E_INVALID_ID");
        assert_eq!(normalize_code(""), "");
    }

    #[test]
    fn suggest_close_finds_substring_matches() {
        let entries = load_entries().unwrap();
        let s = suggest_close_codes("E_FUNCTION", &entries, 5);
        assert!(s.iter().any(|c| c.contains("FUNCTION")), "got {s:?}");
    }

    #[test]
    fn first_sentence_caps_at_max_chars() {
        let s = first_sentence("Short.", 80);
        assert_eq!(s, "Short.");
        let long = "A very long description that keeps going and going and going past the cap.";
        let s = first_sentence(long, 30);
        assert!(
            s.chars().count() <= 30,
            "got {s} ({} chars)",
            s.chars().count()
        );
    }

    #[test]
    fn wrap_respects_width() {
        let lines = wrap("one two three four five six seven", 10);
        for line in &lines {
            assert!(line.chars().count() <= 10, "line too long: {line:?}");
        }
        assert_eq!(lines.join(" "), "one two three four five six seven");
    }

    #[test]
    fn truncate_chars_handles_multibyte() {
        let s = truncate_chars("αβγδεζη", 4);
        assert_eq!(s.chars().count(), 4);
        assert!(s.ends_with('…'));
    }
}
