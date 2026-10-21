use super::*;
use serde_json::{Value, json};

const FIXTURE: &[u8] = include_bytes!("../application_manifest_v2.json");

fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn parse(value: &Value) -> Result<RegistryApplicationManifest, RegistryPackVerificationError> {
    parse_application_manifest(&serde_json::to_vec(value).unwrap())
}

#[test]
fn exact_publisher_fixture_round_trips_as_untrusted_data() {
    let manifest = parse_application_manifest(FIXTURE).unwrap();
    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.reference.to_string(), "test/hello@1.0.0");
    assert_eq!(manifest.application.bundle.archive_size, 123);
    assert_eq!(serde_json::to_value(manifest).unwrap(), document());
}

#[test]
fn policy_schema_stays_one_and_is_not_an_application_fallback() {
    assert_eq!(super::super::REGISTRY_PACK_MANIFEST_SCHEMA_VERSION, 1);
    assert_eq!(APPLICATION_MANIFEST_SCHEMA_VERSION, 2);
    let policy = json!({
        "schema_version": 1,
        "reference": "test/hello@1.0.0",
        "description": "Policy, not application",
        "files": []
    });
    assert!(parse(&policy).is_err());
    for field in ["files", "image", "payload", "publisher", "policy", "role"] {
        let mut value = document();
        value[field] = json!([]);
        assert!(parse(&value).is_err(), "{field}");
    }
}

#[test]
fn every_envelope_field_is_required_without_defaults() {
    for pointer in ["", "/application", "/application/bundle"] {
        let value = document();
        let keys: Vec<_> = value
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut bad = value.clone();
            bad.pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(parse(&bad).is_err(), "{pointer}/{key}");
        }
    }
}

#[test]
fn unknown_nested_fields_and_authority_assertions_refuse() {
    for pointer in ["/application", "/application/bundle"] {
        for key in ["verified", "allow", "publisher", "role", "default_role"] {
            let mut value = document();
            value.pointer_mut(pointer).unwrap()[key] = json!(true);
            assert!(parse(&value).is_err(), "{pointer}/{key}");
        }
    }
}

#[test]
fn duplicate_json_fields_refuse_at_each_depth_even_when_equal() {
    let value = serde_json::to_string(&document()).unwrap();
    for (needle, replacement) in [
        (
            "\"schema_version\":2",
            "\"schema_version\":2,\"schema_version\":2",
        ),
        (
            "\"kind\":\"application\"",
            "\"kind\":\"application\",\"kind\":\"application\"",
        ),
        (
            "\"guest_arch\":\"aarch64\"",
            "\"guest_arch\":\"aarch64\",\"guest_arch\":\"aarch64\"",
        ),
        (
            "\"archive_size\":123",
            "\"archive_size\":123,\"archive_size\":123",
        ),
        ("\"key_id\":", "\"archive_size\":123,\"key_id\":"),
    ] {
        let duplicate = value.replacen(needle, replacement, 1);
        assert_ne!(duplicate, value, "{needle}");
        assert!(
            parse_application_manifest(duplicate.as_bytes()).is_err(),
            "{needle}"
        );
    }
}

#[test]
fn versions_sizes_and_architectures_do_not_coerce() {
    for (pointer, bad) in [
        ("/schema_version", json!(1)),
        ("/schema_version", json!(3)),
        ("/schema_version", json!(true)),
        ("/schema_version", json!(2.0)),
        ("/schema_version", json!("2")),
        ("/kind", json!("policy")),
        ("/kind", json!("legacy")),
        ("/kind", json!("default")),
        ("/application/schema_version", json!(2)),
        ("/application/schema_version", json!(true)),
        ("/application/schema_version", json!(1.0)),
        ("/application/guest_arch", json!("arm64")),
        ("/application/guest_arch", json!("amd64")),
        ("/application/guest_arch", json!("")),
        ("/application/bundle/archive_size", json!(0)),
        ("/application/bundle/archive_size", json!(-1)),
        ("/application/bundle/archive_size", json!(true)),
        ("/application/bundle/archive_size", json!(123.0)),
        ("/application/bundle/archive_size", json!("123")),
    ] {
        let mut value = document();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(parse(&value).is_err(), "{pointer}");
    }
}

#[test]
fn archive_size_preserves_u64_limits_without_rounding() {
    let mut value = document();
    value["application"]["bundle"]["archive_size"] = json!(u64::MAX);
    assert_eq!(
        parse(&value).unwrap().application.bundle.archive_size,
        u64::MAX
    );
    let bytes = serde_json::to_string(&document()).unwrap();
    let overflow = bytes.replacen(
        "\"archive_size\":123",
        "\"archive_size\":18446744073709551616",
        1,
    );
    assert!(parse_application_manifest(overflow.as_bytes()).is_err());
}

#[test]
fn exact_versions_and_nonempty_descriptions_are_mandatory() {
    for reference in [
        "test/hello",
        "test/hello@latest",
        "test/hello@v1.0.0",
        "test/hello@01.0.0",
        "test/hello@1.0.0+build",
        "test/hello@1.0.0-01",
    ] {
        let mut value = document();
        value["reference"] = json!(reference);
        assert!(parse(&value).is_err(), "{reference}");
    }
    for description in ["", " ", "\n\t"] {
        let mut value = document();
        value["description"] = json!(description);
        assert!(parse(&value).is_err());
    }
    for reference in ["test/hello@1.0.0", "test/hello@1.0.0-rc.1"] {
        let mut value = document();
        value["reference"] = json!(reference);
        assert!(parse(&value).is_ok(), "{reference}");
    }
}

#[test]
fn bundle_digest_and_key_assertions_are_canonical_lower_hex() {
    for (field, invalid) in [
        ("archive_sha256", "A".repeat(64)),
        ("archive_sha256", "a".repeat(63)),
        ("archive_sha256", format!("sha256:{}", "a".repeat(64))),
        ("key_id", "B".repeat(32)),
        ("key_id", "b".repeat(31)),
        ("key_id", "b".repeat(64)),
        ("key_id", "g".repeat(32)),
    ] {
        let mut value = document();
        value["application"]["bundle"][field] = json!(invalid);
        assert!(parse(&value).is_err(), "{field}");
    }
    for architecture in ["x86_64", "aarch64"] {
        let mut value = document();
        value["application"]["guest_arch"] = json!(architecture);
        assert!(parse(&value).is_ok());
    }
}

#[test]
fn descriptor_bound_is_enforced_before_parsing() {
    let mut bytes = FIXTURE.to_vec();
    bytes.resize(MAX_DESCRIPTOR_BYTES, b' ');
    assert!(parse_application_manifest(&bytes).is_ok());
    bytes.push(b' ');
    assert!(parse_application_manifest(&bytes).is_err());
    for bad in [b"".as_slice(), b"not JSON".as_slice(), &[0xff]] {
        assert!(parse_application_manifest(bad).is_err());
    }
}

#[test]
fn all_39_publisher_source_vectors_have_identical_outcomes() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Vectors {
        schema_version: u32,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Case {
        source: String,
        valid: bool,
    }
    let vectors: Vectors =
        serde_json::from_str(include_str!("../application_source_vectors.json")).unwrap();
    assert_eq!(vectors.schema_version, 1);
    assert_eq!(vectors.cases.len(), 39);
    for case in vectors.cases {
        assert_eq!(
            validate_application_source(&case.source).is_ok(),
            case.valid,
            "{}",
            case.source
        );
    }
}

#[test]
fn ambiguous_hosts_credentials_and_unsupported_digests_refuse() {
    let digest = "a".repeat(64);
    for source in [
        "https://user:do-not-log@bundles.example/app".to_owned(),
        "https://bundles.example/app?do-not-log".to_owned(),
        "https://127.1/app".to_owned(),
        "https://0x7f000001/app".to_owned(),
        "https://a!b.example/app".to_owned(),
        "https://bücher.example/app".to_owned(),
        "https://bundles.example:0/app".to_owned(),
        "https://bundles.example/a/.%2E/app".to_owned(),
        format!("oci://0x7f000001/team/app@sha256:{digest}"),
        format!("oci://127.1/team/app@sha256:{digest}"),
        format!("oci://bücher.example/team/app@sha256:{digest}"),
        format!("oci://a!b.example/team/app@sha256:{digest}"),
        format!("oci://ghcr.io/team/app@sha512:{digest}"),
        format!("oci://ghcr.io/team/app@sha256:{}", "A".repeat(64)),
        format!("oci://ghcr.io/team/app@sha256:{digest}?"),
    ] {
        assert!(validate_application_source(&source).is_err(), "{source}");
    }
}

#[test]
fn parser_errors_do_not_echo_invalid_secret_bearing_inputs() {
    let mut value = document();
    value["application"]["bundle"]["source"] = json!("https://user:do-not-log@bundles.example/app");
    let error = parse(&value).unwrap_err().to_string();
    assert!(!error.contains("do-not-log"));
    assert!(!error.contains("user:"));
}

#[test]
fn descriptor_objects_cannot_be_substituted_with_positional_arrays() {
    let value = document();
    let root_array = json!([
        value["schema_version"],
        value["kind"],
        value["reference"],
        value["description"],
        value["application"]
    ]);
    assert!(parse(&root_array).is_err());

    for (pointer, fields) in [
        (
            "/application",
            vec!["schema_version", "guest_arch", "bundle"],
        ),
        (
            "/application/bundle",
            vec!["source", "archive_sha256", "archive_size", "key_id"],
        ),
    ] {
        let array: Vec<_> = fields
            .iter()
            .map(|field| value.pointer(pointer).unwrap()[*field].clone())
            .collect();
        for replacement in [
            Value::Array(array.clone()),
            json!([]),
            Value::Array([array, vec![Value::Null]].concat()),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(parse(&bad).is_err(), "{pointer}");
        }
    }
    assert!(parse(&json!([])).is_err());
    let mut too_long = root_array.as_array().unwrap().clone();
    too_long.push(Value::Null);
    assert!(parse(&Value::Array(too_long)).is_err());
}

#[test]
fn application_kind_requires_a_string_not_an_enum_object() {
    for kind in [
        json!({"application": null}),
        json!(["application"]),
        Value::Null,
    ] {
        let mut bad = document();
        bad["kind"] = kind.clone();
        assert!(parse(&bad).is_err());
        assert!(serde_json::from_value::<ApplicationManifestKind>(kind).is_err());
    }
}

#[test]
fn descriptor_rejects_trailing_data_after_an_otherwise_valid_object() {
    for suffix in [b" {}".as_slice(), b"[]", b"null", b"1"] {
        let mut bytes = FIXTURE.to_vec();
        bytes.extend_from_slice(suffix);
        assert!(parse_application_manifest(&bytes).is_err());
    }
    let mut whitespace = FIXTURE.to_vec();
    whitespace.extend_from_slice(b" \n\t\r");
    assert!(parse_application_manifest(&whitespace).is_ok());
}

#[test]
fn https_locator_table_matches_the_url_parser_it_replaced() {
    // Outcomes recorded from the previous `url`-based validator, except the
    // rows marked as intentional refusals.
    let digest = "a".repeat(64);
    let cases: &[(&str, bool)] = &[
        ("https://bundles.example/app", true),
        ("https://bundles.example/", true),
        ("https://bundles.example:8443/a/b", true),
        ("https://bundles.example:443/app", false),
        ("https://bundles.example:0443/app", false),
        ("https://bundles.example:65536/app", false),
        ("https://bundles.example:65535/app", true),
        ("https://bundles.example:/app", false),
        ("https://bundles.example:+1/app", false),
        ("https://bundles.example", false),
        ("https://", false),
        ("https:///app", false),
        ("HTTPS://bundles.example/app", false),
        ("http://bundles.example/app", false),
        ("https://Bundles.example/app", false),
        ("https://user@bundles.example/app", false),
        ("https://bundles.example/app?x", false),
        ("https://bundles.example/app?", false),
        ("https://bundles.example/app#x", false),
        ("https://bundles.example/a/./b", false),
        ("https://bundles.example/a/../b", false),
        ("https://bundles.example/a/%2e%2E/b", false),
        ("https://bundles.example/a/.%2e", false),
        ("https://bundles.example/a/...", true),
        ("https://bundles.example/a%2fb", true),
        ("https://bundles.example/a\\b", false),
        ("https://bundles.example/a b", false),
        ("https://bundles.example/a\"b", false),
        ("https://bundles.example/a<b>", false),
        ("https://bundles.example/a`b", false),
        ("https://bundles.example/a{b}", false),
        ("https://bundles.example/a^b", true),
        ("https://bundles.example/a|b[c]", true),
        ("https://bundles.example/a\u{7f}", false),
        ("https://bundles.example/a\tb", false),
        ("https://bundles.example//a", true),
        ("https://1.2.3.4/app", true),
        ("https://1.2.3.4:8080/app", true),
        ("https://1.2.3.04/app", false),
        ("https://127.1/app", false),
        ("https://[::1]/app", true),
        ("https://[::1]:8443/app", true),
        ("https://[0:0:0:0:0:0:0:1]/app", false),
        ("https://[2001:db8::1]/app", true),
        ("https://[2001:0db8::1]/app", false),
        ("https://[::ffff:1.2.3.4]/app", false),
        ("https://[::ffff:102:304]/app", true),
        ("https://[1:0:2:0:3:0:4:0]/app", true),
        ("https://[1:0:0:2:0:0:0:3]/app", false),
        ("https://[::1/app", false),
        ("https://[::1]x/app", false),
        // Intentional refusals: hosts that need IDNA conversion.
        ("https://b\u{fc}cher.example/app", false),
        ("https://xn--bcher-kva.example/app", false),
        ("https://a.xn--p1ai/app", false),
    ];
    for (source, accepted) in cases {
        assert_eq!(
            validate_application_source(source).is_ok(),
            *accepted,
            "{source}"
        );
    }
    for registry in ["xn--bcher-kva.example", "b\u{fc}cher.example"] {
        let source = format!("oci://{registry}/team/app@sha256:{digest}");
        assert!(validate_application_source(&source).is_err(), "{source}");
    }
    let oci = format!("oci://ghcr.io:443/team/app@sha256:{digest}");
    assert!(validate_application_source(&oci).is_ok());
}

#[test]
fn arbitrary_bytes_never_panic_and_accepted_locators_are_plain_ascii() {
    let alphabet = b"ab.-_:/[]@%?#\\ ^`{}<>\"09xnA~|\x00\x7f\xc3\xbc";
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..20_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let length = (state >> 59) as usize + 4;
        let mut bytes = b"https://".to_vec();
        for _ in 0..length {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push(alphabet[(state >> 33) as usize % alphabet.len()]);
        }
        let Ok(source) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if validate_application_source(source).is_ok() {
            assert!(source.is_ascii(), "{source:?}");
            let authority = source["https://".len()..].split('/').next().unwrap();
            assert!(!authority.contains('@'), "{source:?}");
        }
    }
}

#[test]
fn overlong_locators_refuse() {
    let source = format!(
        "https://bundles.example/{}",
        "a".repeat(MAX_DESCRIPTOR_BYTES)
    );
    assert!(validate_application_source(&source).is_err());
}
