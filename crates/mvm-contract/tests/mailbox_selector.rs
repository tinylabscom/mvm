use mvm_contract::protocol::mailbox::MailboxGrant;
use serde_json::{Value, json};

fn legacy() -> Value {
    json!({
        "mailbox": vec![1; 32],
        "authority_key": vec![2; 32],
        "epoch": 1
    })
}

fn profile() -> Value {
    json!({
        "version": 3,
        "descriptor_commitment": vec![3; 32],
        "owner_policy_commitment": vec![4; 32]
    })
}

#[test]
fn selector_absence_preserves_legacy_grant_bytes() {
    let old = legacy().to_string();
    let grant: MailboxGrant = serde_json::from_str(&old).unwrap();
    let bytes = serde_json::to_vec(&grant).unwrap();
    let mut null = legacy();
    null["service_blind"] = Value::Null;
    let absent: MailboxGrant = serde_json::from_value(null).unwrap();
    assert_eq!(serde_json::to_vec(&absent).unwrap(), bytes);
    assert_eq!(serde_json::to_value(grant).unwrap(), legacy());
}

#[test]
fn selector_roundtrip_preserves_exact_selected_object() {
    let mut selected = legacy();
    selected["service_blind"] = profile();
    let grant: MailboxGrant = serde_json::from_str(&selected.to_string()).unwrap();
    assert_eq!(serde_json::to_value(grant).unwrap(), selected);
}

#[test]
fn selector_refuses_wrong_versions_types_lengths_and_zero_commitments() {
    let valid = profile();
    for (field, bad) in [
        ("version", json!(1)),
        ("version", json!(4)),
        ("version", json!(3.0)),
        ("version", json!("3")),
        ("version", Value::Null),
        ("descriptor_commitment", json!(vec![0; 32])),
        ("owner_policy_commitment", json!(vec![0; 32])),
        ("descriptor_commitment", json!(vec![1; 31])),
        ("owner_policy_commitment", json!(vec![1; 33])),
        ("descriptor_commitment", json!("not an array")),
        ("owner_policy_commitment", Value::Null),
    ] {
        let mut selected = legacy();
        selected["service_blind"] = valid.clone();
        selected["service_blind"][field] = bad;
        assert!(
            serde_json::from_str::<MailboxGrant>(&selected.to_string()).is_err(),
            "{field}"
        );
        assert!(
            serde_json::from_value::<MailboxGrant>(selected).is_err(),
            "{field}"
        );
    }
    for bad in [json!(1.0), json!("1"), json!(-1), json!(256)] {
        let mut selected = legacy();
        selected["service_blind"] = valid.clone();
        selected["service_blind"]["descriptor_commitment"][0] = bad;
        assert!(serde_json::from_str::<MailboxGrant>(&selected.to_string()).is_err());
        assert!(serde_json::from_value::<MailboxGrant>(selected).is_err());
    }
}

#[test]
fn selector_refuses_missing_unknown_and_duplicate_fields_at_raw_boundary() {
    for field in [
        "version",
        "descriptor_commitment",
        "owner_policy_commitment",
    ] {
        let mut selected = legacy();
        selected["service_blind"] = profile();
        selected["service_blind"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_str::<MailboxGrant>(&selected.to_string()).is_err(),
            "{field}"
        );
    }
    let mut selected = legacy();
    selected["service_blind"] = profile();
    selected["service_blind"]["unknown"] = json!(true);
    assert!(serde_json::from_value::<MailboxGrant>(selected).is_err());

    for field in [
        r#""version":3"#.to_string(),
        r#""ver\u0073ion":3"#.to_string(),
        format!(r#""descriptor_commitment":{}"#, json!(vec![3; 32])),
        format!(r#""descriptor\u005fcommitment":{}"#, json!(vec![3; 32])),
        format!(r#""owner_policy_commitment":{}"#, json!(vec![4; 32])),
        format!(r#""owner_policy\u005fcommitment":{}"#, json!(vec![4; 32])),
    ] {
        let raw_profile = profile().to_string();
        let duplicate = format!("{{{field},{}", &raw_profile[1..]);
        let raw = format!(
            r#"{{"service_blind":{duplicate},{}"#,
            &legacy().to_string()[1..]
        );
        assert!(
            serde_json::from_str::<MailboxGrant>(&raw).is_err(),
            "{field}"
        );
    }
    let raw = format!(
        r#"{{"service_blind":{},"service\u005fblind":null,{}"#,
        profile(),
        &legacy().to_string()[1..]
    );
    assert!(serde_json::from_str::<MailboxGrant>(&raw).is_err());
}

#[test]
fn selector_cannot_be_constructed_with_absent_commitments_or_decoded_from_other_shapes() {
    use mvm_contract::protocol::mailbox::service_blind::LaunchProfile;
    assert!(LaunchProfile::new([0; 32], [1; 32]).is_err());
    assert!(LaunchProfile::new([1; 32], [0; 32]).is_err());
    for shape in [json!([]), json!("v3"), json!(3), json!(true)] {
        let mut selected = legacy();
        selected["service_blind"] = shape;
        assert!(serde_json::from_str::<MailboxGrant>(&selected.to_string()).is_err());
    }
}
