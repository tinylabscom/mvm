//! Parser regressions retained at the CLI boundary.

#![cfg(test)]

use super::{parse_declared_secrets, validated_checkpoint_id};

#[test]
fn validated_checkpoint_id_accepts_normal() {
    assert!(validated_checkpoint_id("ckpt-myvm-1700000000").is_ok());
    assert!(validated_checkpoint_id("fork-child-42").is_ok());
}

#[test]
fn validated_checkpoint_id_rejects_traversal() {
    assert!(validated_checkpoint_id("../etc").is_err());
    assert!(validated_checkpoint_id("a/b").is_err());
    assert!(validated_checkpoint_id("a\\b").is_err());
    assert!(validated_checkpoint_id("").is_err());
    assert!(validated_checkpoint_id("a\0b").is_err());
    assert!(validated_checkpoint_id("a\nb").is_err());
}

#[test]
fn bare_secret_name_binds_var_and_address_alike() {
    let got = parse_declared_secrets(&["STRIPE_KEY".to_string()]).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "STRIPE_KEY");
    assert_eq!(
        got[0].source,
        mvm_core::plan::SecretSource::Keystore {
            address: "STRIPE_KEY".to_string()
        }
    );
}

#[test]
fn var_equals_address_separates_the_two() {
    let got = parse_declared_secrets(&["DB_PASSWORD=prod/db/password".to_string()]).unwrap();
    assert_eq!(got[0].name, "DB_PASSWORD");
    assert_eq!(
        got[0].source,
        mvm_core::plan::SecretSource::Keystore {
            address: "prod/db/password".to_string()
        }
    );
}

#[test]
fn an_empty_half_is_refused() {
    for bad in ["", "=addr", "VAR=", "  =  "] {
        assert!(
            parse_declared_secrets(&[bad.to_string()]).is_err(),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn declaring_nothing_parses_to_nothing() {
    assert!(parse_declared_secrets(&[]).unwrap().is_empty());
}
