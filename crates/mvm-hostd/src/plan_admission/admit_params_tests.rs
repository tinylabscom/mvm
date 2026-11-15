#![cfg(test)]

use super::admit_params::AdmitAndStartParams;
use mvm_contract::builder::BuilderError;

/// An empty builder must refuse to finish, naming the first
/// required field it is missing — never substituting a default.
#[test]
fn an_empty_builder_names_the_first_missing_field() {
    let Err(err) = AdmitAndStartParams::builder().build() else {
        panic!("an empty AdmitAndStartParams builder must not build");
    };
    assert_eq!(
        err,
        BuilderError::missing("AdmitAndStartParams", "synthesis")
    );
}
