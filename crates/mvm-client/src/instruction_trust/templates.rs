//! Starter policies written by `mvmctl trust instructions init`.
//!
//! Rendered as commented TOML rather than serialized, because the comments are
//! the documentation an operator reads when they open the file. Both templates
//! are parsed back in the tests, so a template can never ship a policy the
//! parser refuses.

use super::policy::{DEFAULT_INCLUDES, Enforcement, GITHUB_ACTIONS_ISSUER};

/// The name `init` gives the keyed publisher for this host's signing key.
pub const HOST_PUBLISHER_NAME: &str = "this-host";

/// A user policy trusting this host's signing key, with a commented keyless
/// example beside it.
#[must_use]
pub fn user_policy(enforcement: Enforcement, host_public_key_hex: &str) -> String {
    format!(
        "# Instruction-file trust policy (user). Authoritative: a project policy\n\
         # may tighten it, never loosen it. Reference: `mvmctl trust instructions policy`.\n\
         \n\
         # deny: refuse to boot when an instruction file copied into the guest fails\n\
         # verification. warn: print and boot. audit: record only.\n\
         enforcement = \"{enforcement}\"\n\
         \n\
         # Which files are instruction files, relative to each scanned root.\n\
         # Omit to use the built-in list shown here.\n\
         includes = [\n{includes}]\n\
         \n\
         # This host's signing key. `mvmctl trust instructions sign <path>` signs\n\
         # with it by default.\n\
         [[publishers]]\n\
         kind = \"keyed\"\n\
         name = \"{HOST_PUBLISHER_NAME}\"\n\
         public_key = \"{host_public_key_hex}\"\n\
         \n\
         # A CI workflow signing keylessly (see the sign-instructions workflow):\n\
         # [[publishers]]\n\
         # kind = \"keyless\"\n\
         # name = \"ci\"\n\
         # issuer = \"{GITHUB_ACTIONS_ISSUER}\"\n\
         # repository = \"owner/repo\"\n\
         # workflow = \".github/workflows/sign-instructions.yml\"\n\
         # ref = \"refs/heads/main\"\n\
         \n\
         # Digests refused whoever signed them:\n\
         # [[blocklist]]\n\
         # sha256 = \"<64 hex characters>\"\n\
         # reason = \"why\"\n",
        enforcement = enforcement.as_str(),
        includes = DEFAULT_INCLUDES
            .iter()
            .map(|pattern| format!("  \"{pattern}\",\n"))
            .collect::<String>(),
    )
}

/// A project policy. It can only add restrictions to the user's policy, and
/// alone it is advisory.
#[must_use]
pub fn project_policy(enforcement: Enforcement) -> String {
    format!(
        "# Instruction-file trust policy (project). This file can only tighten the\n\
         # user's policy: raise enforcement, add include patterns, block digests, or\n\
         # narrow the user's publishers to the ones listed here. With no user policy\n\
         # it is advisory and its findings only warn.\n\
         enforcement = \"{}\"\n\
         \n\
         # Extra instruction files this project carries, beyond the user's list:\n\
         # includes = [\"prompts/**/*.md\"]\n",
        enforcement.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::super::policy::{InstructionTrustPolicy, Publisher};
    use super::*;

    #[test]
    fn the_user_template_parses_to_the_policy_it_describes() {
        let key = "ab".repeat(32);
        let policy =
            InstructionTrustPolicy::from_toml_str(&user_policy(Enforcement::Deny, &key)).unwrap();
        assert_eq!(policy.enforcement, Some(Enforcement::Deny));
        assert_eq!(
            policy.includes.as_deref().map(<[String]>::len),
            Some(DEFAULT_INCLUDES.len())
        );
        assert_eq!(
            policy.publishers,
            vec![Publisher::Keyed {
                name: HOST_PUBLISHER_NAME.to_string(),
                key_id: None,
                public_key: Some(key),
            }]
        );
    }

    #[test]
    fn the_project_template_parses_and_names_no_publisher() {
        let policy =
            InstructionTrustPolicy::from_toml_str(&project_policy(Enforcement::Warn)).unwrap();
        assert_eq!(policy.enforcement, Some(Enforcement::Warn));
        assert!(policy.publishers.is_empty());
        assert!(policy.includes.is_none());
    }
}
