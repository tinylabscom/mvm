//! The certificate identity a CI workflow signs under, taken apart.
//!
//! A GitHub Actions keyless signature carries one subject alternative name:
//! `https://github.com/<owner>/<repo>/<workflow path>@<git ref>`. It is the
//! same shape the release trust root interpolates its own templates into; a
//! publisher here names the three parts separately so the ref can be a
//! pattern (`refs/tags/v*`) while the repository and workflow stay exact.

/// The only identity host a keyless publisher is matched under.
const GITHUB_IDENTITY_PREFIX: &str = "https://github.com/";

/// Directory every GitHub Actions workflow file lives under.
pub(crate) const WORKFLOW_DIR_PREFIX: &str = ".github/workflows/";

/// A workflow identity split into the parts a publisher constrains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkflowIdentity<'a> {
    /// `owner/repo`.
    pub repository: &'a str,
    /// The workflow file, e.g. `.github/workflows/sign-instructions.yml`.
    pub workflow: &'a str,
    /// The ref the workflow ran under, e.g. `refs/heads/main`.
    pub git_ref: &'a str,
}

/// Split a certificate SAN into its workflow parts.
///
/// `None` for anything that is not a GitHub workflow identity — an e-mail
/// SAN, another forge, a path outside `.github/workflows/`. Such a signer
/// cannot match a keyless publisher, which is the answer the caller needs.
/// The ref is everything after the first `@`: an owner, repository or
/// workflow path cannot contain one, and a ref may.
pub(crate) fn parse_workflow_identity(san: &str) -> Option<WorkflowIdentity<'_>> {
    let rest = san.strip_prefix(GITHUB_IDENTITY_PREFIX)?;
    let (path, git_ref) = rest.split_once('@')?;
    let (owner, after_owner) = path.split_once('/')?;
    let (repo, workflow) = after_owner.split_once('/')?;
    if owner.is_empty()
        || repo.is_empty()
        || git_ref.is_empty()
        || !workflow.starts_with(WORKFLOW_DIR_PREFIX)
        || workflow.len() == WORKFLOW_DIR_PREFIX.len()
    {
        return None;
    }
    Some(WorkflowIdentity {
        repository: &path[..owner.len() + 1 + repo.len()],
        workflow,
        git_ref,
    })
}

/// The SAN a workflow signs under, for display and for exact matching.
#[must_use]
pub(crate) fn workflow_identity(repository: &str, workflow: &str, git_ref: &str) -> String {
    format!("{GITHUB_IDENTITY_PREFIX}{repository}/{workflow}@{git_ref}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_workflow_identity_splits_into_its_parts() {
        let san =
            "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.18.0";
        assert_eq!(
            parse_workflow_identity(san),
            Some(WorkflowIdentity {
                repository: "tinylabscom/mvm",
                workflow: ".github/workflows/release.yml",
                git_ref: "refs/tags/v0.18.0",
            })
        );
    }

    #[test]
    fn composing_and_splitting_round_trip() {
        let san = workflow_identity(
            "acme/agents",
            ".github/workflows/sign-instructions.yml",
            "refs/heads/release/1.0",
        );
        let parts = parse_workflow_identity(&san).expect("round-trips");
        assert_eq!(parts.repository, "acme/agents");
        assert_eq!(parts.workflow, ".github/workflows/sign-instructions.yml");
        assert_eq!(parts.git_ref, "refs/heads/release/1.0");
    }

    #[test]
    fn identities_that_are_not_github_workflows_do_not_parse() {
        for san in [
            "someone@example.test",
            "https://gitlab.example.test/acme/agents/.github/workflows/x.yml@refs/heads/main",
            "https://github.com/acme/agents/scripts/sign.sh@refs/heads/main",
            "https://github.com/acme/agents/.github/workflows/@refs/heads/main",
            "https://github.com/acme/agents/.github/workflows/x.yml",
            "https://github.com/acme/agents/.github/workflows/x.yml@",
            "https://github.com//agents/.github/workflows/x.yml@refs/heads/main",
        ] {
            assert_eq!(parse_workflow_identity(san), None, "{san}");
        }
    }
}
