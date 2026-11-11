"""SDK policy models are generated from the Rust-authored contract."""

import mvm


def test_public_policy_profile_carries_composition_and_rules() -> None:
    profile = mvm.policy.ProfileFile(
        extends=["base"],
        groups=mvm.policy.GroupSelection(include=["required"]),
        when=[
            mvm.policy.WhenBlock(
                os=mvm.policy.HostOs.linux,
                overrides=mvm.policy.PolicyBody(
                    network=mvm.policy.NetworkSection(deny=["blocked.test"])
                ),
            )
        ],
    )
    assert profile.extends == ["base"]
    assert profile.groups.include == ["required"]
    assert profile.when[0].overrides.network.deny == ["blocked.test"]
