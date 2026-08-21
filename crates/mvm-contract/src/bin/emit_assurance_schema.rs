//! Emit the versioned assurance request/result and generic extension schemas.

fn main() {
    let document = serde_json::json!({
        "mvm.assurance.ai-session-request/v1":
            schemars::schema_for!(mvm_contract::assurance::AssuranceSessionRequest),
        "mvm.security.campaign-request/v1":
            schemars::schema_for!(mvm_contract::assurance::CampaignProviderRequest),
        "mvm.assurance.operator-session-bundle/v1":
            schemars::schema_for!(mvm_contract::assurance::OperatorSessionBundle),
        "mvm.security.provider-response/v1":
            schemars::schema_for!(mvm_contract::assurance::CampaignProviderResponse),
        "mvm.assurance.trial-result/v1":
            schemars::schema_for!(mvm_contract::assurance::TrialResultDocument),
        "mvm.extension-pack/v1":
            schemars::schema_for!(mvm_contract::protocol::extension_pack::ExtensionPackContract),
    });
    let json =
        serde_json::to_string_pretty(&document).expect("serialize assurance and extension schemas");
    println!("{json}");
}
