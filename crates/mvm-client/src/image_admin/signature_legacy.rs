//! Translate the legacy OCI layer annotations without changing the signed
//! payload or weakening the offline verifier's transparency requirements.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::signature_registry::read_body;

const REKOR: &str = "https://rekor.sigstore.dev";

async fn rekor_json(request: mvm_http::RequestBuilder) -> Result<Value> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let response = request.send().await.context("acquire Rekor evidence")?;
        if !response.status().is_success() {
            return Err(super::trust::CosignVerifyError::AcquisitionFailed(format!(
                "Rekor evidence request returned {}",
                response.status()
            ))
            .into());
        }
        serde_json::from_slice(&read_body(response).await?).context("parse Rekor evidence")
    })
    .await
    .map_err(|_| {
        super::trust::CosignVerifyError::AcquisitionFailed(
            "Rekor evidence request exceeded 30 seconds".to_string(),
        )
    })?
}

pub(super) async fn bundles(payload: &[u8], annotations: &Value) -> Result<Vec<Vec<u8>>> {
    bundles_with_rekor(payload, annotations, REKOR).await
}

async fn bundles_with_rekor(
    payload: &[u8],
    annotations: &Value,
    rekor: &str,
) -> Result<Vec<Vec<u8>>> {
    if annotations["dev.sigstore.cosign/bundle"]
        .as_str()
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(vec![bundle_with_rekor(payload, annotations, rekor).await?]);
    }
    let signature = string(annotations, "dev.cosignproject.cosign/signature")?;
    let certificate = string(annotations, "dev.sigstore.cosign/certificate")?;
    let proposed = json!({
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": hex::encode(Sha256::digest(payload))}},
            "signature": {
                "content": signature,
                "publicKey": {"content": STANDARD.encode(certificate.as_bytes())}
            }
        }
    });
    let request = mvm_http::Client::new()
        .post(format!("{rekor}/api/v1/log/entries/retrieve"))
        .json(&json!({"entries": [proposed]}));
    let response = rekor_json(request).await?;
    let groups = response
        .as_array()
        .context("Rekor search response must be an array")?;
    ensure!(groups.len() <= 128, "too many Rekor search results");
    let mut bundles = Vec::new();
    let mut failures = Vec::new();
    let mut count = 0usize;
    for group in groups {
        let Some(entries) = group.as_object() else {
            failures.push("Rekor result must be an entry map".to_string());
            continue;
        };
        for (uuid, entry) in entries {
            count += 1;
            ensure!(count <= 128, "too many Rekor search entries");
            let candidate = annotations_for_entry(payload, annotations, uuid, entry);
            match candidate {
                Ok(candidate) => match bundle_with_rekor(payload, &candidate, rekor).await {
                    Ok(bundle) => bundles.push(bundle),
                    Err(error) => failures.push(format!("{error:#}")),
                },
                Err(error) => failures.push(format!("{error:#}")),
            }
        }
    }
    ensure!(
        !bundles.is_empty(),
        "no matching Rekor inclusion evidence: {}",
        failures.join("; ")
    );
    Ok(bundles)
}

fn annotations_for_entry(
    payload: &[u8],
    annotations: &Value,
    uuid: &str,
    entry: &Value,
) -> Result<Value> {
    let body = STANDARD.decode(string(entry, "body")?)?;
    let mut leaf = Sha256::new();
    leaf.update([0]);
    leaf.update(&body);
    ensure!(
        matches!(uuid.len(), 64 | 80) && uuid.ends_with(&hex::encode(leaf.finalize())),
        "Rekor entry UUID does not match its body"
    );
    let logged: Value = serde_json::from_slice(&body)?;
    ensure!(
        logged["kind"] == "hashedrekord" && logged["apiVersion"] == "0.0.1",
        "unexpected Rekor entry kind"
    );
    let spec = &logged["spec"];
    ensure!(
        spec["data"]["hash"]["algorithm"] == "sha256"
            && spec["data"]["hash"]["value"].as_str()
                == Some(hex::encode(Sha256::digest(payload)).as_str()),
        "Rekor entry is for another payload"
    );
    ensure!(
        STANDARD.decode(string(&spec["signature"], "content")?)?
            == STANDARD.decode(string(annotations, "dev.cosignproject.cosign/signature")?)?,
        "Rekor entry is for another signature"
    );
    let logged_certificate =
        STANDARD.decode(string(&spec["signature"]["publicKey"], "content")?)?;
    ensure!(
        certificate_der(std::str::from_utf8(&logged_certificate)?)?
            == certificate_der(string(annotations, "dev.sigstore.cosign/certificate")?)?,
        "Rekor entry is for another certificate"
    );
    let proof = entry["verification"]
        .get("inclusionProof")
        .context("Rekor search result has no inclusion proof")?;
    let legacy = json!({
        "SignedEntryTimestamp": string(&entry["verification"], "signedEntryTimestamp")?,
        "Payload": {
            "body": entry["body"],
            "logID": entry["logID"],
            "logIndex": entry["logIndex"],
            "integratedTime": entry["integratedTime"],
            "inclusionProof": proof
        }
    });
    let mut candidate = annotations.clone();
    candidate["dev.sigstore.cosign/bundle"] = Value::String(legacy.to_string());
    Ok(candidate)
}

pub(super) async fn bundle_with_rekor(
    payload: &[u8],
    annotations: &Value,
    rekor: &str,
) -> Result<Vec<u8>> {
    let signature = string(annotations, "dev.cosignproject.cosign/signature")?;
    STANDARD
        .decode(signature)
        .context("decode legacy signature")?;
    let certificate = certificate_der(string(annotations, "dev.sigstore.cosign/certificate")?)?;
    let legacy: Value = serde_json::from_str(string(annotations, "dev.sigstore.cosign/bundle")?)
        .context("parse legacy Rekor bundle")?;
    let entry = legacy
        .get("Payload")
        .context("missing legacy Rekor payload")?;
    let body = string(entry, "body")?;
    let body_json: Value = serde_json::from_slice(&STANDARD.decode(body)?)?;
    let index = entry["logIndex"]
        .as_u64()
        .context("missing Rekor log index")?;
    let log_id = string(entry, "logID")?;
    let integrated_time = entry["integratedTime"]
        .as_u64()
        .context("missing Rekor integrated time")?;

    // The old annotation normally contains only a signed entry timestamp.
    // A promise is not inclusion: acquire the proof, then let the existing
    // verifier authenticate its checkpoint and Merkle path.
    let proof = if let Some(proof) = entry.get("inclusionProof") {
        proof.clone()
    } else {
        let response = rekor_json(
            mvm_http::Client::new().get(format!("{rekor}/api/v1/log/entries?logIndex={index}")),
        )
        .await?;
        let entries = response
            .as_object()
            .context("Rekor response must be an entry map")?;
        let matched = entries
            .values()
            .find(|candidate| {
                candidate["logIndex"].as_u64() == Some(index)
                    && candidate["logID"].as_str() == Some(log_id)
                    && candidate["integratedTime"].as_u64() == Some(integrated_time)
                    && candidate["body"].as_str() == Some(body)
            })
            .context("Rekor response does not match the signature's logged entry")?;
        matched["verification"]
            .get("inclusionProof")
            .context("Rekor response has no inclusion proof")?
            .clone()
    };
    let hashes = proof["hashes"]
        .as_array()
        .context("missing inclusion hashes")?
        .iter()
        .map(|hash| {
            Ok(STANDARD.encode(hex::decode(
                hash.as_str().context("invalid inclusion hash")?,
            )?))
        })
        .collect::<Result<Vec<_>>>()?;
    let checkpoint = string(&proof, "checkpoint")?;
    ensure!(!checkpoint.is_empty(), "missing signed Rekor checkpoint");
    let normalized = json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": STANDARD.encode(certificate)},
            "tlogEntries": [{
                "logIndex": index.to_string(),
                "logId": {"keyId": STANDARD.encode(hex::decode(log_id)?)},
                "kindVersion": {
                    "kind": string(&body_json, "kind")?,
                    "version": string(&body_json, "apiVersion")?
                },
                "integratedTime": integrated_time.to_string(),
                "inclusionPromise": {
                    "signedEntryTimestamp": string(&legacy, "SignedEntryTimestamp")?
                },
                "inclusionProof": {
                    "logIndex": proof["logIndex"].as_u64().context("missing proof index")?.to_string(),
                    "treeSize": proof["treeSize"].as_u64().context("missing proof tree size")?.to_string(),
                    "rootHash": STANDARD.encode(hex::decode(string(&proof, "rootHash")?)?),
                    "hashes": hashes,
                    "checkpoint": {"envelope": checkpoint}
                },
                "canonicalizedBody": body
            }]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": STANDARD.encode(Sha256::digest(payload))
            },
            "signature": signature
        }
    });
    serde_json::to_vec(&normalized).context("serialize normalized legacy bundle")
}

fn certificate_der(pem: &str) -> Result<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----"))
        .context("legacy signing certificate must be one PEM certificate")?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = STANDARD
        .decode(compact)
        .context("decode signing certificate")?;
    if der.is_empty() {
        bail!("empty signing certificate");
    }
    Ok(der)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing signature material field {key}"))
}

#[cfg(all(test, feature = "manifest-verify"))]
mod tests {
    use super::*;
    use mvm_fs::oci::test_registry::MemoryRegistry;

    struct Fixture {
        payload: Vec<u8>,
        annotations: Value,
        entry: Value,
        index: u64,
    }

    // Reuse the checked-in release's real Fulcio/Rekor material. This tests
    // the wire normalization, not OCI claim semantics: these signed bytes
    // are a checksum document and must not pass an OCI claim check.
    fn fixture() -> Fixture {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");
        let payload = std::fs::read(root.join("builder-vm-aarch64-checksums-sha256.txt")).unwrap();
        let bundle: Value = serde_json::from_slice(
            &std::fs::read(root.join("builder-vm-aarch64-checksums-sha256.txt.bundle")).unwrap(),
        )
        .unwrap();
        let log = &bundle["verificationMaterial"]["tlogEntries"][0];
        let integer = |value: &Value| value.as_str().unwrap().parse::<u64>().unwrap();
        let unbase64 =
            |value: &Value| hex::encode(STANDARD.decode(value.as_str().unwrap()).unwrap());
        let index = integer(&log["logIndex"]);
        let entry = json!({
            "body": log["canonicalizedBody"],
            "logIndex": index,
            "logID": unbase64(&log["logId"]["keyId"]),
            "integratedTime": integer(&log["integratedTime"]),
            "verification": {
                "signedEntryTimestamp": log["inclusionPromise"]["signedEntryTimestamp"],
                "inclusionProof": {
                    "logIndex": integer(&log["inclusionProof"]["logIndex"]),
                    "treeSize": integer(&log["inclusionProof"]["treeSize"]),
                    "rootHash": unbase64(&log["inclusionProof"]["rootHash"]),
                    "hashes": log["inclusionProof"]["hashes"].as_array().unwrap()
                        .iter().map(unbase64).collect::<Vec<_>>(),
                    "checkpoint": log["inclusionProof"]["checkpoint"]["envelope"]
                }
            }
        });
        let legacy = json!({
            "SignedEntryTimestamp": log["inclusionPromise"]["signedEntryTimestamp"],
            "Payload": {
                "body": entry["body"],
                "logIndex": entry["logIndex"],
                "logID": entry["logID"],
                "integratedTime": entry["integratedTime"]
            }
        });
        let annotations = json!({
            "dev.cosignproject.cosign/signature": bundle["messageSignature"]["signature"],
            "dev.sigstore.cosign/certificate": format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                bundle["verificationMaterial"]["certificate"]["rawBytes"].as_str().unwrap()
            ),
            "dev.sigstore.cosign/bundle": legacy.to_string()
        });
        Fixture {
            payload,
            annotations,
            entry,
            index,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn proof_server(fixture: &Fixture) -> MemoryRegistry {
        let server = MemoryRegistry::start();
        server.respond_to_get(
            &format!("/v2/rekor/api/v1/log/entries?logIndex={}", fixture.index),
            200,
            &serde_json::to_vec(&json!({"fixture-entry": fixture.entry})).unwrap(),
            &[("Content-Type", "application/json")],
        );
        server
    }

    fn entry_uuid(entry: &Value) -> String {
        let mut hash = Sha256::new();
        hash.update([0]);
        hash.update(STANDARD.decode(entry["body"].as_str().unwrap()).unwrap());
        hex::encode(hash.finalize())
    }

    #[test]
    fn unbundled_real_signature_searches_rekor_and_ignores_a_bad_first_entry() {
        let mut fixture = fixture();
        fixture
            .annotations
            .as_object_mut()
            .unwrap()
            .remove("dev.sigstore.cosign/bundle");
        let server = MemoryRegistry::start();
        let uuid = entry_uuid(&fixture.entry);
        server.respond_to_post(
            "/v2/rekor/api/v1/log/entries/retrieve",
            200,
            &serde_json::to_vec(&json!([
                {"invalid-entry": fixture.entry},
                {uuid: fixture.entry}
            ]))
            .unwrap(),
        );
        let bundles = runtime()
            .block_on(bundles_with_rekor(
                &fixture.payload,
                &fixture.annotations,
                &format!("http://{}/v2/rekor", server.host()),
            ))
            .unwrap();
        assert_eq!(bundles.len(), 1);
        mvm_core::crypto::image_verify::verify_signed_payload(
            &fixture.payload,
            &bundles[0],
            &mvm_core::release_trust::accepted_release_identities("0.18.0-rc.1")[0],
            mvm_core::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect("unbundled legacy search preserves real signature verification");
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert!(requests[0].authorization.is_none());
    }

    #[test]
    fn searched_entry_must_bind_the_exact_payload_signature_and_certificate() {
        let fixture = fixture();
        let uuid = entry_uuid(&fixture.entry);
        let mut changed_payload = fixture.payload.clone();
        changed_payload.push(b'\n');
        annotations_for_entry(
            &changed_payload,
            &fixture.annotations,
            &uuid,
            &fixture.entry,
        )
        .expect_err("entry for another payload");
        let mut annotations = fixture.annotations.clone();
        annotations["dev.cosignproject.cosign/signature"] =
            json!(STANDARD.encode(b"another signature"));
        annotations_for_entry(&fixture.payload, &annotations, &uuid, &fixture.entry)
            .expect_err("entry for another signature");
        annotations = fixture.annotations.clone();
        annotations["dev.sigstore.cosign/certificate"] =
            json!("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----");
        annotations_for_entry(&fixture.payload, &annotations, &uuid, &fixture.entry)
            .expect_err("entry for another certificate");
    }

    #[test]
    fn real_signature_normalization_fetches_and_verifies_the_missing_inclusion_proof() {
        let fixture = fixture();
        let server = proof_server(&fixture);
        let bundle = runtime()
            .block_on(bundle_with_rekor(
                &fixture.payload,
                &fixture.annotations,
                &format!("http://{}/v2/rekor", server.host()),
            ))
            .unwrap();
        let identity = &mvm_core::release_trust::accepted_release_identities("0.18.0-rc.1")[0];
        mvm_core::crypto::image_verify::verify_signed_payload(
            &fixture.payload,
            &bundle,
            identity,
            mvm_core::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect("real payload/certificate/signature/log proof survive normalization");
        assert_eq!(server.requests().len(), 1);
        assert!(server.requests()[0].authorization.is_none());

        let mut tampered = fixture.payload.clone();
        tampered.push(b'\n');
        mvm_core::crypto::image_verify::verify_signed_payload(
            &tampered,
            &bundle,
            identity,
            mvm_core::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("signed bytes remain bound");
        mvm_core::crypto::image_verify::verify_signed_payload(
            &fixture.payload,
            &bundle,
            "another identity",
            mvm_core::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("exact identity remains required");
        mvm_core::crypto::image_verify::verify_signed_payload(
            &fixture.payload,
            &bundle,
            identity,
            "https://wrong-issuer.example.test",
        )
        .expect_err("exact issuer remains required");
    }

    #[test]
    fn a_real_set_alone_is_not_accepted_when_rekor_cannot_supply_inclusion() {
        let fixture = fixture();
        let server = MemoryRegistry::start();
        runtime()
            .block_on(bundle_with_rekor(
                &fixture.payload,
                &fixture.annotations,
                &format!("http://{}/v2/rekor", server.host()),
            ))
            .expect_err("404 cannot turn a SET into inclusion");
    }

    #[test]
    fn a_real_set_does_not_override_a_tampered_inclusion_proof() {
        let mut fixture = fixture();
        fixture.entry["verification"]["inclusionProof"]["rootHash"] = json!("00".repeat(32));
        let server = proof_server(&fixture);
        let bundle = runtime()
            .block_on(bundle_with_rekor(
                &fixture.payload,
                &fixture.annotations,
                &format!("http://{}/v2/rekor", server.host()),
            ))
            .unwrap();
        mvm_core::crypto::image_verify::verify_signed_payload(
            &fixture.payload,
            &bundle,
            &mvm_core::release_trust::accepted_release_identities("0.18.0-rc.1")[0],
            mvm_core::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("a genuine signed entry timestamp cannot override a bad proof");
    }

    #[test]
    fn a_proof_for_another_logged_entry_is_not_attached_to_the_signature() {
        let mut fixture = fixture();
        fixture.entry["body"] = json!(STANDARD.encode(b"another entry"));
        let server = proof_server(&fixture);
        let error = runtime()
            .block_on(bundle_with_rekor(
                &fixture.payload,
                &fixture.annotations,
                &format!("http://{}/v2/rekor", server.host()),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }
}
