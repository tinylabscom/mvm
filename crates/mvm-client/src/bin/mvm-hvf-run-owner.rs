//! Refusal-only protected HVF owner process boundary.
//!
//! This binary deliberately has no admission, signer, backend or VM factory.

use std::io::{Read, Write};

use anyhow::{Context as _, Result, ensure};
use mvm_contract::protocol::hvf_entrypoint_owner::{
    MAX_BOOTSTRAP_BYTES, OwnerBootstrap, OwnerBootstrapResponse, VERSION,
};

fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("mvm-hvf-run-owner aborted");
    }));
    ensure!(
        std::env::args_os().len() == 1,
        "mvm-hvf-run-owner accepts no arguments"
    );
    serve_refusal(std::io::stdin().lock(), std::io::stdout().lock())
}

fn serve_refusal(mut input: impl Read, mut output: impl Write) -> Result<()> {
    let mut length = [0u8; 4];
    input
        .read_exact(&mut length)
        .context("read owner bootstrap length")?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .context("owner bootstrap length does not fit this host")?;
    ensure!(
        length > 0 && length <= MAX_BOOTSTRAP_BYTES,
        "owner bootstrap exceeds bound"
    );
    let mut bytes = vec![0; length];
    input
        .read_exact(&mut bytes)
        .context("read owner bootstrap")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("decode owner bootstrap")?;
    ensure!(value.is_object(), "owner bootstrap must be an object");
    let bootstrap: OwnerBootstrap =
        serde_json::from_value(value).context("decode owner bootstrap")?;
    validate(&bootstrap)?;

    let response = serde_json::to_vec(&OwnerBootstrapResponse::OwnerFactoryDisabled {})?;
    let length: u32 = response
        .len()
        .try_into()
        .context("owner refusal response exceeds frame")?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(&response)?;
    output.flush()?;
    Ok(())
}

fn validate(bootstrap: &OwnerBootstrap) -> Result<()> {
    ensure!(bootstrap.version == VERSION, "unsupported owner bootstrap");
    ensure!(
        bootstrap.provider_id != [0; 32]
            && bootstrap.grant_id != [0; 32]
            && bootstrap.operation_id != [0; 32]
            && bootstrap.owner_incarnation != [0; 32]
            && bootstrap.request_digest != [0; 32],
        "invalid owner bootstrap binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn bootstrap() -> OwnerBootstrap {
        OwnerBootstrap {
            version: VERSION,
            provider_id: [1; 32],
            grant_id: [2; 32],
            operation_id: [3; 32],
            owner_incarnation: [4; 32],
            request_digest: [5; 32],
        }
    }

    fn frame(value: &impl serde::Serialize) -> Vec<u8> {
        let bytes = serde_json::to_vec(value).unwrap();
        let mut frame = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        frame.extend(bytes);
        frame
    }

    #[test]
    fn exact_bootstrap_returns_only_factory_disabled() {
        let mut output = Vec::new();
        serve_refusal(Cursor::new(frame(&bootstrap())), &mut output).unwrap();
        let length = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(length, output.len() - 4);
        assert_eq!(
            serde_json::from_slice::<OwnerBootstrapResponse>(&output[4..]).unwrap(),
            OwnerBootstrapResponse::OwnerFactoryDisabled {}
        );
    }

    #[test]
    fn oversized_truncated_unknown_version_and_changed_binding_refuse_without_output() {
        let mut cases = vec![
            0u32.to_be_bytes().to_vec(),
            u32::try_from(MAX_BOOTSTRAP_BYTES + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            {
                let mut value = frame(&bootstrap());
                value.pop();
                value
            },
            {
                let mut value = bootstrap();
                value.version += 1;
                frame(&value)
            },
        ];
        for mutate in [
            |value: &mut OwnerBootstrap| value.provider_id = [0; 32],
            |value: &mut OwnerBootstrap| value.grant_id = [0; 32],
            |value: &mut OwnerBootstrap| value.operation_id = [0; 32],
            |value: &mut OwnerBootstrap| value.owner_incarnation = [0; 32],
            |value: &mut OwnerBootstrap| value.request_digest = [0; 32],
        ] {
            let mut value = bootstrap();
            mutate(&mut value);
            cases.push(frame(&value));
        }
        cases.push(frame(&serde_json::json!({
            "version": VERSION,
            "provider_id": vec![1;32],
            "grant_id": vec![2;32],
            "operation_id": vec![3;32],
            "owner_incarnation": vec![4;32],
            "request_digest": vec![5;32],
            "path": "/tmp/forbidden"
        })));
        cases.push(frame(&serde_json::json!([
            VERSION,
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
            vec![5; 32]
        ])));
        for input in cases {
            let mut output = Vec::new();
            assert!(serve_refusal(Cursor::new(input), &mut output).is_err());
            assert!(output.is_empty());
        }
    }
}
