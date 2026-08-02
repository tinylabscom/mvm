//! Authenticated mvmd-backed volume lifecycle commands.

use anyhow::{Context, Result, bail};
use mvm_core::client::gateway::{
    GatewayBackend, GatewayConfig, RemoteVolume, RemoteVolumeCreate, RemoteVolumeMount,
};
use mvm_core::crypto::policy::validate_mount_path;

struct RemoteContext {
    client: GatewayBackend,
    tenant_id: String,
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("{name} is required for --remote volume operations"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty for --remote volume operations");
    }
    Ok(value)
}

fn context() -> Result<RemoteContext> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let base_url = required_env("MVM_GATEWAY_URL")?;
    let token = required_env("MVM_GATEWAY_TOKEN")?;
    let tenant_id = required_env("MVM_TENANT_ID")?;
    let client =
        GatewayBackend::new(GatewayConfig { base_url, token }).map_err(anyhow::Error::from)?;
    Ok(RemoteContext { client, tenant_id })
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building remote volume client runtime")
}

fn size_gib(size: &str) -> Result<u32> {
    let size_mib = mvm_core::util::parse_human_size(size)
        .with_context(|| format!("invalid remote volume size {size:?}"))?;
    if size_mib == 0 {
        bail!("remote volume size must be at least 1 MiB");
    }
    Ok(size_mib.div_ceil(1024))
}

pub(super) fn create(
    volume_name: &str,
    size: &str,
    bucket: Option<&str>,
    storage_class: Option<&str>,
) -> Result<()> {
    let context = context()?;
    let mut builder = RemoteVolumeCreate::builder(volume_name, size_gib(size)?);
    if let Some(bucket) = bucket {
        builder = builder.bucket(bucket);
    }
    if let Some(storage_class) = storage_class {
        builder = builder.storage_class(storage_class);
    }
    let request = builder.build().map_err(anyhow::Error::from)?;
    let volume = runtime()?
        .block_on(
            context
                .client
                .create_remote_volume(&context.tenant_id, &request),
        )
        .map_err(anyhow::Error::from)?;
    println!("{}", serde_json::to_string_pretty(&volume)?);
    Ok(())
}

pub(super) fn catalog(json: bool) -> Result<()> {
    let context = context()?;
    let volumes = runtime()?
        .block_on(context.client.list_remote_volumes(&context.tenant_id))
        .map_err(anyhow::Error::from)?;
    print_volumes(&volumes, json)
}

fn print_volumes(volumes: &[RemoteVolume], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(volumes)?);
        return Ok(());
    }
    for volume in volumes {
        let attached = volume.attached_instance_id.as_deref().unwrap_or("-");
        println!(
            "{}\t{}\t{} GiB\tattached={attached}",
            volume.volume_id, volume.name, volume.size_gib
        );
    }
    Ok(())
}

pub(super) fn snapshot(volume_id: &str, snapshot_name: &str) -> Result<()> {
    let context = context()?;
    let snapshot = runtime()?
        .block_on(context.client.create_remote_volume_snapshot(
            &context.tenant_id,
            volume_id,
            snapshot_name,
        ))
        .map_err(anyhow::Error::from)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

pub(super) fn restore(source_volume_id: &str, snapshot_id: &str, target_name: &str) -> Result<()> {
    let context = context()?;
    let volume = runtime()?
        .block_on(context.client.restore_remote_volume(
            &context.tenant_id,
            source_volume_id,
            snapshot_id,
            target_name,
        ))
        .map_err(anyhow::Error::from)?;
    println!("{}", serde_json::to_string_pretty(&volume)?);
    Ok(())
}

pub(super) fn delete(volume_id: &str) -> Result<()> {
    let context = context()?;
    runtime()?
        .block_on(
            context
                .client
                .delete_remote_volume(&context.tenant_id, volume_id),
        )
        .map_err(anyhow::Error::from)?;
    println!("Deleted remote volume {volume_id}");
    Ok(())
}

pub(super) fn mount(
    instance_id: &str,
    volume_id: &str,
    guest_path: &str,
    writable: bool,
) -> Result<()> {
    validate_mount_path(guest_path).context("invalid remote guest mount path")?;
    let context = context()?;
    let request = RemoteVolumeMount::new(volume_id, instance_id, guest_path).writable(writable);
    let attachment = runtime()?
        .block_on(
            context
                .client
                .attach_remote_volume(&context.tenant_id, &request),
        )
        .map_err(anyhow::Error::from)?;
    println!("{}", serde_json::to_string_pretty(&attachment)?);
    Ok(())
}

pub(super) fn ls(instance_id: &str, json: bool) -> Result<()> {
    let context = context()?;
    let runtime = runtime()?;
    let attachments = runtime.block_on(async {
        let volumes = context
            .client
            .list_remote_volumes(&context.tenant_id)
            .await?;
        let mut attachments = Vec::new();
        for volume in volumes
            .into_iter()
            .filter(|volume| volume.attached_instance_id.as_deref() == Some(instance_id))
        {
            attachments.push(
                context
                    .client
                    .remote_volume_attachment(&context.tenant_id, &volume.volume_id)
                    .await?,
            );
        }
        Ok::<_, mvm_core::client::MvmError>(attachments)
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&attachments)?);
    } else {
        for attachment in attachments {
            println!(
                "{}\t{}\tread_only={}\tfencing_token={}",
                attachment.volume_id,
                attachment.device_path,
                attachment.read_only,
                attachment.fencing_token
            );
        }
    }
    Ok(())
}

pub(super) fn unmount(instance_id: &str, guest_path: &str) -> Result<()> {
    let context = context()?;
    let runtime = runtime()?;
    let volume_id = runtime.block_on(async {
        let volumes = context
            .client
            .list_remote_volumes(&context.tenant_id)
            .await?;
        for volume in volumes
            .into_iter()
            .filter(|volume| volume.attached_instance_id.as_deref() == Some(instance_id))
        {
            let attachment = context
                .client
                .remote_volume_attachment(&context.tenant_id, &volume.volume_id)
                .await?;
            if attachment.device_path == guest_path {
                return Ok::<_, mvm_core::client::MvmError>(Some(volume.volume_id));
            }
        }
        Ok(None)
    })?;
    let volume_id = volume_id.with_context(|| {
        format!("no remote volume is mounted at {guest_path:?} on instance {instance_id:?}")
    })?;
    runtime
        .block_on(
            context
                .client
                .detach_remote_volume(&context.tenant_id, &volume_id),
        )
        .map_err(anyhow::Error::from)?;
    println!("Detached remote volume {volume_id}");
    Ok(())
}
