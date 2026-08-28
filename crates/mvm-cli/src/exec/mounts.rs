use anyhow::Result;

use crate::commands::DirShareSpec;

/// Refuse `--mount` on a backend with no virtio-fs share device, naming the
/// backend and what to use instead.
///
/// `--mount` is advertised without qualification but only one backend serves
/// it, so on every other backend the flag is accepted, paid for, and then
/// rejected mid-launch. Deciding here costs nothing and says which backend is
/// the problem — the runner's own refusal names the volume but not the reason
/// the caller can act on, which is *which backend they are on*.
pub(crate) fn refuse_unsupported_dir_shares(
    backend_name: &str,
    supports_dir_shares: bool,
    dir_shares: &[DirShareSpec],
) -> Result<()> {
    if dir_shares.is_empty() || supports_dir_shares {
        return Ok(());
    }
    let shares = dir_shares
        .iter()
        .map(|share| format!("{}:{}", share.host_dir, share.guest_mount))
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "the {} backend cannot attach a host directory share, so --mount is \
         unsupported here (requested: {shares}). Attach a disk-image volume \
         instead (--volume HOST:GUEST:SIZE), or run on a backend with virtio-fs \
         directory shares.",
        backend_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dir_share_is_refused_up_front_on_a_backend_without_virtiofs() {
        let shares = vec![DirShareSpec {
            host_dir: "/host/fixtures".into(),
            guest_mount: "/work/fixtures".into(),
            read_only: true,
        }];

        let err = refuse_unsupported_dir_shares("firecracker", false, &shares)
            .expect_err("a backend without virtio-fs shares must refuse --mount");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("firecracker"),
            "the refusal must name the backend, got: {msg}"
        );
        assert!(
            msg.contains("/work/fixtures"),
            "the refusal must name the requested share, got: {msg}"
        );

        refuse_unsupported_dir_shares("hvf", true, &shares)
            .expect("a backend with virtio-fs shares must accept --mount");
    }

    #[test]
    fn a_launch_without_mounts_is_not_refused() {
        refuse_unsupported_dir_shares("firecracker", false, &[])
            .expect("a launch with no --mount must not be refused");
    }
}
