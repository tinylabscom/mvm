//! Which images a `pool warm` invocation warms, and warming each in turn.

use anyhow::Result;

use super::WarmRequest;

/// Which images a `pool warm` invocation names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WarmSelection {
    Image(String),
    Default,
    Recent,
}

impl WarmSelection {
    pub(super) fn from_flags(image: Option<String>, default_image: bool) -> Self {
        match (image, default_image) {
            (Some(image), _) => Self::Image(image),
            (None, true) => Self::Default,
            (None, false) => Self::Recent,
        }
    }
}

/// The images to warm, `None` standing for the default image. `recent` is the
/// newest-first history the caller read; it is consulted only for
/// [`WarmSelection::Recent`], and an empty history falls back to the default
/// image so a fresh host's `pool warm` behaves as it always has.
pub(super) fn images_to_warm(
    selection: WarmSelection,
    recent: &[String],
    limit: usize,
) -> Vec<Option<String>> {
    match selection {
        WarmSelection::Image(image) => vec![Some(image)],
        WarmSelection::Default => vec![None],
        WarmSelection::Recent if recent.is_empty() => vec![None],
        WarmSelection::Recent => recent
            .iter()
            .take(limit.max(1))
            .cloned()
            .map(Some)
            .collect(),
    }
}

/// How many recent images a bare `pool warm` warms: the residency warm target,
/// never fewer than one. Each standby holds a booted guest's memory, so the
/// number of images is bounded by what residency says to keep warm rather
/// than by how many images happen to be cached.
pub(super) fn recent_image_limit() -> usize {
    mvm_core::residency::effective_warm_pool_size(None).max(1) as usize
}

pub(super) fn announce_recent_selection(images: &[Option<String>]) {
    let named: Vec<&str> = images.iter().filter_map(|i| i.as_deref()).collect();
    if named.is_empty() {
        crate::ui::info("No pulled images in the local cache; warming the default image.");
    } else {
        crate::ui::info(&format!(
            "Warming the most recently pulled image(s): {}",
            named.join(", ")
        ));
    }
}

/// Warm every request in turn. One image failing does not stop the next; the
/// failures are reported together once every image has been tried.
pub(super) fn warm_each(
    requests: &[WarmRequest],
    mut warm: impl FnMut(&WarmRequest) -> Result<()>,
) -> Result<()> {
    let mut failed = Vec::new();
    for req in requests {
        if let Err(e) = warm(req) {
            failed.push(format!("{}: {e:#}", req.label()));
        }
    }
    if failed.is_empty() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "pool warm: {} of {} image(s) not warmed: {}",
        failed.len(),
        requests.len(),
        failed.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recent() -> Vec<String> {
        ["python:3.12", "nginx", "alpine"]
            .map(str::to_string)
            .to_vec()
    }

    #[test]
    fn a_bare_pool_warm_picks_the_newest_pulls_up_to_the_limit() {
        assert_eq!(
            images_to_warm(WarmSelection::Recent, &recent(), 2),
            [Some("python:3.12".to_string()), Some("nginx".to_string())]
        );
        assert_eq!(
            images_to_warm(WarmSelection::Recent, &recent(), 0),
            [Some("python:3.12".to_string())],
            "a parked host's zero warm target still warms the one image asked for"
        );
    }

    #[test]
    fn a_bare_pool_warm_with_no_history_warms_the_default_image() {
        assert_eq!(images_to_warm(WarmSelection::Recent, &[], 3), [None]);
    }

    #[test]
    fn a_named_or_default_selection_ignores_history() {
        assert_eq!(
            images_to_warm(WarmSelection::Image("rust".to_string()), &recent(), 3),
            [Some("rust".to_string())]
        );
        assert_eq!(images_to_warm(WarmSelection::Default, &recent(), 3), [None]);
        assert_eq!(
            WarmSelection::from_flags(None, false),
            WarmSelection::Recent
        );
        assert_eq!(
            WarmSelection::from_flags(None, true),
            WarmSelection::Default
        );
    }

    #[test]
    fn warm_each_tries_every_image_and_names_the_ones_that_failed() {
        let requests: Vec<WarmRequest> = ["alpine", "nginx"]
            .into_iter()
            .map(|image| WarmRequest {
                image: Some(image.to_string()),
                cpus: 2,
                memory_mib: 512,
                target: 1,
            })
            .collect();
        let mut tried = Vec::new();
        let err = warm_each(&requests, |req| {
            tried.push(req.label().to_string());
            if req.label() == "alpine" {
                anyhow::bail!("spawn failed")
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(tried, ["alpine", "nginx"]);
        assert_eq!(
            err.to_string(),
            "pool warm: 1 of 2 image(s) not warmed: alpine: spawn failed"
        );
    }
}
