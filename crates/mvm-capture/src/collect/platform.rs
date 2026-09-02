//! Platform-fact collection.

use crate::report::PlatformFacts;

pub fn collect_platform_facts() -> PlatformFacts {
    let mut facts = PlatformFacts {
        architecture: Some(std::env::consts::ARCH.to_owned()),
        ..Default::default()
    };

    #[cfg(target_os = "linux")]
    {
        facts.kernel_name = Some("Linux".to_owned());
        if let Ok(text) = std::fs::read_to_string("/proc/version") {
            facts.kernel_version = text.split_whitespace().nth(2).map(str::to_owned);
        }
        if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
            for line in release.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim().trim_matches('"').to_owned();
                    match key {
                        "ID" => facts.distribution_id = Some(value),
                        "NAME" => facts.distribution_name = Some(value),
                        "VERSION_ID" => facts.distribution_version = Some(value),
                        _ => {}
                    }
                }
            }
        }
        if std::path::Path::new("/.dockerenv").exists() {
            facts.virtualization = Some("container".to_owned());
        } else if let Ok(virt) = std::fs::read_to_string("/proc/1/cgroup") {
            if virt.contains("docker") || virt.contains("containerd") || virt.contains("lxc") {
                facts.virtualization = Some("container".to_owned());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        facts.kernel_name = Some("Darwin".to_owned());
    }

    facts
}
