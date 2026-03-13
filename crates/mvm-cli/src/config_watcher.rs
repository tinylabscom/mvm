use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Result;
use mvm_core::user_config::MvmConfig;
use notify_debouncer_mini::{DebouncedEventKind, new_debouncer};

/// Events sent from the background watcher thread.
pub enum ConfigReloadEvent {
    Reloaded(MvmConfig),
    ParseError(String),
}

/// Watches a config file for changes and sends reload events on a channel.
///
/// Changes are debounced by 500 ms (via `notify-debouncer-mini`) to avoid
/// reacting to partial writes or rapid saves.  Drop this struct to stop
/// watching — the background thread exits when it detects the receiver
/// has been dropped.
pub struct ConfigWatcher {
    /// Receive `ConfigReloadEvent`s from the background thread.
    pub receiver: mpsc::Receiver<ConfigReloadEvent>,
}

impl ConfigWatcher {
    /// Start watching `path`.  Returns immediately; the debouncer runs on a
    /// background thread managed by `notify`.
    pub fn start(path: &Path) -> Result<Self> {
        // Canonicalize so that event.path comparisons work reliably.
        let watch_file = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        // Watch the parent directory — notify is most reliable when watching dirs.
        let watch_dir = watch_file
            .parent()
            .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?
            .to_path_buf();

        let (event_tx, event_rx) = mpsc::channel::<ConfigReloadEvent>();

        let (raw_tx, raw_rx) = mpsc::channel();
        let mut debouncer = new_debouncer(Duration::from_millis(500), raw_tx)?;
        debouncer
            .watcher()
            .watch(&watch_dir, notify::RecursiveMode::NonRecursive)?;

        // Spawn a thread that translates raw events → ConfigReloadEvent.
        // The debouncer is moved into the thread to keep the OS watch alive.
        std::thread::spawn(move || {
            let _debouncer = debouncer;
            loop {
                match raw_rx.recv() {
                    Ok(Ok(events)) => {
                        for event in &events {
                            if event.kind != DebouncedEventKind::Any {
                                continue;
                            }
                            // Filter: only react to changes on the config file itself.
                            let event_file = event
                                .path
                                .canonicalize()
                                .unwrap_or_else(|_| event.path.clone());
                            if event_file != watch_file {
                                continue;
                            }
                            let reload = match std::fs::read_to_string(&watch_file) {
                                Ok(text) => match toml::from_str::<MvmConfig>(&text) {
                                    Ok(cfg) => ConfigReloadEvent::Reloaded(cfg),
                                    Err(e) => ConfigReloadEvent::ParseError(e.to_string()),
                                },
                                Err(e) => ConfigReloadEvent::ParseError(e.to_string()),
                            };
                            if event_tx.send(reload).is_err() {
                                // Receiver was dropped — stop watching.
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("config watcher error: {e}");
                    }
                    Err(_) => {
                        // raw_rx channel closed — stop the thread.
                        return;
                    }
                }
            }
        });

        Ok(ConfigWatcher { receiver: event_rx })
    }
}

/// Drain any pending reload events and apply them to `cfg`.
///
/// Logs each reload or parse error via tracing.  Returns the (possibly
/// updated) config.
pub fn apply_pending_reloads(cfg: MvmConfig, rx: &mpsc::Receiver<ConfigReloadEvent>) -> MvmConfig {
    let mut current = cfg;
    while let Ok(event) = rx.try_recv() {
        match event {
            ConfigReloadEvent::Reloaded(new_cfg) => {
                tracing::info!("Config reloaded from ~/.mvm/config.toml");
                current = new_cfg;
            }
            ConfigReloadEvent::ParseError(msg) => {
                tracing::warn!("Config reload failed: {msg}; keeping previous config");
            }
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::user_config::MvmConfig;

    fn write_config(path: &Path, cfg: &MvmConfig) {
        let text = toml::to_string_pretty(cfg).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn test_config_watcher_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        write_config(&config_path, &MvmConfig::default());
        let watcher = ConfigWatcher::start(&config_path).unwrap();

        // Give the watcher time to register before writing.
        std::thread::sleep(Duration::from_millis(200));

        let mut updated = MvmConfig::default();
        updated.lima_cpus = 4;
        write_config(&config_path, &updated);

        // Wait up to 3 s for the reload event.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut received = false;
        while std::time::Instant::now() < deadline {
            match watcher.receiver.try_recv() {
                Ok(ConfigReloadEvent::Reloaded(cfg)) => {
                    assert_eq!(cfg.lima_cpus, 4);
                    received = true;
                    break;
                }
                Ok(ConfigReloadEvent::ParseError(e)) => {
                    panic!("Unexpected parse error: {e}");
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        assert!(
            received,
            "No ConfigReloadEvent::Reloaded received within 3 s"
        );
    }

    #[test]
    fn test_config_watcher_invalid_toml_sends_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        write_config(&config_path, &MvmConfig::default());
        let watcher = ConfigWatcher::start(&config_path).unwrap();

        std::thread::sleep(Duration::from_millis(200));

        // Overwrite with invalid TOML.
        std::fs::write(&config_path, b"this is [[ not valid toml").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut received = false;
        while std::time::Instant::now() < deadline {
            match watcher.receiver.try_recv() {
                Ok(ConfigReloadEvent::ParseError(_)) => {
                    received = true;
                    break;
                }
                Ok(ConfigReloadEvent::Reloaded(_)) => {
                    // Race with earlier write — keep waiting.
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        assert!(
            received,
            "No ConfigReloadEvent::ParseError received within 3 s"
        );
    }

    #[test]
    fn test_apply_pending_reloads_updates_cfg() {
        let (tx, rx) = mpsc::channel();
        let mut cfg = MvmConfig::default();

        let mut new_cfg = MvmConfig::default();
        new_cfg.lima_cpus = 12;
        tx.send(ConfigReloadEvent::Reloaded(new_cfg)).unwrap();

        cfg = apply_pending_reloads(cfg, &rx);
        assert_eq!(cfg.lima_cpus, 12);
    }

    #[test]
    fn test_apply_pending_reloads_keeps_cfg_on_error() {
        let (tx, rx) = mpsc::channel();
        let mut cfg = MvmConfig::default();
        cfg.lima_cpus = 6;

        tx.send(ConfigReloadEvent::ParseError("bad toml".to_string()))
            .unwrap();

        cfg = apply_pending_reloads(cfg, &rx);
        // Config unchanged after parse error.
        assert_eq!(cfg.lima_cpus, 6);
    }
}
