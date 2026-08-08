//! Simple file-injection descriptor shared by backends and the builder VM.

/// A file to inject onto a config or secrets drive before boot.
#[derive(Debug, Clone)]
pub struct DriveFile {
    /// Destination filename inside the drive (e.g., "openclaw.json").
    pub name: String,
    /// File contents (inline).
    pub content: String,
    /// Unix permissions (octal). Config files: 0o444, secrets: 0o400.
    pub mode: u32,
}

impl Default for DriveFile {
    fn default() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            mode: 0o444,
        }
    }
}
