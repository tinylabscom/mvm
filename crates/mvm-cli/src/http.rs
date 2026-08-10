use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

fn build_blocking_client(timeout: std::time::Duration) -> Result<mvm_http::blocking::Client> {
    mvm_http::blocking::Client::builder()
        .user_agent(concat!("mvmctl/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .build()
        .context("Failed to build HTTP client")
}

/// Fetch a URL and return the response body as a string.
pub fn fetch_text(url: &str) -> Result<String> {
    let client = build_blocking_client(std::time::Duration::from_secs(30))?;

    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("HTTP request failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} for {}", status, url);
    }

    resp.text()
        .with_context(|| format!("Failed to read response body from {}", url))
}

/// Fetch a URL and parse the response as JSON.
pub fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let client = build_blocking_client(std::time::Duration::from_secs(30))?;

    let resp = client
        .get(url)
        .header("accept", "application/json")
        .send()
        .with_context(|| format!("HTTP request failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} for {}", status, url);
    }

    resp.json::<serde_json::Value>()
        .with_context(|| format!("Failed to parse JSON from {}", url))
}

/// Download a URL to a file on disk. Shows no progress (use for small files).
pub fn download_file(url: &str, dest: &Path) -> Result<()> {
    let client = build_blocking_client(std::time::Duration::from_secs(600))?;

    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("Download failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} downloading {}", status, url);
    }

    let bytes = resp.bytes();

    let mut file = std::fs::File::create(dest)
        .with_context(|| format!("Failed to create file: {}", dest.display()))?;

    file.write_all(&bytes)
        .with_context(|| format!("Failed to write to: {}", dest.display()))?;

    Ok(())
}
