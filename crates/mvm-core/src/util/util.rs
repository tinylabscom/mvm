//! Utility functions for parsing and formatting.

use anyhow::{Result, anyhow};

/// Parse a human-readable size string into megabytes.
///
/// Supports suffixes: K/KB, M/MB, G/GB (case-insensitive).
/// If no suffix is provided, assumes megabytes.
///
/// # Examples
///
/// ```
/// use mvm_core::util::parse_human_size;
///
/// assert_eq!(parse_human_size("512").unwrap(), 512);
/// assert_eq!(parse_human_size("512M").unwrap(), 512);
/// assert_eq!(parse_human_size("512MB").unwrap(), 512);
/// assert_eq!(parse_human_size("4G").unwrap(), 4096);
/// assert_eq!(parse_human_size("4GB").unwrap(), 4096);
/// assert_eq!(parse_human_size("1024K").unwrap(), 1);
/// assert_eq!(parse_human_size("1024KB").unwrap(), 1);
/// ```
pub fn parse_human_size(input: &str) -> Result<u32> {
    let input = input.trim();
    if input.is_empty() {
        return Err(anyhow!("Empty size string"));
    }

    // Find where the numeric part ends
    let (num_part, suffix) = {
        let mut num_end = 0;
        for (i, ch) in input.chars().enumerate() {
            if ch.is_ascii_digit() || ch == '.' {
                num_end = i + 1;
            } else {
                break;
            }
        }
        (&input[..num_end], &input[num_end..])
    };

    if num_part.is_empty() {
        return Err(anyhow!("No numeric value found in '{}'", input));
    }

    let num: f64 = num_part
        .parse()
        .map_err(|_| anyhow!("Invalid number '{}'", num_part))?;

    if num < 0.0 {
        return Err(anyhow!("Size cannot be negative"));
    }

    // Determine multiplier based on suffix (case-insensitive)
    let multiplier: f64 = match suffix.trim().to_uppercase().as_str() {
        "" | "M" | "MB" | "MIB" => 1.0,
        "G" | "GB" | "GIB" => 1024.0,
        "K" | "KB" | "KIB" => 1.0 / 1024.0,
        other => return Err(anyhow!("Unknown size suffix '{}'", other)),
    };

    let result = num * multiplier;

    // Check for overflow and round to nearest integer
    if result > u32::MAX as f64 {
        return Err(anyhow!("Size too large (max: {} MiB)", u32::MAX));
    }

    Ok(result.round() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain_number() {
        assert_eq!(parse_human_size("512").unwrap(), 512);
        assert_eq!(parse_human_size("1024").unwrap(), 1024);
        assert_eq!(parse_human_size("1").unwrap(), 1);
    }

    #[test]
    fn test_parse_megabytes() {
        assert_eq!(parse_human_size("512M").unwrap(), 512);
        assert_eq!(parse_human_size("512MB").unwrap(), 512);
        assert_eq!(parse_human_size("512MiB").unwrap(), 512);
        assert_eq!(parse_human_size("512m").unwrap(), 512);
        assert_eq!(parse_human_size("512mb").unwrap(), 512);
    }

    #[test]
    fn test_parse_gigabytes() {
        assert_eq!(parse_human_size("1G").unwrap(), 1024);
        assert_eq!(parse_human_size("1GB").unwrap(), 1024);
        assert_eq!(parse_human_size("1GiB").unwrap(), 1024);
        assert_eq!(parse_human_size("4G").unwrap(), 4096);
        assert_eq!(parse_human_size("4g").unwrap(), 4096);
        assert_eq!(parse_human_size("0.5G").unwrap(), 512);
    }

    #[test]
    fn test_parse_kilobytes() {
        assert_eq!(parse_human_size("1024K").unwrap(), 1);
        assert_eq!(parse_human_size("1024KB").unwrap(), 1);
        assert_eq!(parse_human_size("1024KiB").unwrap(), 1);
        assert_eq!(parse_human_size("512K").unwrap(), 1); // rounds 0.5 to 1
        assert_eq!(parse_human_size("2048k").unwrap(), 2);
    }

    #[test]
    fn test_parse_with_whitespace() {
        assert_eq!(parse_human_size("  512  ").unwrap(), 512);
        assert_eq!(parse_human_size("  4G  ").unwrap(), 4096);
        assert_eq!(parse_human_size("512 M").unwrap(), 512);
    }

    #[test]
    fn test_parse_decimal() {
        assert_eq!(parse_human_size("1.5G").unwrap(), 1536);
        assert_eq!(parse_human_size("0.5G").unwrap(), 512);
        assert_eq!(parse_human_size("2.5G").unwrap(), 2560);
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_human_size("").is_err());
        assert!(parse_human_size("abc").is_err());
        assert!(parse_human_size("512T").is_err()); // Unsupported suffix
        assert!(parse_human_size("-512M").is_err()); // Negative
        assert!(parse_human_size("512XB").is_err()); // Invalid suffix
    }

    #[test]
    fn test_parse_overflow() {
        // u32::MAX is 4294967295, way larger than practical memory values
        // but let's test the boundary
        assert!(parse_human_size("9999999G").is_err());
    }

    #[test]
    fn test_parse_zero() {
        assert_eq!(parse_human_size("0").unwrap(), 0);
        assert_eq!(parse_human_size("0M").unwrap(), 0);
        assert_eq!(parse_human_size("0G").unwrap(), 0);
    }
}
