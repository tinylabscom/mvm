//! Data-only Git configuration discovery, never executable probing.
#[cfg(any(windows, test))]
use super::message;
#[cfg(windows)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Resolved V2 data-source policy. NoSystem is the fixed default, not a
/// caller-supplied manifest setting. Attributes never opt in via config.
pub(super) struct ResolvedPolicy {
    pub path: Option<PathBuf>,
    pub prefix: Option<PathBuf>,
    pub attributes: Option<PathBuf>,
}
pub(super) fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}
fn parse_bool_os(value: &std::ffi::OsStr) -> Option<bool> {
    parse_boolean(value.to_str()?.as_bytes()).ok()
}

/// Git's bool-or-int conversion uses base-zero numbers and binary units,
/// narrowed to a signed C int. gix's Boolean currently accepts decimal i64 only.
pub(super) fn parse_boolean(value: &[u8]) -> Result<bool, String> {
    let s = std::str::from_utf8(value).map_err(|_| "non-UTF-8 boolean".to_owned())?;
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => return Ok(true),
        "false" | "no" | "off" | "" => return Ok(false),
        _ => {}
    }
    let (number, multiplier) = match s.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'k') => (&s[..s.len() - 1], 1024_i64),
        Some(b'm') => (&s[..s.len() - 1], 1024_i64 * 1024),
        Some(b'g') => (&s[..s.len() - 1], 1024_i64 * 1024 * 1024),
        _ => (s, 1),
    };
    let number = number.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (negative, digits) = if let Some(v) = number.strip_prefix('-') {
        (true, v)
    } else {
        (false, number.strip_prefix('+').unwrap_or(number))
    };
    let (base, digits) = if let Some(v) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, v)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let invalid = || format!("invalid Git boolean {s:?}");
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return Err(invalid());
    }
    let value = i64::from_str_radix(digits, base).map_err(|_| invalid())?;
    let value = if negative { -value } else { value };
    let value = value.checked_mul(multiplier).ok_or_else(invalid)?;
    let value = i32::try_from(value).map_err(|_| invalid())?;
    Ok(value != 0)
}

pub(super) fn env_boolean(name: &str) -> Result<bool, String> {
    match std::env::var_os(name) {
        None => Ok(false),
        Some(value) => parse_bool_os(&value).ok_or_else(|| {
            format!(
                "invalid boolean value for {name}: {:?}",
                value.to_string_lossy()
            )
        }),
    }
}
pub(super) fn system() -> Result<ResolvedPolicy, String> {
    let attributes_requested =
        std::env::var_os("GIT_ATTR_NOSYSTEM").is_some() && !env_boolean("GIT_ATTR_NOSYSTEM")?;
    let disabled = env_boolean("GIT_CONFIG_NOSYSTEM")?;
    let implicit_config_requested = !disabled
        && std::env::var_os("GIT_CONFIG_NOSYSTEM").is_some()
        && std::env::var_os("GIT_CONFIG_SYSTEM").is_none();
    #[cfg(windows)]
    let prefix = if attributes_requested || implicit_config_requested {
        windows_prefix()?
    } else {
        None
    };
    #[cfg(not(windows))]
    let prefix: Option<PathBuf> = None;
    let attributes =
        if attributes_requested {
            Some(prefix.as_ref().ok_or_else(|| {
            "implicit system Git attributes path is unproven; set GIT_ATTR_NOSYSTEM=true".to_owned()
        })?.join("etc/gitattributes"))
        } else {
            None
        };
    if let Some(value) = (!disabled)
        .then(|| std::env::var_os("GIT_CONFIG_SYSTEM"))
        .flatten()
    {
        if value.is_empty() {
            return Err(
                "GIT_CONFIG_SYSTEM is empty; name an accessible file or set GIT_CONFIG_NOSYSTEM=1"
                    .to_owned(),
            );
        }
        let path = PathBuf::from(value);
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() || path == Path::new("/dev/null") => {}
            Ok(_) => {
                return Err(format!(
                    "Git config {} is not a regular file",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(format!(
                    "reading Git config {}: {err}; set GIT_CONFIG_SYSTEM or GIT_CONFIG_NOSYSTEM=1",
                    path.display()
                ));
            }
        }
        return Ok(ResolvedPolicy {
            path: Some(path),
            prefix,
            attributes,
        });
    }
    if implicit_config_requested && prefix.is_none() {
        return Err(
            "implicit system Git config path is unproven; name GIT_CONFIG_SYSTEM explicitly"
                .to_owned(),
        );
    }
    let path = if disabled || std::env::var_os("GIT_CONFIG_NOSYSTEM").is_none() {
        None
    } else {
        prefix.as_ref().map(|p| p.join("etc/gitconfig"))
    };
    Ok(ResolvedPolicy {
        path,
        prefix,
        attributes,
    })
}

#[cfg(test)]
pub(super) fn prefix_from_path(
    dirs: impl IntoIterator<Item = PathBuf>,
) -> Result<Option<PathBuf>, String> {
    for dir in dirs {
        let executable = dir.join("git.exe");
        match std::fs::metadata(&executable) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "cannot inspect {}: {err}; name GIT_CONFIG_SYSTEM explicitly",
                    executable.display()
                ));
            }
            Ok(meta) if !meta.is_file() => {
                return Err("Git executable data path is not a regular file".to_owned());
            }
            Ok(_) => {}
        }
        let executable = executable.canonicalize().map_err(message)?;
        let parent = executable
            .parent()
            .ok_or_else(|| "Git executable has no directory".to_owned())?;
        let component = parent.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if !matches!(component.to_ascii_lowercase().as_str(), "cmd" | "bin") {
            return Err(format!(
                "cannot infer installed/portable Git prefix from {}; set GIT_CONFIG_SYSTEM to its config file",
                executable.display()
            ));
        }
        let mut prefix = parent
            .parent()
            .ok_or_else(|| "Git executable has no prefix".to_owned())?
            .to_path_buf();
        if prefix
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| {
                matches!(
                    v.to_ascii_lowercase().as_str(),
                    "mingw32" | "mingw64" | "usr"
                )
            })
        {
            prefix = prefix
                .parent()
                .ok_or_else(|| "Git installation has no root".to_owned())?
                .to_path_buf();
        }
        match std::fs::metadata(prefix.join("etc")) {
            Ok(meta) if meta.is_dir() => return Ok(Some(prefix)),
            Ok(_) => return Err("Git installation etc path is not a directory".to_owned()),
            Err(err) => {
                return Err(format!(
                    "cannot inspect Git prefix {}: {err}; set GIT_CONFIG_SYSTEM explicitly",
                    prefix.display()
                ));
            }
        }
    }
    Ok(None)
}

#[cfg(windows)]
pub(super) fn windows_prefix() -> Result<Option<PathBuf>, String> {
    let mut roots = BTreeSet::new();
    for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(variable) {
            let root = PathBuf::from(base).join(if variable == "LOCALAPPDATA" {
                "Programs/Git"
            } else {
                "Git"
            });
            match std::fs::metadata(root.join("etc")) {
                Ok(meta) if meta.is_dir() => {
                    roots.insert(root.canonicalize().map_err(message)?);
                }
                Ok(_) => return Err("installed Git etc path is not a directory".to_owned()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "cannot inspect Git installation {}: {err}; set GIT_CONFIG_SYSTEM explicitly",
                        root.display()
                    ));
                }
            }
        }
    }
    if roots.len() > 1 {
        return Err("ambiguous Windows Git installations; set GIT_CONFIG_SYSTEM to the intended accessible config file".to_owned());
    }
    Ok(roots.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_boolean_numeric_and_keyword_semantics() {
        for value in [
            "yes",
            "ON",
            "true",
            "1",
            "-1",
            "0x10",
            "010",
            "1k",
            "-2m",
            "2147483647",
            "-2147483648",
        ] {
            assert!(parse_boolean(value.as_bytes()).unwrap(), "{value}");
        }
        for value in ["", "false", "NO", "off", "0", "0x0", "0k"] {
            assert!(!parse_boolean(value.as_bytes()).unwrap(), "{value}");
        }
        for value in [
            "garbage",
            "08",
            "2147483648",
            "-2147483649",
            "2g",
            "1kk",
            "+-1",
            "--1",
            "0x+1",
        ] {
            assert!(parse_boolean(value.as_bytes()).is_err(), "{value}");
        }
    }
    #[test]
    fn installed_and_portable_layouts_are_only_read_as_data() {
        for suffix in ["cmd", "bin", "mingw64/bin", "mingw32/bin", "usr/bin"] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join(suffix)).unwrap();
            std::fs::create_dir(tmp.path().join("etc")).unwrap();
            std::fs::write(
                tmp.path().join(suffix).join("git.exe"),
                b"not executable code",
            )
            .unwrap();
            assert_eq!(
                prefix_from_path([tmp.path().join(suffix)]).unwrap(),
                Some(tmp.path().canonicalize().unwrap())
            );
        }
    }
    #[test]
    fn absent_and_unknown_layouts_have_explicit_results() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(prefix_from_path([tmp.path().to_path_buf()]).unwrap(), None);
        std::fs::write(tmp.path().join("git.exe"), b"not a known layout").unwrap();
        assert!(
            prefix_from_path([tmp.path().to_path_buf()])
                .unwrap_err()
                .contains("GIT_CONFIG_SYSTEM")
        );
    }
}
