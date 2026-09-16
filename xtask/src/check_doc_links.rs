//! `xtask check-doc-links`
//!
//! Resolve links that the repository can prove without the network: files in
//! this checkout, GitHub blob/tree URLs for this repository, and routes built
//! by the public documentation site. External URLs deliberately stay out of
//! the blocking gate.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use crate::fs_walk::walk_files;

const DOCS_DIR: &str = "public/src/content/docs";
const PAGES_DIR: &str = "public/src/pages";
const ASSETS_DIR: &str = "public/public";
const GITHUB_BLOB: &str = "https://github.com/tinylabscom/mvm/blob/";
const GITHUB_TREE: &str = "https://github.com/tinylabscom/mvm/tree/";

static MARKDOWN_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"!?(?:\[[^\]\n]*\])\(([^)\n]+)\)"#).expect("the markdown-link regex is valid")
});
static HTML_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:href|src)\s*=\s*["']([^"']+)["']"#).expect("the HTML-link regex is valid")
});

/// Check every Markdown/MDX file in the published documentation tree.
pub fn run(root: &Path) -> Result<()> {
    let docs = root.join(DOCS_DIR);
    if !docs.is_dir() {
        bail!(
            "check-doc-links: expected documentation at {}",
            docs.display()
        );
    }

    let routes = built_routes(root)?;
    let mut errors = Vec::new();
    let mut checked = 0usize;
    walk_files(&docs, &mut |source| {
        if !matches!(
            source.extension().and_then(|ext| ext.to_str()),
            Some("md" | "mdx")
        ) {
            return;
        }
        let Ok(text) = std::fs::read_to_string(source) else {
            return;
        };
        for (line, target) in link_targets(&text) {
            if let Some(reason) = link_error(root, &routes, source, &target) {
                let rel = source.strip_prefix(root).unwrap_or(source);
                errors.push(format!("{}:{line}: `{target}` {reason}", rel.display()));
            } else if is_hermetic_target(&target) {
                checked += 1;
            }
        }
    })?;

    if !errors.is_empty() {
        for error in &errors {
            eprintln!("[error] {error}");
        }
        bail!(
            "check-doc-links: {} repository or internal-site link(s) do not resolve",
            errors.len()
        );
    }

    println!("check-doc-links: clean ({checked} hermetic links resolved)");
    Ok(())
}

fn link_targets(text: &str) -> Vec<(usize, String)> {
    let mut targets = Vec::new();
    let mut fence: Option<&str> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("```") {
            Some("```")
        } else if trimmed.starts_with("~~~") {
            Some("~~~")
        } else {
            None
        };
        if let Some(marker) = marker {
            if fence == Some(marker) {
                fence = None;
            } else if fence.is_none() {
                fence = Some(marker);
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }

        for captures in MARKDOWN_LINK.captures_iter(line) {
            let Some(raw) = captures.get(1) else {
                continue;
            };
            if let Some(target) = markdown_destination(raw.as_str()) {
                targets.push((index + 1, target.to_string()));
            }
        }
        for captures in HTML_LINK.captures_iter(line) {
            if let Some(target) = captures.get(1) {
                targets.push((index + 1, target.as_str().to_string()));
            }
        }
    }
    targets
}

fn markdown_destination(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(angle) = raw.strip_prefix('<') {
        return angle.split_once('>').map(|(target, _)| target);
    }
    raw.split_whitespace().next()
}

fn link_error(
    root: &Path,
    routes: &HashSet<String>,
    source: &Path,
    target: &str,
) -> Option<String> {
    let target = target.trim();
    if target.is_empty() || target.starts_with('#') {
        return None;
    }

    if let Some(repo_path) = github_repo_path(target) {
        return missing_file(root, &repo_path);
    }
    if target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
        || target.starts_with("tel:")
        || target.starts_with("//")
    {
        return None;
    }

    let path = strip_query_and_fragment(target);
    if path.starts_with('/') {
        let route = normalize_route(path);
        return (!routes.contains(&route)).then(|| "does not match a built site route".to_string());
    }

    let beside_source = source.parent().unwrap_or(root).join(path);
    if resolves_existing_path(root, &beside_source)
        || resolves_existing_path(root, &root.join(path))
        || resolves_doc_sibling(root, &beside_source)
    {
        None
    } else {
        Some("does not name a file in the repository".to_string())
    }
}

fn is_hermetic_target(target: &str) -> bool {
    let target = target.trim();
    target.starts_with('/')
        || github_repo_path(target).is_some()
        || (!target.is_empty()
            && !target.starts_with('#')
            && !target.starts_with("http://")
            && !target.starts_with("https://")
            && !target.starts_with("mailto:")
            && !target.starts_with("tel:")
            && !target.starts_with("//"))
}

fn github_repo_path(target: &str) -> Option<PathBuf> {
    let rest = target
        .strip_prefix(GITHUB_BLOB)
        .or_else(|| target.strip_prefix(GITHUB_TREE))?;
    let (_, path) = strip_query_and_fragment(rest).split_once('/')?;
    let path = PathBuf::from(path);
    safe_relative(&path).then_some(path)
}

fn missing_file(root: &Path, relative: &Path) -> Option<String> {
    (!root.join(relative).exists()).then(|| "does not name a file in this checkout".to_string())
}

fn resolves_existing_path(root: &Path, candidate: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    std::fs::canonicalize(candidate).is_ok_and(|candidate| candidate.starts_with(root))
}

fn resolves_doc_sibling(root: &Path, candidate: &Path) -> bool {
    candidate.extension().is_none()
        && ["md", "mdx"]
            .iter()
            .any(|extension| resolves_existing_path(root, &candidate.with_extension(extension)))
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn strip_query_and_fragment(target: &str) -> &str {
    let fragment_free = target.split_once('#').map_or(target, |(path, _)| path);
    fragment_free
        .split_once('?')
        .map_or(fragment_free, |(path, _)| path)
}

fn normalize_route(route: &str) -> String {
    let route = strip_query_and_fragment(route).trim_matches('/');
    if route.is_empty() {
        "/".to_string()
    } else {
        format!("/{route}")
    }
}

fn built_routes(root: &Path) -> Result<HashSet<String>> {
    let mut routes = HashSet::new();
    collect_content_routes(&root.join(DOCS_DIR), &mut routes)?;
    collect_page_routes(&root.join(PAGES_DIR), &mut routes)?;
    collect_asset_routes(&root.join(ASSETS_DIR), &mut routes)?;
    Ok(routes)
}

fn collect_content_routes(dir: &Path, routes: &mut HashSet<String>) -> Result<()> {
    walk_files(dir, &mut |path| {
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("md" | "mdx")
        ) {
            return;
        }
        let Ok(relative) = path.strip_prefix(dir) else {
            return;
        };
        let without_extension = relative.with_extension("");
        let route = if without_extension
            .file_name()
            .is_some_and(|name| name == "index")
        {
            without_extension.parent().unwrap_or(Path::new(""))
        } else {
            without_extension.as_path()
        };
        let route = normalize_route(&format!("/{}", route.to_string_lossy()));
        routes.insert(format!("{route}.md"));
        routes.insert(route);
    })
}

fn collect_page_routes(dir: &Path, routes: &mut HashSet<String>) -> Result<()> {
    walk_files(dir, &mut |path| {
        let Ok(relative) = path.strip_prefix(dir) else {
            return;
        };
        let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if name.starts_with('_') || name.contains('[') {
            return;
        }
        let route = if let Some(stem) = name.strip_suffix(".astro") {
            relative.with_file_name(stem)
        } else if let Some(stem) = name.strip_suffix(".ts") {
            relative.with_file_name(stem)
        } else {
            return;
        };
        let route = if route.file_name().is_some_and(|name| name == "index") {
            route.parent().unwrap_or(Path::new(""))
        } else {
            route.as_path()
        };
        routes.insert(normalize_route(&format!("/{}", route.to_string_lossy())));
    })
}

fn collect_asset_routes(dir: &Path, routes: &mut HashSet<String>) -> Result<()> {
    walk_files(dir, &mut |path| {
        if let Ok(relative) = path.strip_prefix(dir) {
            routes.insert(normalize_route(&format!("/{}", relative.to_string_lossy())));
            if relative
                .file_name()
                .is_some_and(|name| name == "index.html")
            {
                let parent = relative.parent().unwrap_or(Path::new(""));
                routes.insert(normalize_route(&format!("/{}", parent.to_string_lossy())));
            }
        }
    })
    .with_context(|| format!("walking public assets at {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| normalize_route(value)).collect()
    }

    #[test]
    fn repo_relative_paths_must_exist() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("specs/plans")).unwrap();
        std::fs::write(root.path().join("specs/plans/live.md"), "live").unwrap();
        let source = root.path().join("public/src/content/docs/guide.md");

        assert_eq!(
            link_error(root.path(), &HashSet::new(), &source, "specs/plans/live.md"),
            None
        );
        assert!(
            link_error(
                root.path(),
                &HashSet::new(),
                &source,
                "specs/plans/deleted.md"
            )
            .is_some()
        );
    }

    #[test]
    fn this_repositories_github_links_resolve_without_the_network() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("crates/example/src")).unwrap();
        std::fs::write(root.path().join("crates/example/src/lib.rs"), "").unwrap();
        let source = root.path().join("public/src/content/docs/guide.md");

        assert_eq!(
            link_error(
                root.path(),
                &HashSet::new(),
                &source,
                "https://github.com/tinylabscom/mvm/blob/main/crates/example/src/lib.rs#L1",
            ),
            None
        );
        assert!(
            link_error(
                root.path(),
                &HashSet::new(),
                &source,
                "https://github.com/tinylabscom/mvm/blob/main/crates/example/src/missing.rs",
            )
            .is_some()
        );
    }

    #[test]
    fn relative_doc_links_resolve_from_the_current_page() {
        let root = tempfile::tempdir().unwrap();
        let docs = root.path().join("public/src/content/docs");
        std::fs::create_dir_all(docs.join("guides")).unwrap();
        std::fs::create_dir_all(docs.join("reference")).unwrap();
        let source = docs.join("guides/current.md");
        std::fs::write(docs.join("guides/sibling.md"), "").unwrap();
        std::fs::write(docs.join("reference/cli.md"), "").unwrap();

        assert_eq!(
            link_error(root.path(), &HashSet::new(), &source, "sibling#heading"),
            None
        );
        assert_eq!(
            link_error(root.path(), &HashSet::new(), &source, "../reference/cli.md"),
            None
        );
    }

    #[test]
    fn internal_routes_must_be_in_the_built_route_set() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("public/src/content/docs/guide.md");
        let known = routes(&["/guides/", "/guides/live/"]);

        assert_eq!(
            link_error(root.path(), &known, &source, "/guides/live/#section"),
            None
        );
        assert!(link_error(root.path(), &known, &source, "/guides/deleted/").is_some());
    }

    #[test]
    fn external_and_fragment_only_links_are_out_of_scope() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("public/src/content/docs/guide.md");

        for target in [
            "https://example.com/guide",
            "mailto:security@example.com",
            "#local-heading",
        ] {
            assert_eq!(
                link_error(root.path(), &HashSet::new(), &source, target),
                None
            );
        }
    }

    #[test]
    fn extraction_skips_fenced_examples_and_accepts_html_links() {
        let text = "[live](/guides/live/)\n```md\n[example](/missing/)\n```\n<a href=\"/reference/\">Reference</a>\n";
        assert_eq!(
            link_targets(text),
            vec![
                (1, "/guides/live/".to_string()),
                (5, "/reference/".to_string())
            ]
        );
    }

    #[test]
    fn route_set_covers_content_pages_static_pages_and_assets() {
        let root = tempfile::tempdir().unwrap();
        for dir in [DOCS_DIR, PAGES_DIR, ASSETS_DIR] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        std::fs::create_dir_all(root.path().join(DOCS_DIR).join("guides")).unwrap();
        std::fs::write(root.path().join(DOCS_DIR).join("guides/index.md"), "").unwrap();
        std::fs::write(root.path().join(DOCS_DIR).join("guides/live.mdx"), "").unwrap();
        std::fs::write(root.path().join(PAGES_DIR).join("pricing.astro"), "").unwrap();
        std::fs::write(root.path().join(PAGES_DIR).join("install.sh.ts"), "").unwrap();
        std::fs::create_dir_all(root.path().join(ASSETS_DIR).join("archive")).unwrap();
        std::fs::write(root.path().join(ASSETS_DIR).join("robots.txt"), "").unwrap();
        std::fs::write(root.path().join(ASSETS_DIR).join("archive/index.html"), "").unwrap();

        let found = built_routes(root.path()).unwrap();
        for route in [
            "/guides",
            "/guides/live",
            "/guides/live.md",
            "/pricing",
            "/install.sh",
            "/robots.txt",
            "/archive",
        ] {
            assert!(found.contains(route), "missing {route} from {found:?}");
        }
    }
}
