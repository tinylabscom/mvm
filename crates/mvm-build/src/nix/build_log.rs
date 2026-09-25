//! Condense a `nix build` log into a one-line progress summary.
//!
//! A builder guest runs `nix build --print-build-logs` with its stderr on the
//! console, so the host can tail `console.log` while the build runs. The raw
//! log is thousands of compiler lines; what someone waiting on it wants is
//! which derivation is building and how far through the plan it is. This
//! module reads the lines nix itself prints around the build output —
//! `these N derivations will be built`, `building '<drv>'`, `copying path` —
//! and keeps the counts. It never fails: a line it does not recognise is not
//! progress, and the summary simply does not move.

/// One recognised line of a nix build log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NixLogEvent {
    /// `these N derivations will be built:` (or the singular form).
    BuildsPlanned(u32),
    /// `these N paths will be fetched (…)` (or the singular form).
    FetchesPlanned(u32),
    /// `building '/nix/store/<hash>-<name>.drv'...`
    Building(String),
    /// `copying path '/nix/store/<hash>-<name>' from '<cache>'...`
    Fetching(String),
    /// `<name>> <build output>` — a line of a derivation's own build log.
    BuildOutput(String),
    /// `stage0-init: <message>` — the bootstrap guest narrating its own steps.
    GuestStep(String),
}

impl NixLogEvent {
    /// Recognise one console line. Terminal escapes and carriage returns are
    /// stripped first, since nix and the guest console both emit them.
    pub fn parse(raw: &str) -> Option<Self> {
        let cleaned = strip_terminal_noise(raw);
        let line = cleaned.trim();
        if line.is_empty() {
            return None;
        }
        if let Some(rest) = line.strip_prefix("stage0-init: ") {
            return Some(Self::GuestStep(rest.trim().to_string()));
        }
        if let Some(count) = planned_count(line, "derivation", "will be built") {
            return Some(Self::BuildsPlanned(count));
        }
        if let Some(count) = planned_count(line, "path", "will be fetched") {
            return Some(Self::FetchesPlanned(count));
        }
        if let Some(rest) = line.strip_prefix("building '") {
            return quoted_store_name(rest).map(Self::Building);
        }
        if let Some(rest) = line.strip_prefix("copying path '") {
            return quoted_store_name(rest).map(Self::Fetching);
        }
        build_output_prefix(line).map(|name| Self::BuildOutput(name.to_string()))
    }
}

/// `these 42 derivations will be built:` → 42; `this derivation will be
/// built:` → 1. `noun` is singular; the plural adds an `s`.
fn planned_count(line: &str, noun: &str, verb: &str) -> Option<u32> {
    if line.starts_with(&format!("this {noun} {verb}")) {
        return Some(1);
    }
    let rest = line.strip_prefix("these ")?;
    let (count, rest) = rest.split_once(' ')?;
    rest.starts_with(&format!("{noun}s {verb}"))
        .then(|| count.parse().ok())
        .flatten()
}

/// The package name out of `'/nix/store/<hash>-<name>[.drv]'…`, with the hash
/// and a `.drv` suffix dropped.
fn quoted_store_name(rest: &str) -> Option<String> {
    let (path, _) = rest.split_once('\'')?;
    let base = path.strip_prefix("/nix/store/")?;
    let name = base.split_once('-').map_or(base, |(_, name)| name);
    let name = name.strip_suffix(".drv").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_string())
}

/// The `<name>` of a `<name>> output` build-log line. Derivation names carry
/// no spaces, which is what separates them from ordinary console lines that
/// happen to contain `> `.
fn build_output_prefix(line: &str) -> Option<&str> {
    const MAX_NAME: usize = 128;
    let (name, _) = line.split_once("> ")?;
    let plausible = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'));
    plausible.then_some(name)
}

/// Drop ANSI escape sequences and carriage returns.
fn strip_terminal_noise(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // A CSI sequence ends at its first byte in `@`..=`~`.
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
            }
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// What the build log last said the guest was working on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CurrentWork {
    Building(String),
    Fetching(String),
}

/// Whether a build-log prefix belongs to the derivation already shown. Nix
/// prefixes build output with the package name without its version
/// (`busybox>`), while the `building` line names the full derivation
/// (`busybox-1.36`), so both forms have to match.
fn is_same_derivation(current: &str, prefix: &str) -> bool {
    current == prefix
        || current
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Running totals for one or more `nix build` invocations sharing a console.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NixBuildProgress {
    builds_planned: u32,
    builds_started: u32,
    fetches_planned: u32,
    fetches_started: u32,
    current: Option<CurrentWork>,
    guest_step: Option<String>,
}

impl NixBuildProgress {
    /// Fold in one console line. Returns whether the summary may have changed.
    pub fn observe(&mut self, line: &str) -> bool {
        let Some(event) = NixLogEvent::parse(line) else {
            return false;
        };
        match event {
            NixLogEvent::BuildsPlanned(n) => {
                self.builds_planned = self.builds_planned.saturating_add(n);
            }
            NixLogEvent::FetchesPlanned(n) => {
                self.fetches_planned = self.fetches_planned.saturating_add(n);
            }
            NixLogEvent::Building(name) => {
                self.builds_started = self.builds_started.saturating_add(1);
                self.current = Some(CurrentWork::Building(name));
            }
            NixLogEvent::Fetching(name) => {
                self.fetches_started = self.fetches_started.saturating_add(1);
                // Once a build is under way, substitutes fetched for later
                // derivations are background detail, not the headline.
                if !matches!(self.current, Some(CurrentWork::Building(_))) {
                    self.current = Some(CurrentWork::Fetching(name));
                }
            }
            NixLogEvent::BuildOutput(name) => {
                if let Some(CurrentWork::Building(current)) = &self.current
                    && is_same_derivation(current, &name)
                {
                    return false;
                }
                self.current = Some(CurrentWork::Building(name));
            }
            NixLogEvent::GuestStep(step) => self.guest_step = Some(step),
        }
        true
    }

    /// `building linux-6.12 (3/42) · fetched 118/118 paths`, or the guest's
    /// own last step before nix has said anything. `None` until either exists.
    pub fn summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        match &self.current {
            Some(CurrentWork::Building(name)) => parts.push(match self.build_counter() {
                Some(counter) => format!("building {name} ({counter})"),
                None => format!("building {name}"),
            }),
            Some(CurrentWork::Fetching(name)) => parts.push(format!("fetching {name}")),
            None => {}
        }
        if self.fetches_started > 0 {
            parts.push(match self.fetches_planned {
                0 => format!("fetched {} paths", self.fetches_started),
                planned => format!("fetched {}/{planned} paths", self.fetches_started),
            });
        }
        if parts.is_empty() {
            return self.guest_step.clone();
        }
        Some(parts.join(" · "))
    }

    /// `3/42`, or `3 started` before nix has printed its plan; `None` while
    /// only build output (no `building` line) has been seen. A second `nix
    /// build` on the same console can start more than the first one planned,
    /// so the denominator never falls below the numerator.
    fn build_counter(&self) -> Option<String> {
        match (self.builds_started, self.builds_planned) {
            (0, _) => None,
            (started, 0) => Some(format!("{started} started")),
            (started, planned) => Some(format!("{started}/{}", planned.max(started))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_are_counted_in_both_grammatical_numbers() {
        assert_eq!(
            NixLogEvent::parse("these 42 derivations will be built:"),
            Some(NixLogEvent::BuildsPlanned(42))
        );
        assert_eq!(
            NixLogEvent::parse("this derivation will be built:"),
            Some(NixLogEvent::BuildsPlanned(1))
        );
        assert_eq!(
            NixLogEvent::parse(
                "these 118 paths will be fetched (212.3 MiB download, 1.1 GiB unpacked):"
            ),
            Some(NixLogEvent::FetchesPlanned(118))
        );
        assert_eq!(
            NixLogEvent::parse("this path will be fetched (0.1 MiB download, 0.4 MiB unpacked):"),
            Some(NixLogEvent::FetchesPlanned(1))
        );
    }

    #[test]
    fn store_paths_lose_their_hash_and_drv_suffix() {
        assert_eq!(
            NixLogEvent::parse(
                "building '/nix/store/0c8kdf4c3xg9ssw3kkwf2gcwlk1s1a8w-linux-6.12.8.drv'..."
            ),
            Some(NixLogEvent::Building("linux-6.12.8".into()))
        );
        assert_eq!(
            NixLogEvent::parse(
                "copying path '/nix/store/8vsg0mbm7x6mfvnb1dnnjy8iwdg5hrxb-glibc-2.40' from 'https://cache.nixos.org'..."
            ),
            Some(NixLogEvent::Fetching("glibc-2.40".into()))
        );
    }

    #[test]
    fn build_output_lines_name_their_derivation() {
        assert_eq!(
            NixLogEvent::parse("linux> CC      kernel/fork.o"),
            Some(NixLogEvent::BuildOutput("linux".into()))
        );
        // A prompt-like line with a space before `> ` is not a build log.
        assert_eq!(NixLogEvent::parse("some text> more"), None);
    }

    #[test]
    fn escapes_and_carriage_returns_do_not_hide_a_line() {
        assert_eq!(
            NixLogEvent::parse("\x1b[2mlinux> \x1b[0mLD vmlinux\r"),
            Some(NixLogEvent::BuildOutput("linux".into()))
        );
    }

    #[test]
    fn unrelated_and_kernel_lines_are_not_progress() {
        for line in [
            "",
            "[    0.000000] Booting Linux on physical CPU 0x0000000000",
            "warning: Git tree '/work' is dirty",
            "building",
            "copying path 'relative' from 'x'",
        ] {
            assert_eq!(NixLogEvent::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn the_summary_tracks_the_current_derivation_against_the_plan() {
        let mut progress = NixBuildProgress::default();
        assert_eq!(progress.summary(), None);

        progress.observe("stage0-init: evaluating the builder flake");
        assert_eq!(
            progress.summary().as_deref(),
            Some("evaluating the builder flake")
        );

        progress.observe("these 3 derivations will be built:");
        progress.observe("these 2 paths will be fetched (1.0 MiB download, 2.0 MiB unpacked):");
        progress
            .observe("copying path '/nix/store/aaaa-glibc-2.40' from 'https://cache.nixos.org'...");
        assert_eq!(
            progress.summary().as_deref(),
            Some("fetching glibc-2.40 · fetched 1/2 paths")
        );

        progress.observe("building '/nix/store/bbbb-busybox-1.36.drv'...");
        progress.observe("busybox> CC applets/applets.o");
        progress.observe("building '/nix/store/cccc-linux-6.12.drv'...");
        assert_eq!(
            progress.summary().as_deref(),
            Some("building linux-6.12 (2/3) · fetched 1/2 paths")
        );
    }

    #[test]
    fn a_build_without_a_plan_line_counts_what_started() {
        let mut progress = NixBuildProgress::default();
        progress.observe("building '/nix/store/aaaa-hello.drv'...");
        assert_eq!(
            progress.summary().as_deref(),
            Some("building hello (1 started)")
        );
    }

    #[test]
    fn build_output_alone_names_the_derivation_without_a_counter() {
        let mut progress = NixBuildProgress::default();
        progress.observe("hello> compiling");
        assert_eq!(progress.summary().as_deref(), Some("building hello"));
    }

    #[test]
    fn repeated_output_from_the_same_derivation_does_not_change_the_summary() {
        let mut progress = NixBuildProgress::default();
        assert!(progress.observe("building '/nix/store/aaaa-hello.drv'..."));
        assert!(!progress.observe("hello> compiling"));
        assert!(progress.observe("building '/nix/store/bbbb-busybox-1.36.drv'..."));
        assert!(
            !progress.observe("busybox> CC applets.o"),
            "an unversioned prefix is the same derivation"
        );
        assert!(progress.observe("bash> configuring"));
        assert!(!progress.observe("[    3.1] random kernel line"));
    }
}
