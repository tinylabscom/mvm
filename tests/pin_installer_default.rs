//! Tests for `scripts/pin-installer-default.sh`, the only writer of
//! install.sh's offline fallback: `DEFAULT_VERSION` and the archive hash a
//! fresh host trusts for it.
//!
//! `gh` and `cosign` are stood in by scripts reading a fixture directory, so
//! what is under test is the script's decisions: which release it will pin,
//! what it refuses, and that a refusal leaves the installer untouched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TARGETS: [(&str, &str); 3] = [
    (
        "aarch64-apple-darwin",
        "DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU",
    ),
    (
        "aarch64-unknown-linux-gnu",
        "DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A digest unique to a tag and target, so a hash pinned from the wrong
/// release or the wrong row is caught.
fn digest(tag: &str, target: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{tag}/{target}")))
}

/// Where a release's fixture files live.
fn release_dir(fixture: &Path, tag: &str) -> PathBuf {
    fixture.join("releases").join(tag)
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(fixture.bin()).unwrap();
        fixture.write_tool(
            "gh",
            r#"#!/bin/sh
case "$1 $2" in
  "release view")
    [ -f "$FIXTURE/releases/$3/state" ] || { echo "release not found" >&2; exit 1; }
    cat "$FIXTURE/releases/$3/state" ;;
  "release download")
    [ -d "$FIXTURE/releases/$3" ] || exit 1
    for f in "$FIXTURE/releases/$3"/checksums-sha256.txt*; do
      [ -f "$f" ] && cp "$f" "$9/"
    done
    exit 0 ;;
  api*)
    jq -r "$4" "$FIXTURE/releases.json" ;;
  *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
"#,
        );
        fixture.write_tool(
            "cosign",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FIXTURE/cosign.log\"\nexit \"${FAKE_COSIGN_STATUS:-0}\"\n",
        );
        std::fs::copy(repo_root().join("install.sh"), fixture.installer()).unwrap();
        fixture
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn installer(&self) -> PathBuf {
        self.path().join("install.sh")
    }

    fn write_tool(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.bin().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Publish `tag` in `state` (`promoted`, `prerelease` or `draft`), with a
    /// checksum manifest covering every target and, when `signed`, a bundle.
    fn publish(&self, tag: &str, state: &str, signed: bool) {
        let dir = release_dir(self.path(), tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("state"), format!("{state}\n")).unwrap();
        let manifest: String = TARGETS
            .iter()
            .map(|(target, _)| format!("{}  mvmctl-{target}.tar.gz\n", digest(tag, target)))
            .collect();
        std::fs::write(dir.join("checksums-sha256.txt"), manifest).unwrap();
        if signed {
            std::fs::write(dir.join("checksums-sha256.txt.bundle"), "bundle").unwrap();
        }
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut command = Command::new("sh");
        command
            .arg(repo_root().join("scripts/pin-installer-default.sh"))
            .args(args)
            .arg(self.installer())
            .env("FIXTURE", self.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.bin().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn installer_text(&self) -> String {
        std::fs::read_to_string(self.installer()).unwrap()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_pinned_to(installer: &str, tag: &str) {
    assert!(
        installer
            .lines()
            .any(|line| line == format!("DEFAULT_VERSION=\"{tag}\"")),
        "DEFAULT_VERSION must name {tag}"
    );
    for (target, variable) in TARGETS {
        let want = format!("{variable}=\"{}\"", digest(tag, target));
        assert!(
            installer.lines().any(|line| line == want),
            "{variable} must carry {tag}'s {target} hash"
        );
    }
}

#[test]
fn a_promoted_signed_release_is_pinned_with_its_own_hashes() {
    let fixture = Fixture::new();
    fixture.publish("v9.1.0", "promoted", true);
    let before = fixture.installer_text();

    let output = fixture.run(&["v9.1.0"], &[]);

    assert!(output.status.success(), "{}", stderr(&output));
    let after = fixture.installer_text();
    assert_pinned_to(&after, "v9.1.0");
    let changed = before
        .lines()
        .zip(after.lines())
        .filter(|(old, new)| old != new)
        .count();
    assert!(
        changed <= 4 && before.lines().count() == after.lines().count(),
        "only the four pinned lines may change"
    );
    let cosign = std::fs::read_to_string(fixture.path().join("cosign.log")).unwrap();
    assert!(
        cosign.contains(
            "--certificate-identity https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v9.1.0"
        ),
        "the manifest must be verified under the identity for exactly this tag: {cosign}"
    );

    let check = fixture.run(&["--check", "v9.1.0"], &[]);
    assert!(check.status.success(), "{}", stderr(&check));
}

#[test]
fn check_fails_when_the_installer_carries_another_pin() {
    let fixture = Fixture::new();
    fixture.publish("v9.1.0", "promoted", true);
    let before = fixture.installer_text();

    let output = fixture.run(&["--check", "v9.1.0"], &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("expected DEFAULT_VERSION=\"v9.1.0\""));
    assert_eq!(
        fixture.installer_text(),
        before,
        "--check must write nothing"
    );
}

#[test]
fn newest_picks_the_newest_promoted_release_publishing_every_target() {
    let fixture = Fixture::new();
    for tag in ["v9.10.0", "v9.9.0", "v9.11.0"] {
        fixture.publish(tag, "promoted", true);
    }
    let all: Vec<String> = TARGETS
        .iter()
        .map(|(target, _)| format!("mvmctl-{target}.tar.gz"))
        .collect();
    let release = |tag: &str, prerelease: bool, assets: &[String]| {
        serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": prerelease,
            "assets": assets.iter().map(|name| serde_json::json!({ "name": name })).collect::<Vec<_>>(),
        })
    };
    let releases = serde_json::json!([
        release("boot-image/v10.0.0", false, &all),
        release("v9.12.0-rc.1", true, &all),
        // Stable, but still staged: its first-run smoke has not passed.
        release("v9.11.1", true, &all),
        // Promoted, but missing a target.
        release("v9.11.0", false, &all[..2]),
        release("v9.9.0", false, &all),
        release("v9.10.0", false, &all),
    ]);
    std::fs::write(
        fixture.path().join("releases.json"),
        serde_json::to_string(&releases).unwrap(),
    )
    .unwrap();

    let output = fixture.run(&["--newest"], &[]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_pinned_to(&fixture.installer_text(), "v9.10.0");
}

#[test]
fn refusals_leave_the_installer_untouched() {
    let fixture = Fixture::new();
    fixture.publish("v9.2.0", "prerelease", true);
    fixture.publish("v9.3.0", "draft", true);
    fixture.publish("v9.4.0", "promoted", false);
    fixture.publish("v9.5.0", "promoted", true);
    let before = fixture.installer_text();

    for (args, envs, reason) in [
        (
            &["v9.2.0"][..],
            &[][..],
            "v9.2.0 is still a prerelease: only a release the workflow promoted",
        ),
        (&["v9.3.0"][..], &[][..], "v9.3.0 is still a draft"),
        (
            &["v9.4.0"][..],
            &[][..],
            "v9.4.0 publishes no signature for its checksum manifest",
        ),
        (
            &["v9.5.0"][..],
            &[("FAKE_COSIGN_STATUS", "1")][..],
            "the checksum manifest of v9.5.0 is not signed by its release workflow",
        ),
        (
            &["v9.6.0-rc.1"][..],
            &[][..],
            "must be a stable vMAJOR.MINOR.PATCH tag",
        ),
        (&["v9.7.0"][..], &[][..], "has no release v9.7.0"),
    ] {
        let output = fixture.run(args, envs);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?} must be refused: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(reason),
            "{args:?} must be refused for its own reason ({reason}): {}",
            stderr(&output)
        );
        assert_eq!(
            fixture.installer_text(),
            before,
            "{args:?}: a refusal must not touch the installer"
        );
    }
}
