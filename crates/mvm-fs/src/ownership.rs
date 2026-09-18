//! File ownership carried from container image layers into the ext4 image.
//!
//! The layer unpacker writes into a host directory as an unprivileged user. It
//! cannot `chown` what it writes, so the host tree holds the unpacking user's
//! ids and the walk that feeds the image writer never sees the owners the
//! layer's tar headers declared. They are recorded here instead, keyed by guest
//! path, and applied to the walked nodes before the image is built.
//!
//! Layers stack: a later layer's entry replaces an earlier one's owner, a
//! whiteout drops the owners of everything it removes, and an opaque marker
//! drops the owners of a directory's lower-layer contents. A path no layer
//! declared — a parent directory the tar stream implied but never listed —
//! stays root-owned.
//!
//! A path the runtime injects after the layers are stacked is not merely
//! undeclared: a layer is free to name it, and the owner it declares would
//! otherwise land on the injected file. [`OwnerTable::apply`] therefore takes
//! the set of paths the image builder owns ([`RootOwnedPaths`]) and forces
//! those back to root, so an image cannot take the account databases its guest
//! resolves uids through away from root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use crate::ext4::{Node, Owner};

/// Ownership changes one layer makes, in the order its tar stream made them.
///
/// Produced by the unpacker in
/// [`crate::oci::unpack::UnpackReport::ownership`] and folded into an
/// [`OwnerTable`] with [`OwnerTable::absorb`], one layer at a time, in manifest
/// order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerOwnership {
    /// Whiteout targets: each path and everything beneath it was removed from
    /// the lower layers.
    removed: Vec<String>,
    /// Opaque-marker directories: everything beneath each one was removed from
    /// the lower layers, the directory itself kept.
    cleared: Vec<String>,
    entries: Vec<OwnedEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnedEntry {
    /// A directory entry. Writing a directory over a lower-layer directory
    /// merges into it, so the lower layer's children keep their owners.
    Dir { path: String, owner: Owner },
    /// A file, symlink or device node. It replaces whatever the lower layers
    /// had at that path, including a directory and all of its children.
    Leaf { path: String, owner: Owner },
    /// A hardlink shares its target's inode, so the owner the link's header
    /// declares is the owner of both names.
    Hardlink {
        path: String,
        target: String,
        owner: Owner,
    },
}

impl LayerOwnership {
    /// Record a directory entry written at `rel` (relative to the layer root).
    pub(crate) fn record_dir(&mut self, rel: &Path, owner: Owner) {
        self.entries.push(OwnedEntry::Dir {
            path: guest_key(rel),
            owner,
        });
    }

    /// Record a file, symlink or device-node entry written at `rel`.
    pub(crate) fn record_leaf(&mut self, rel: &Path, owner: Owner) {
        self.entries.push(OwnedEntry::Leaf {
            path: guest_key(rel),
            owner,
        });
    }

    /// Record a hardlink at `rel` naming `target` (both relative to the root).
    pub(crate) fn record_hardlink(&mut self, rel: &Path, target: &Path, owner: Owner) {
        self.entries.push(OwnedEntry::Hardlink {
            path: guest_key(rel),
            target: guest_key(target),
            owner,
        });
    }

    /// Record a `.wh.<name>` whiteout that removed `rel` from the lower layers.
    pub(crate) fn record_whiteout(&mut self, rel: &Path) {
        self.removed.push(guest_key(rel));
    }

    /// Record an opaque marker that cleared the lower-layer contents of `dir`.
    pub(crate) fn record_opaque(&mut self, dir: &Path) {
        self.cleared.push(guest_key(dir));
    }

    /// Whether this layer declared or removed anything.
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.cleared.is_empty() && self.entries.is_empty()
    }
}

/// The owner of every path the unpacked layers declared, keyed by guest path
/// (`/`-rooted, the shape [`Node::path`] carries).
///
/// Serialized as a plain path → owner map so the image cache can keep it beside
/// an unpacked tree and rebuild the image later without the layer tarballs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct OwnerTable {
    owners: BTreeMap<String, Owner>,
}

impl OwnerTable {
    /// An empty table: every node stays root-owned.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one layer's changes over the layers absorbed before it.
    ///
    /// Removals apply first. A whiteout only ever removes lower-layer state —
    /// an entry the same layer writes survives its own layer's marker whatever
    /// order the two appear in — so clearing before recording this layer's
    /// entries reproduces exactly what the unpacker left on disk.
    pub fn absorb(&mut self, layer: &LayerOwnership) {
        for path in &layer.removed {
            self.remove_subtree(path);
        }
        for dir in &layer.cleared {
            self.remove_descendants(dir);
        }
        for entry in &layer.entries {
            match entry {
                OwnedEntry::Dir { path, owner } => {
                    self.owners.insert(path.clone(), *owner);
                }
                OwnedEntry::Leaf { path, owner } => {
                    self.remove_subtree(path);
                    self.owners.insert(path.clone(), *owner);
                }
                OwnedEntry::Hardlink {
                    path,
                    target,
                    owner,
                } => {
                    self.remove_subtree(path);
                    self.owners.insert(path.clone(), *owner);
                    self.owners.insert(target.clone(), *owner);
                }
            }
        }
    }

    /// The owner recorded for `guest_path`, or root when none was.
    #[must_use]
    pub fn owner_of(&self, guest_path: &str) -> Owner {
        self.owners.get(guest_path).copied().unwrap_or_default()
    }

    /// Whether every recorded owner is root, so applying the table changes
    /// nothing. A materializer that cannot place owners may still build such a
    /// tree faithfully.
    #[must_use]
    pub fn is_root_only(&self) -> bool {
        self.owners.values().all(Owner::is_root)
    }

    /// Number of paths carrying a non-root owner.
    #[must_use]
    pub fn non_root_count(&self) -> usize {
        self.owners
            .values()
            .filter(|owner| !owner.is_root())
            .count()
    }

    /// Set the owner of each node the table names, except the nodes
    /// `root_owned` claims for the image builder. A node the table does not
    /// name keeps the owner it already carries — root for a walked host tree.
    ///
    /// The claimed nodes are set to root rather than skipped: a node can reach
    /// the image carrying a layer's owner without the table naming it (an
    /// unpack defers a node it could not place on the host tree, owner
    /// included), and skipping would let that owner through.
    pub fn apply(&self, nodes: &mut [Node], root_owned: &RootOwnedPaths) {
        if self.owners.is_empty() && root_owned.is_empty() {
            return;
        }
        for node in nodes {
            if root_owned.claims(node.path()) {
                node.set_owner(Owner::ROOT);
                continue;
            }
            if let Some(owner) = self.owners.get(node.path()) {
                node.set_owner(*owner);
            }
        }
    }

    fn remove_subtree(&mut self, path: &str) {
        self.owners.remove(path);
        self.remove_descendants(path);
    }

    fn remove_descendants(&mut self, dir: &str) {
        let prefix = if dir == "/" {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        let doomed: Vec<String> = self
            .owners
            .range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix))
            .map(|(path, _)| path.clone())
            .collect();
        for path in doomed {
            self.owners.remove(&path);
        }
    }
}

/// The guest paths the image builder owns, whose inodes are root-owned in the
/// built image whatever the layers declared.
///
/// The runtime writes into the unpacked tree after the layers are stacked: the
/// account databases naming the workload uid, the wrapper the guest boots, the
/// trust policy it enforces, the mount points it needs. An image is free to
/// ship a file at any of those paths, and its layer declares an owner for it —
/// so without this set, an image chooses who owns the built `/etc/passwd`.
///
/// Two shapes, because the two differ in what they claim below themselves:
/// a path claims exactly one node, a tree claims a directory and everything
/// beneath it. Mount points are paths — an image's own content under `/tmp`
/// keeps the owner its layer declared — while the directories that exist only
/// to hold injected files are trees.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootOwnedPaths {
    paths: BTreeSet<String>,
    trees: BTreeSet<String>,
}

impl RootOwnedPaths {
    /// Claim nothing: every node keeps the owner its layer declared. What a
    /// tree not built from an image's layers, and so carrying nothing
    /// injected, passes.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Claim exactly the node at `path`.
    #[must_use]
    pub fn with_path(mut self, path: impl AsRef<Path>) -> Self {
        self.paths.insert(guest_key(path.as_ref()));
        self
    }

    /// Claim the directory at `dir` and every node beneath it.
    #[must_use]
    pub fn with_tree(mut self, dir: impl AsRef<Path>) -> Self {
        self.trees.insert(guest_key(dir.as_ref()));
        self
    }

    /// Whether `guest_path` is claimed, directly or by an enclosing tree.
    #[must_use]
    pub fn claims(&self, guest_path: &str) -> bool {
        if self.paths.contains(guest_path) {
            return true;
        }
        self.trees.iter().any(|tree| {
            tree == "/"
                || guest_path == tree
                || guest_path
                    .strip_prefix(tree.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// Whether nothing is claimed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.trees.is_empty()
    }
}

/// Guest-absolute key for a layer-relative path: `./usr/bin/` and `usr/bin`
/// both name `/usr/bin`, matching what the walk of the unpacked tree yields.
fn guest_key(rel: &Path) -> String {
    let segments: Vec<String> = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    format!("/{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVC: Owner = Owner::new(999, 999);
    const OTHER: Owner = Owner::new(1000, 100);

    fn layer(build: impl FnOnce(&mut LayerOwnership)) -> LayerOwnership {
        let mut layer = LayerOwnership::default();
        build(&mut layer);
        layer
    }

    fn table_of(layers: &[LayerOwnership]) -> OwnerTable {
        let mut table = OwnerTable::new();
        for layer in layers {
            table.absorb(layer);
        }
        table
    }

    #[test]
    fn tar_spellings_of_one_path_share_a_key() {
        assert_eq!(guest_key(Path::new("./var/lib/svc/")), "/var/lib/svc");
        assert_eq!(guest_key(Path::new("var/lib/svc")), "/var/lib/svc");
        assert_eq!(guest_key(Path::new("./")), "/");
    }

    #[test]
    fn a_later_layer_overrides_an_earlier_owner() {
        let table = table_of(&[
            layer(|l| l.record_leaf(Path::new("etc/app.conf"), SVC)),
            layer(|l| l.record_leaf(Path::new("etc/app.conf"), OTHER)),
        ]);
        assert_eq!(table.owner_of("/etc/app.conf"), OTHER);
    }

    #[test]
    fn a_whiteout_drops_the_owners_of_everything_it_removed() {
        let table = table_of(&[
            layer(|l| {
                l.record_dir(Path::new("var/lib/svc"), SVC);
                l.record_leaf(Path::new("var/lib/svc/state"), SVC);
                l.record_leaf(Path::new("var/lib/svcx"), SVC);
            }),
            layer(|l| l.record_whiteout(Path::new("var/lib/svc"))),
        ]);
        assert_eq!(table.owner_of("/var/lib/svc"), Owner::ROOT);
        assert_eq!(table.owner_of("/var/lib/svc/state"), Owner::ROOT);
        assert_eq!(
            table.owner_of("/var/lib/svcx"),
            SVC,
            "a sibling sharing the name as a prefix is not beneath the whiteout"
        );
    }

    #[test]
    fn a_whiteout_never_removes_an_entry_from_its_own_layer() {
        let table = table_of(&[
            layer(|l| l.record_leaf(Path::new("data"), OTHER)),
            layer(|l| {
                l.record_leaf(Path::new("data"), SVC);
                l.record_whiteout(Path::new("data"));
            }),
        ]);
        assert_eq!(table.owner_of("/data"), SVC);
    }

    #[test]
    fn an_opaque_marker_clears_lower_contents_and_keeps_the_directory() {
        let table = table_of(&[
            layer(|l| {
                l.record_dir(Path::new("srv"), SVC);
                l.record_leaf(Path::new("srv/old"), SVC);
            }),
            layer(|l| {
                l.record_opaque(Path::new("srv"));
                l.record_leaf(Path::new("srv/new"), OTHER);
            }),
        ]);
        assert_eq!(table.owner_of("/srv"), SVC);
        assert_eq!(table.owner_of("/srv/old"), Owner::ROOT);
        assert_eq!(table.owner_of("/srv/new"), OTHER);
    }

    #[test]
    fn a_file_replacing_a_directory_drops_the_directory_children() {
        let table = table_of(&[
            layer(|l| {
                l.record_dir(Path::new("opt/app"), SVC);
                l.record_leaf(Path::new("opt/app/bin"), SVC);
            }),
            layer(|l| l.record_leaf(Path::new("opt/app"), OTHER)),
        ]);
        assert_eq!(table.owner_of("/opt/app"), OTHER);
        assert_eq!(table.owner_of("/opt/app/bin"), Owner::ROOT);
    }

    #[test]
    fn a_directory_over_a_directory_keeps_the_lower_children() {
        let table = table_of(&[
            layer(|l| {
                l.record_dir(Path::new("home/app"), SVC);
                l.record_leaf(Path::new("home/app/.profile"), SVC);
            }),
            layer(|l| l.record_dir(Path::new("home/app"), OTHER)),
        ]);
        assert_eq!(table.owner_of("/home/app"), OTHER);
        assert_eq!(table.owner_of("/home/app/.profile"), SVC);
    }

    #[test]
    fn a_hardlink_gives_both_names_the_link_owner() {
        let table = table_of(&[layer(|l| {
            l.record_leaf(Path::new("usr/bin/a"), OTHER);
            l.record_hardlink(Path::new("usr/bin/b"), Path::new("usr/bin/a"), SVC);
        })]);
        assert_eq!(table.owner_of("/usr/bin/a"), SVC);
        assert_eq!(table.owner_of("/usr/bin/b"), SVC);
    }

    #[test]
    fn apply_sets_named_nodes_and_leaves_the_rest_alone() {
        let table = table_of(&[layer(|l| l.record_dir(Path::new("data"), SVC))]);
        let mut nodes = vec![
            Node::Dir {
                path: "/data".into(),
                mode: 0o700,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
            Node::Dir {
                path: "/implied".into(),
                mode: 0o755,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
        ];
        table.apply(&mut nodes, &RootOwnedPaths::none());
        assert_eq!(nodes[0].owner(), SVC);
        assert_eq!(nodes[1].owner(), Owner::ROOT);
    }

    fn file(path: &str, owner: Owner) -> Node {
        Node::File {
            path: path.into(),
            data: Vec::new(),
            mode: 0o644,
            xattrs: Vec::new(),
            owner,
        }
    }

    #[test]
    fn a_claimed_path_stays_root_owned_whatever_the_layer_declared() {
        let table = table_of(&[layer(|l| {
            l.record_leaf(Path::new("etc/passwd"), OTHER);
            l.record_leaf(Path::new("etc/hosts"), OTHER);
        })]);
        let claimed = RootOwnedPaths::none().with_path("etc/passwd");
        let mut nodes = vec![
            file("/etc/passwd", Owner::ROOT),
            file("/etc/hosts", Owner::ROOT),
        ];
        table.apply(&mut nodes, &claimed);
        assert_eq!(nodes[0].owner(), Owner::ROOT);
        assert_eq!(
            nodes[1].owner(),
            OTHER,
            "a path the builder does not claim keeps its declared owner"
        );
    }

    #[test]
    fn a_claimed_node_arriving_already_owned_is_set_back_to_root() {
        // A deferred node carries the owner its layer declared, without the
        // table naming the path, so skipping instead of setting would let it
        // through.
        let mut nodes = vec![file("/etc/group", SVC)];
        OwnerTable::new().apply(&mut nodes, &RootOwnedPaths::none().with_path("etc/group"));
        assert_eq!(nodes[0].owner(), Owner::ROOT);
    }

    #[test]
    fn a_claimed_tree_covers_its_contents_and_a_path_does_not() {
        let claimed = RootOwnedPaths::none()
            .with_tree("usr/lib/mvm")
            .with_path("tmp");
        assert!(claimed.claims("/usr/lib/mvm"));
        assert!(claimed.claims("/usr/lib/mvm/wrappers/oci-entrypoint"));
        assert!(
            !claimed.claims("/usr/lib/mvmx"),
            "a sibling sharing the name as a prefix is not beneath the tree"
        );
        assert!(claimed.claims("/tmp"));
        assert!(
            !claimed.claims("/tmp/image-content"),
            "an image's own content under a claimed mount point keeps its owner"
        );
        assert!(RootOwnedPaths::none().is_empty());
        assert!(!claimed.is_empty());
    }

    #[test]
    fn tar_spellings_of_a_claimed_path_share_the_guest_key() {
        let claimed = RootOwnedPaths::none()
            .with_path("./etc/passwd")
            .with_tree("./etc/mvm/");
        assert!(claimed.claims("/etc/passwd"));
        assert!(claimed.claims("/etc/mvm/verb-trust.json"));
    }

    #[test]
    fn root_only_is_judged_on_recorded_owners() {
        let root = table_of(&[layer(|l| {
            l.record_leaf(Path::new("etc/passwd"), Owner::ROOT)
        })]);
        assert!(root.is_root_only());
        assert_eq!(root.non_root_count(), 0);
        let mixed = table_of(&[layer(|l| {
            l.record_leaf(Path::new("etc/passwd"), Owner::ROOT);
            l.record_dir(Path::new("data"), SVC);
        })]);
        assert!(!mixed.is_root_only());
        assert_eq!(mixed.non_root_count(), 1);
    }

    #[test]
    fn the_table_round_trips_through_json() {
        let table = table_of(&[layer(|l| {
            l.record_dir(Path::new("data"), SVC);
            l.record_leaf(Path::new("big"), Owner::new(70_000, 70_001));
        })]);
        let encoded = serde_json::to_vec(&table).unwrap();
        let decoded: OwnerTable = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, table);
    }
}
