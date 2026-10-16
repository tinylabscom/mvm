//! Deterministic Git fixtures without commands, hooks, templates or config.
use sha1::{Digest, Sha1};
use std::io::Write;
use std::path::Path;

pub fn init(root: &Path) {
    for dir in ["objects", "refs/heads"] {
        std::fs::create_dir_all(root.join(".git").join(dir)).unwrap();
    }
    std::fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    std::fs::write(
        root.join(".git/config"),
        b"[core]\nrepositoryformatversion = 0\nbare = false\n",
    )
    .unwrap();
}

fn object(root: &Path, kind: &str, body: &[u8]) -> [u8; 20] {
    let mut bytes = format!("{kind} {}\0", body.len()).into_bytes();
    bytes.extend(body);
    let id: [u8; 20] = Sha1::digest(&bytes).into();
    let hex = hex::encode(id);
    let path = root.join(".git/objects").join(&hex[..2]).join(&hex[2..]);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&bytes).unwrap();
    std::fs::write(path, encoder.finish().unwrap()).unwrap();
    id
}

type Entry = (Vec<u8>, u32, [u8; 20]);

fn tree(root: &Path, dir: &Path, index: &mut Vec<Entry>) -> [u8; 20] {
    let mut children = Vec::new();
    for child in std::fs::read_dir(dir).unwrap() {
        let child = child.unwrap();
        if child.file_name() == ".git" {
            continue;
        }
        let path = child.path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let (mode, id) = if meta.is_dir() {
            (0o040000, tree(root, &path, index))
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path).unwrap();
            (
                0o120000,
                object(root, "blob", target.as_os_str().as_encoded_bytes()),
            )
        } else {
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o100 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            (
                if executable { 0o100755 } else { 0o100644 },
                object(root, "blob", &std::fs::read(&path).unwrap()),
            )
        };
        if mode != 0o040000 {
            index.push((
                path.strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|part| part.as_os_str().as_encoded_bytes().to_vec())
                    .collect::<Vec<_>>()
                    .join(&b'/'),
                mode,
                id,
            ));
        }
        let name = child.file_name().as_encoded_bytes().to_vec();
        let mut sort_key = name.clone();
        if mode == 0o040000 {
            sort_key.push(b'/');
        }
        children.push((sort_key, name, mode, id));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    let mut body = Vec::new();
    for (_, name, mode, id) in children {
        body.extend(format!("{mode:o} ").as_bytes());
        body.extend(name);
        body.push(0);
        body.extend(id);
    }
    object(root, "tree", &body)
}

pub fn stage(root: &Path) {
    let mut entries = Vec::new();
    tree(root, root, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut bytes = b"DIRC".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    for (path, mode, id) in entries {
        let start = bytes.len();
        bytes.extend([0; 24]);
        bytes.extend(mode.to_be_bytes());
        bytes.extend([0; 12]);
        bytes.extend(id);
        bytes.extend(u16::try_from(path.len().min(4095)).unwrap().to_be_bytes());
        bytes.extend(path);
        bytes.push(0);
        bytes.resize(bytes.len() + (8 - (bytes.len() - start) % 8) % 8, 0);
    }
    bytes.extend(Sha1::digest(&bytes));
    std::fs::write(root.join(".git/index"), bytes).unwrap();
}

pub fn commit(root: &Path, message: &str) {
    let tree = tree(root, root, &mut Vec::new());
    let head = root.join(".git/refs/heads/main");
    let parent = std::fs::read_to_string(&head).ok();
    let mut body = format!("tree {}\n", hex::encode(tree));
    if let Some(parent) = parent {
        body.push_str(&format!("parent {}\n", parent.trim()));
    }
    let actor = "mvm-test <mvm-test@example.invalid> 1700000000 +0000";
    body.push_str(&format!("author {actor}\ncommitter {actor}\n\n{message}\n"));
    let id = object(root, "commit", body.as_bytes());
    std::fs::write(head, format!("{}\n", hex::encode(id))).unwrap();
}

pub fn commit_all(root: &Path, message: &str) {
    if !root.join(".git").exists() {
        init(root);
    }
    stage(root);
    commit(root, message);
}

#[test]
fn image_source_fixture_preserves_commit_bytes_without_ambient_git() {
    use std::io::Read;
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    let toxic = tmp.path().join("toxic.config");
    std::fs::write(&toxic, b"[core]\nautocrlf = garbage\n").unwrap();
    env.set("GIT_CONFIG_SYSTEM", &toxic);
    env.set("GIT_CONFIG_GLOBAL", &toxic);
    env.set("GIT_CONFIG_NOSYSTEM", "false");
    env.set("GIT_AUTHOR_NAME", "ambient");
    env.set("GIT_COMMITTER_DATE", "invalid");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a"), b"base\n").unwrap();
    commit_all(&root, "fixture");
    let id = "c0defb9bbe5a4685583e2357ca16af4a44960d36";
    assert_eq!(
        std::fs::read_to_string(root.join(".git/refs/heads/main")).unwrap(),
        format!("{id}\n")
    );
    let compressed =
        std::fs::read(root.join(".git/objects").join(&id[..2]).join(&id[2..])).unwrap();
    let mut bytes = Vec::new();
    flate2::read::ZlibDecoder::new(compressed.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();
    let body = concat!(
        "tree 7660e9e0062a6900be538815286ace2e43f9114c\n",
        "author mvm-test <mvm-test@example.invalid> 1700000000 +0000\n",
        "committer mvm-test <mvm-test@example.invalid> 1700000000 +0000\n\nfixture\n"
    );
    assert_eq!(
        bytes,
        [
            format!("commit {}\0", body.len()).as_bytes(),
            body.as_bytes()
        ]
        .concat()
    );
    commit_all(&root, "next");
    let next = std::fs::read_to_string(root.join(".git/refs/heads/main")).unwrap();
    assert_ne!(next.trim(), id);

    let shared = tmp.path().join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(shared.join("a.txt"), b"tracked\n").unwrap();
    commit_all(&shared, "fixture");
    assert_eq!(
        std::fs::read_to_string(shared.join(".git/refs/heads/main")).unwrap(),
        "d40e7ed3d340d03c7ad6910387c60943c0ff3d0d\n"
    );
}
