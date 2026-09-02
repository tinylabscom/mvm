//! ext4rs — pure-Rust ext4 filesystem driver.
//!
//! Exposes a stable C ABI (`fs_ext4_*`) via [`capi`] so FFI consumers
//! (Swift/C/Go/…) can link `libfs_ext4.a` and `#include "fs_ext4.h"`.
//!
//! Architecture (read-only Phase 1):
//! - [`block_io`] — abstract trait for reading device blocks
//! - [`superblock`] — parse + validate the on-disk superblock
//! - [`features`] — feature flag inventory (COMPAT/INCOMPAT/RO_COMPAT)
//! - [`bgd`] — block group descriptor parsing
//! - [`inode`] — inode + extra fields parsing
//! - [`extent`] — extent tree traversal (leaf/internal nodes, uninitialized extents)
//! - [`dir`] — directory entries (linear and HTree)
//! - [`hash`] — htree hash functions (legacy / half_md4 / tea)
//! - [`fs`] — top-level filesystem handle, file/dir lookup, read API
//! - [`capi`] — C ABI exports matching `include/fs_ext4.h`

#![allow(dead_code)]
// many spec items not yet wired through
// `doc_lazy_continuation` disagrees with the existing numbered-list
// indentation in several module preambles; the content is fine.
#![allow(clippy::doc_lazy_continuation)]

pub mod acl;
pub mod alloc;
pub mod bgd;
pub mod block_cache;
pub mod block_io;
pub mod casefold;
pub mod checksum;
pub mod dir;
pub mod ea_inode;
pub mod error;
pub mod extent;
pub mod extent_mut;
pub mod features;
pub mod file_io;
pub mod file_mut;
pub mod fs;
pub mod fs_core_bridge;
pub mod fsck;
pub mod hash;
pub mod htree;
pub mod htree_mut;
pub mod indirect;
pub mod indirect_mut;
pub mod inline_data;
pub mod inode;
pub mod jbd2;
pub mod journal;
pub mod journal_apply;
pub mod journal_writer;
pub mod mkfs;
pub mod path;
pub mod superblock;
pub mod transaction;
pub mod verify;
pub mod xattr;

// C ABI exports — surface defined in `include/fs_ext4.h`.
pub mod capi;

pub use error::{Error, Result};
pub use fs::Filesystem;
pub use superblock::Superblock;
