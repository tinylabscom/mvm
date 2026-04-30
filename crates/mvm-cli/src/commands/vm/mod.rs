//! VM lifecycle commands — start, stop, list, attach, exec.

pub(super) mod console;
pub(super) mod diff;
pub(super) mod down;
pub(super) mod exec;
pub(super) mod forward;
pub(super) mod logs;
pub(super) mod ps;
pub(super) mod up;

pub(super) use super::{Cli, shared};
