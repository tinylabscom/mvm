//! Source selection and one-launch runtime identity at the CLI admission handoff.

/// The source choices held while constructing the transient command request.
pub(super) struct ImageSelection {
    pub(super) image_ref: Option<String>,
    pub(super) prod: bool,
    pub(super) runtime_pack: bool,
}
