//! Host-only, depth-one workload lifecycle admission.

mod activation;
mod journal;
mod lifecycle;
pub mod local_mailboxes;
mod mailbox;
mod template;

pub use activation::ParentActivation;
pub use journal::ActorJournal;
pub use lifecycle::{ActorConstraints, ActorLifecycle, ActorLifecycleInputs};
pub use mailbox::{ActorMailboxes, DerivedChildMailbox};
pub use template::{
    ActorTemplate, ColdLaunch, ExactTemplateCatalog, TemplateDefinition, TemplateFile,
};
