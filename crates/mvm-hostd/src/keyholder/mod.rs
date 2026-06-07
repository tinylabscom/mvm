//! Host-side secret keyholder (Plan 129 / ADR-067).
//!
//! The keyholder owns the boundary where a workload's `SecretRef`
//! becomes a real credential. Phase B is the value source: the
//! [`SecretResolver`] trait + the single-host [`LocalResolver`]. Phase C
//! adds the signer/injector that uses a resolved value on egress without
//! ever handing it to the guest (claims 12/13).

pub mod admission;
pub mod binding;
pub mod injector;
pub mod resolver;
pub mod signer;
pub mod substitution;

pub use admission::{AssembleError, HandedPlaceholders, assemble_registry};
pub use binding::{BindingStore, FileBindingStore, SecretBindingMeta};
pub use injector::{InjectError, Injector};
pub use resolver::{LocalResolver, ResolveError, SecretResolver};
pub use signer::{SigV4Input, SignError, Signature, Signer, SigningInput};
pub use substitution::{
    PLACEHOLDER_PREFIX, Placeholder, SignDispatchError, SubstituteError, SubstitutionEndpoint,
    SubstitutionRegistry, find_placeholder,
};
