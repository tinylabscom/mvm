//! Host-side secret keyholder.
//!
//! The keyholder owns the boundary where a workload's `SecretRef`
//! becomes a real credential. The value source is the `SecretResolver`
//! trait + the single-host `LocalResolver`; the signer/injector then
//! uses a resolved value on egress without ever handing it to the guest
//! (claims 12/13).

pub mod admission;
pub mod binding;
pub mod injector;
pub mod remote_resolver;
pub mod resolver;
pub mod signer;
pub mod sigv4;
pub mod substitution;

pub use admission::{AssembleError, HandedPlaceholders, assemble_registry, secret_placeholder_env};
pub use binding::{BindingStore, FileBindingStore, SecretBindingMeta};
pub use injector::{InjectError, Injector};
pub use remote_resolver::RemoteResolver;
pub use resolver::{LocalResolver, ResolveError, SecretResolver};
pub use signer::{SigV4Input, SignError, Signature, Signer, SigningInput};
pub use sigv4::{SigV4BuildError, build_sigv4_input};
pub use substitution::{
    NetworkEndpoint, Placeholder, SECRET_PLACEHOLDER_PREFIX, SignDispatchError, SubstituteError,
    SubstitutionRegistry, find_placeholder,
};

/// Re-exported so a caller who only depends on `mvm-hostd` (e.g. mvmd,
/// which registers `SecretBindingMeta`s for a VM's substitution endpoint)
/// can name `SecretBindingMeta::auth_type`'s type without also taking a
/// direct `mvm-sdk` dependency edge. `SecretRef`/`SecretMount` are
/// re-exported for the same reason: a fleet-side loopback caller
/// driving `RemoteResolver::resolve(&SecretRef)` directly (e.g. mvmd's
/// `secret_resolver_daemon` test) needs to construct a `SecretRef`
/// literal, which requires naming its `mount: SecretMount` field's
/// type too.
pub use mvm_sdk::ir::{AuthType, SecretMount, SecretRef, Sigv4Params};
