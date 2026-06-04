use crate::ir::Workload;

use crate::error::EmitError;

/// Emit the workload's canonical IR per the ADR-0002 subprocess
/// contract. Honors `MVM_IR_OUT`: when set, writes to that path;
/// when unset, writes to stdout.
pub fn emit(workload: &Workload) -> Result<(), EmitError> {
    let canonical = emit_json(workload)?;
    match std::env::var("MVM_IR_OUT") {
        Ok(path) => std::fs::write(&path, &canonical).map_err(|e| EmitError::Write(path, e)),
        Err(_) => {
            use std::io::Write;
            std::io::stdout()
                .write_all(canonical.as_bytes())
                .map_err(EmitError::Stdout)
        }
    }
}

/// Validate, canonicalize (RFC 8785), and return the canonical IR as a
/// String. Use [`emit`] when you want the ADR-0002 subprocess
/// behavior; this is the in-process variant for tests and embedding.
pub fn emit_json(workload: &Workload) -> Result<String, EmitError> {
    if let Err(errors) = crate::ir::validate(workload) {
        return Err(EmitError::Validation(errors));
    }
    crate::ir::canonicalize(workload).map_err(EmitError::Canonicalize)
}
