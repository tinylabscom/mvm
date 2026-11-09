use super::*;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum MachineMailboxAction {
    /// Print the oldest message in the machine's mailbox, or nothing if empty
    Recv {
        /// Machine name.
        #[arg(value_name = "NAME")]
        name: String,
    },
}

/// Write the oldest mailbox message to stdout; an empty queue is not an error.
pub(super) fn recv_mailbox(name: &str) -> Result<()> {
    if let Some(body) = mvm_client::mailbox::recv(name)? {
        use std::io::Write as _;
        std::io::stdout().write_all(&body)?;
    }
    Ok(())
}
