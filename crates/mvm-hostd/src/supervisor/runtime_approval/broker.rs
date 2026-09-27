//! The endpoint's side of the approval socket.
//!
//! One connection per question: the endpoint writes one [`ApprovalPrompt`]
//! line and reads one [`ApprovalAnswer`] line, both bounded. The socket is the
//! operator's `mvmctl` (or the host library embedding the approval broker),
//! bound in the VM's own socket directory for the life of the foreground run.
//! No socket there means nobody to ask, which the supervisor turns into a
//! denial.

use std::path::PathBuf;

use async_trait::async_trait;
use mvm_contract::policy::approval_prompt::{
    ApprovalAnswer, ApprovalPrompt, MAX_ANSWER_LINE_BYTES,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Why a broker could not answer.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// No broker is listening.
    #[error("no approval broker is listening")]
    Unavailable,
    /// The broker answered with something that is not an answer.
    #[error("the approval broker's answer was malformed")]
    Malformed,
    /// The connection failed partway.
    #[error("the approval broker connection failed: {0}")]
    Io(#[from] std::io::Error),
}

impl BrokerError {
    /// Stable audit label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unavailable => super::REASON_APPROVAL_UNAVAILABLE,
            Self::Malformed => "approval_malformed",
            Self::Io(_) => "approval_error",
        }
    }
}

/// Something that answers approval prompts.
#[async_trait]
pub trait ApprovalBroker: Send + Sync {
    async fn ask(&self, prompt: &ApprovalPrompt) -> Result<ApprovalAnswer, BrokerError>;
}

/// A broker reached over a host-local Unix socket.
#[derive(Debug, Clone)]
pub struct SocketBroker {
    path: PathBuf,
}

impl SocketBroker {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl ApprovalBroker for SocketBroker {
    async fn ask(&self, prompt: &ApprovalPrompt) -> Result<ApprovalAnswer, BrokerError> {
        let mut stream = match tokio::net::UnixStream::connect(&self.path).await {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Err(BrokerError::Unavailable);
            }
            Err(error) => return Err(BrokerError::Io(error)),
        };
        let mut line = serde_json::to_vec(prompt).map_err(|_| BrokerError::Malformed)?;
        line.push(b'\n');
        stream.write_all(&line).await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream).take(MAX_ANSWER_LINE_BYTES as u64 + 1);
        let mut answer = Vec::new();
        reader.read_until(b'\n', &mut answer).await?;
        if answer.len() > MAX_ANSWER_LINE_BYTES || !answer.ends_with(b"\n") {
            return Err(BrokerError::Malformed);
        }
        serde_json::from_slice(&answer).map_err(|_| BrokerError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::approval::ApprovalRequestId;
    use mvm_contract::policy::approval_prompt::{ApprovalScope, ApprovalSubject};

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("appr-1").unwrap(),
            subject: ApprovalSubject::ToolCall { tool: "t".into() },
            expires_in_ms: 1000,
        }
    }

    #[tokio::test]
    async fn no_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let err = SocketBroker::new(dir.path().join("absent.sock"))
            .ask(&prompt())
            .await
            .unwrap_err();
        assert!(matches!(err, BrokerError::Unavailable), "{err}");
    }

    async fn answering(reply: Vec<u8>) -> Result<ApprovalAnswer, BrokerError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            assert!(line.contains("\"request_id\":\"appr-1\""));
            write.write_all(&reply).await.unwrap();
        });
        let result = SocketBroker::new(path).ask(&prompt()).await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn a_well_formed_answer_is_returned() {
        let answer = ApprovalAnswer::approved(
            ApprovalRequestId::parse("appr-1").unwrap(),
            ApprovalScope::Session,
            "tty",
        );
        let mut line = serde_json::to_vec(&answer).unwrap();
        line.push(b'\n');
        assert_eq!(answering(line).await.unwrap(), answer);
    }

    #[tokio::test]
    async fn an_oversized_or_unterminated_answer_is_malformed() {
        let oversized = [vec![b'x'; MAX_ANSWER_LINE_BYTES + 10], b"\n".to_vec()].concat();
        assert!(matches!(
            answering(oversized).await,
            Err(BrokerError::Malformed)
        ));
        assert!(matches!(
            answering(b"{\"request_id\":\"appr-1\"".to_vec()).await,
            Err(BrokerError::Malformed)
        ));
        assert!(matches!(
            answering(b"not json\n".to_vec()).await,
            Err(BrokerError::Malformed)
        ));
    }
}
