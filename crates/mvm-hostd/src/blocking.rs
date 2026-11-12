//! Synchronous bridge for code that must wait on a future from a sync
//! function that async callers can also reach.

use std::future::Future;
use std::io;

/// Run `future` to completion on a fresh single-thread runtime and return its
/// output.
///
/// A runtime cannot be started or blocked on from inside another, so when the
/// caller is already on a tokio thread the future runs on a short-lived scoped
/// thread with its own runtime instead. A failure to build the runtime, or a
/// panic in the future on that helper thread, comes back as an error rather
/// than propagating as a panic into an unrelated caller.
///
/// # Errors
///
/// Any `io::Error` building the runtime, or `io::ErrorKind::Other` when the
/// helper thread panicked.
pub fn block_on_anywhere<F>(future: F) -> io::Result<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    let run = move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(future))
    };
    if tokio::runtime::Handle::try_current().is_err() {
        return run();
    }
    std::thread::scope(|scope| {
        scope
            .spawn(run)
            .join()
            .map_err(|_| io::Error::other("the blocking bridge thread panicked"))?
    })
}

#[cfg(test)]
mod tests {
    use super::block_on_anywhere;

    #[test]
    fn runs_a_future_from_plain_sync_code() {
        assert_eq!(block_on_anywhere(async { 7 }).unwrap(), 7);
    }

    #[tokio::test]
    async fn runs_a_future_from_inside_a_current_thread_runtime() {
        assert_eq!(block_on_anywhere(async { 7 }).unwrap(), 7);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runs_a_future_from_inside_a_multi_thread_runtime() {
        assert_eq!(block_on_anywhere(async { 7 }).unwrap(), 7);
    }

    #[tokio::test]
    async fn a_panicking_future_is_an_error_not_a_panic() {
        let err = block_on_anywhere(async { panic!("boom") }).unwrap_err();
        assert!(err.to_string().contains("panicked"), "{err}");
    }
}
