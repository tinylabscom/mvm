//! Process-isolated test fixtures; never used for real boots.

use std::io::{Read, Seek, SeekFrom};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use mvm_vmm::host::process_exit::{
    ProcessExitError, ProcessExitObserver, ProcessExitWait, collect_after_exit_event,
};

const CHILD: &str = "MVM_BASE_CONTRACT_TEST_CHILD";
const FRESH_CHILD: &str = "MVM_FRESH_PROCESS_TEST_CHILD";
const CHILD_DEADLINE: Duration = Duration::from_secs(120);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(10);
/// Longest observer or cleanup error text kept in a failure report.
const ERROR_TEXT_LIMIT: usize = 4096;

pub(crate) fn in_payload_capable_test_process(module: &str, name: &str) -> bool {
    in_test_process(module, name, CHILD)
}

pub(crate) fn in_fresh_test_process(module: &str, name: &str) -> bool {
    in_test_process(module, name, FRESH_CHILD)
}

fn in_test_process(module: &str, name: &str, marker: &str) -> bool {
    let module = module
        .split_once("::")
        .expect("test module includes crate")
        .1;
    let test = format!("{module}::{name}");
    if std::env::var(marker).as_deref() == Ok(test.as_str()) {
        return true;
    }
    let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
    command
        .stdin(Stdio::null())
        .args(["--exact", &test, "--nocapture"])
        .env_remove(CHILD)
        .env_remove(FRESH_CHILD)
        .env(marker, &test);
    let output = run_test_child(&mut command, CHILD_DEADLINE)
        .unwrap_or_else(|error| panic!("isolated test {test}: {error:#}"));
    assert!(
        output.status.success(),
        "isolated test child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
        "the isolated child must execute exactly the requested test"
    );
    false
}

fn wait_for_child(child: &mut Child, deadline: Instant) -> anyhow::Result<Option<ExitStatus>> {
    wait_for_child_with(child, deadline, ProcessExitObserver::arm)
}

/// `arm` builds the exit observer; tests inject its failure modes.
fn wait_for_child_with(
    child: &mut Child,
    deadline: Instant,
    arm: impl FnOnce(libc::pid_t) -> Result<ProcessExitObserver, ProcessExitError>,
) -> anyhow::Result<Option<ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    let pid = i32::try_from(child.id())?;
    let observer = arm(pid);
    match observer {
        Ok(observer) => match observer.wait_event(deadline)? {
            ProcessExitWait::Exited => Ok(collect_after_exit_event(deadline, || child.try_wait())?),
            ProcessExitWait::TimedOut => Ok(None),
        },
        // Keep the same deadline on kernels without a process-exit primitive.
        Err(ProcessExitError::Unsupported) => {
            Ok(collect_after_exit_event(deadline, || child.try_wait())?)
        }
        Err(error) => Err(anyhow::Error::from(error)
            .context(format!("arm process-exit observer for child {pid}"))),
    }
}

fn captured_output(file: &mut std::fs::File) -> std::io::Result<Vec<u8>> {
    const LIMIT: u64 = 1024 * 1024;
    file.rewind()?;
    let mut bytes = Vec::new();
    let length = file.metadata()?.len();
    if length > LIMIT {
        (&mut *file).take(LIMIT / 2).read_to_end(&mut bytes)?;
        bytes.extend_from_slice(b"\n[isolated test output: middle omitted; 1 MiB retained]\n");
        // Preserve libtest's trailing summary as well as early failure context.
        file.seek(SeekFrom::Start(length - LIMIT / 2))?;
        file.take(LIMIT / 2).read_to_end(&mut bytes)?;
    } else {
        file.take(LIMIT).read_to_end(&mut bytes)?;
    }
    Ok(bytes)
}

fn run_test_child(command: &mut Command, within: Duration) -> anyhow::Result<Output> {
    run_test_child_with(command, within, wait_for_child)
}

fn reap_owned_child(child: &mut Child) -> anyhow::Result<ExitStatus> {
    reap_owned_child_with(child, CLEANUP_DEADLINE, Child::kill, Child::try_wait)
}

/// `kill` and `try_wait` are the two steps tests make fail; a failure names
/// the child and is returned, never swallowed.
fn reap_owned_child_with(
    child: &mut Child,
    deadline: Duration,
    kill: impl FnOnce(&mut Child) -> std::io::Result<()>,
    mut try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
) -> anyhow::Result<ExitStatus> {
    let pid = child.id();
    if let Some(status) = try_wait(child).with_context(|| format!("poll owned child {pid}"))? {
        return Ok(status);
    }
    kill(child).with_context(|| format!("terminate owned isolated child {pid}"))?;
    collect_after_exit_event(Instant::now() + deadline, || try_wait(child))
        .with_context(|| format!("reap owned isolated child {pid}"))?
        .with_context(|| format!("owned child {pid} was not reaped within cleanup deadline"))
}

/// Keep the head and tail of an error text over `ERROR_TEXT_LIMIT`, cutting on
/// char boundaries, as `captured_output` does for child output.
fn bounded_error_text(text: String) -> String {
    if text.len() <= ERROR_TEXT_LIMIT {
        return text;
    }
    let head = text.floor_char_boundary(ERROR_TEXT_LIMIT / 2);
    let tail = text.ceil_char_boundary(text.len() - ERROR_TEXT_LIMIT / 2);
    format!(
        "{}\n[isolated test error: middle omitted; {ERROR_TEXT_LIMIT} bytes retained]\n{}",
        &text[..head],
        &text[tail..]
    )
}

fn failure_summary(
    outcome: anyhow::Result<Option<ExitStatus>>,
    cleanup: anyhow::Result<ExitStatus>,
) -> String {
    let reason = match outcome {
        Ok(_) => "execution deadline exceeded".to_owned(),
        Err(error) => bounded_error_text(format!("exit observation failed: {error:#}")),
    };
    let cleanup = match cleanup {
        Ok(status) => format!("owned child reaped: {status}"),
        Err(error) => bounded_error_text(format!("cleanup failed: {error:#}")),
    };
    format!("{reason}; {cleanup}")
}

fn run_test_child_with(
    command: &mut Command,
    within: Duration,
    wait: impl FnOnce(&mut Child, Instant) -> anyhow::Result<Option<ExitStatus>>,
) -> anyhow::Result<Output> {
    run_test_child_with_cleanup(command, within, wait, reap_owned_child)
}

fn run_test_child_with_cleanup(
    command: &mut Command,
    within: Duration,
    wait: impl FnOnce(&mut Child, Instant) -> anyhow::Result<Option<ExitStatus>>,
    cleanup: impl FnOnce(&mut Child) -> anyhow::Result<ExitStatus>,
) -> anyhow::Result<Output> {
    // Files avoid pipe backpressure while the parent waits for the exit event.
    let mut stdout = tempfile::tempfile().context("create child stdout capture")?;
    let mut stderr = tempfile::tempfile().context("create child stderr capture")?;
    command
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    #[cfg(unix)]
    mvm_vmm::host::process_exit::require_owned_child_custody()?;
    let started = Instant::now();
    let mut child = command.spawn().context("spawn isolated test child")?;
    let pid = child.id();
    match wait(&mut child, started + within) {
        Ok(Some(status)) => Ok(Output {
            status,
            stdout: captured_output(&mut stdout)?,
            stderr: captured_output(&mut stderr)?,
        }),
        outcome => {
            // The retained Child is the authority; never rediscover or signal a PID.
            let summary = failure_summary(outcome, cleanup(&mut child));
            bail!(
                "child {pid} after {:?}: {summary}\nstdout:\n{}\nstderr:\n{}",
                started.elapsed(),
                String::from_utf8_lossy(&captured_output(&mut stdout)?),
                String::from_utf8_lossy(&captured_output(&mut stderr)?),
            );
        }
    }
}

pub(crate) fn register_fixture_payload() {
    struct FixturePayload(tempfile::TempDir);
    impl mvm_build::builder_boot::BootPayloadSource for FixturePayload {
        fn boot_payload(
            &self,
        ) -> Result<
            mvm_build::builder_boot::BuilderBootPayload,
            mvm_build::builder_boot::BootPayloadError,
        > {
            mvm_build::builder_boot::BuilderBootPayload::builder()
                .host_bin_dir(self.0.path())
                .build()
        }
    }
    assert!(
        std::env::var_os(CHILD).is_some(),
        "register the process-global payload source only in an isolated test child"
    );
    let payload = tempfile::tempdir().unwrap();
    for name in mvm_build::host_payload_manifest::host_binary_names() {
        std::fs::write(payload.path().join(name), name.as_bytes()).unwrap();
    }
    let source = FixturePayload(payload);
    mvm_build::builder_boot::BootPayloadSource::boot_payload(&source).unwrap();
    mvm_build::builder_boot::register_boot_payload_source(Box::new(source));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // What these witnesses do and do not establish. The helper owns exactly one
    // retained `Child`; a deadline or observer failure kills and reaps that
    // handle and nothing else, so a bystander process must survive. Nothing
    // here claims that descendants of the child are signalled (there is no
    // process group or tree cleanup), that a grandchild outlives or dies with
    // the child, or that the child is cleaned up if the *parent* test process
    // is itself killed: SIGKILL of the parent leaves the child to the OS.
    // Parent-termination behaviour is whatever the helper implements, which is
    // none. The observer, kill and reap steps are injectable, so a refused
    // kill, an unreaped child, a wait error and an observer that cannot be
    // armed are each forced and shown to be reported and (where the helper
    // owns the kill) to leave no process; every injected failure keeps a drop
    // guard that kills and reaps the child so a failing test leaks nothing.
    // A refused kill is reported with the child's pid and is not retried.
    const MODE: &str = "MVM_ISOLATED_HELPER_TEST_MODE";

    /// Kills and reaps its child on drop so a failed assertion leaves no process.
    struct Bystander(Child);

    impl Drop for Bystander {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn pid_exists(pid: u32) -> bool {
        let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");
        // SAFETY: signal 0 only probes for existence; it delivers nothing.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn fixture(mode: &str) -> Command {
        let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "test_boot_payload::tests::child_fixture",
                "--nocapture",
            ])
            .env(MODE, mode)
            .stdin(Stdio::piped());
        command
    }

    #[test]
    fn child_fixture() {
        match std::env::var(MODE).as_deref() {
            Ok("output") => {
                let bytes = vec![b'x'; 128 * 1024];
                std::io::stdout().write_all(&bytes).unwrap();
                std::io::stderr().write_all(&bytes).unwrap();
            }
            Ok("fail") => panic!("isolated fixture failure"),
            Ok("block") => {
                // The parent retains the pipe writer until it kills this child.
                std::io::stdin().read_exact(&mut [0]).unwrap();
            }
            _ => {}
        }
    }

    #[test]
    fn child_output_larger_than_a_pipe_does_not_block_exit() {
        let output = run_test_child(&mut fixture("output"), Duration::from_secs(10)).unwrap();
        assert!(output.status.success());
        assert!(output.stdout.len() >= 128 * 1024);
        assert!(output.stderr.len() >= 128 * 1024);
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"));
    }

    #[test]
    fn verbose_success_preserves_exact_test_summary() {
        if in_fresh_test_process(
            module_path!(),
            "verbose_success_preserves_exact_test_summary",
        ) {
            std::io::stdout()
                .write_all(&vec![b'x'; 2 * 1024 * 1024])
                .unwrap();
        }
    }

    #[test]
    fn child_failure_preserves_status_and_diagnostics() {
        let output = run_test_child(&mut fixture("fail"), Duration::from_secs(10)).unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("isolated fixture failure"));
    }

    #[test]
    fn expired_child_deadline_reports_termination_and_reaping() {
        let error = run_test_child(&mut fixture("block"), Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(error.contains("execution deadline exceeded"), "{error}");
        assert!(error.contains("owned child reaped"), "{error}");
    }

    #[test]
    fn observer_error_is_returned_after_the_child_is_killed_and_reaped() {
        let error = run_test_child_with(&mut fixture("block"), Duration::from_secs(10), |_, _| {
            bail!("observer unavailable")
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("exit observation failed: observer unavailable"),
            "{error}"
        );
        assert!(error.contains("owned child reaped"), "{error}");
    }

    #[test]
    fn cleanup_failure_is_reported_not_swallowed() {
        let summary = failure_summary(Ok(None), Err(anyhow::anyhow!("kill refused")));
        assert!(summary.contains("execution deadline exceeded"), "{summary}");
        assert!(
            summary.contains("cleanup failed: kill refused"),
            "{summary}"
        );
        assert!(!summary.contains("owned child reaped"), "{summary}");
    }

    #[test]
    fn diagnostic_capture_is_bounded() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        file.write_all(b"capture-tail").unwrap();
        let bytes = captured_output(&mut file).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("middle omitted; 1 MiB retained"));
        assert!(bytes.ends_with(b"capture-tail"));
        assert!(bytes.len() < 1024 * 1024 + 100);
    }

    #[test]
    fn observer_and_cleanup_failures_are_both_reported() {
        let summary = failure_summary(
            Err(anyhow::anyhow!("observer unavailable")),
            Err(anyhow::anyhow!("kill refused")),
        );
        assert!(
            summary.contains("exit observation failed: observer unavailable"),
            "{summary}"
        );
        assert!(
            summary.contains("cleanup failed: kill refused"),
            "{summary}"
        );
    }

    #[test]
    fn a_blocked_running_child_is_killed_and_reaped_and_a_bystander_survives() {
        let mut bystander = Bystander(fixture("block").spawn().unwrap());
        let mut owned = fixture("block").spawn().unwrap();
        let owned_pid = owned.id();

        let status = reap_owned_child(&mut owned).unwrap();

        assert!(!status.success(), "a killed child does not exit cleanly");
        assert!(owned.try_wait().unwrap().is_some(), "owned child is reaped");
        assert!(!pid_exists(owned_pid), "no zombie is left behind");
        assert!(
            bystander.0.try_wait().unwrap().is_none(),
            "a process the helper does not own is untouched"
        );
    }

    #[test]
    fn the_wrapper_deadline_on_a_blocked_child_reaps_it_and_spares_a_bystander() {
        let bystander = Bystander(fixture("block").spawn().unwrap());
        let pid = std::cell::Cell::new(0);

        let error = run_test_child_with(
            &mut fixture("block"),
            Duration::from_millis(250),
            |child, deadline| {
                pid.set(child.id());
                wait_for_child(child, deadline)
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("execution deadline exceeded"), "{error}");
        assert!(error.contains("owned child reaped"), "{error}");
        assert_ne!(pid.get(), 0);
        assert!(!pid_exists(pid.get()), "no zombie is left behind");
        assert!(pid_exists(bystander.0.id()), "bystander is still alive");
    }

    fn blocked_child() -> Bystander {
        Bystander(fixture("block").spawn().unwrap())
    }

    fn io_error(message: &str) -> std::io::Error {
        std::io::Error::other(message.to_owned())
    }

    #[test]
    fn an_unsupported_observer_falls_back_to_polling_and_collects_the_exit() {
        let mut child = blocked_child();
        let raw = libc::pid_t::try_from(child.0.id()).expect("pid fits pid_t");
        let status = wait_for_child_with(
            &mut child.0,
            Instant::now() + Duration::from_secs(10),
            |_| {
                // Reached only after the first try_wait found the child running.
                // SAFETY: SIGKILL to the pid of a child this test owns and has not reaped.
                assert_eq!(unsafe { libc::kill(raw, libc::SIGKILL) }, 0);
                Err(ProcessExitError::Unsupported)
            },
        )
        .unwrap();
        assert!(status.is_some_and(|status| !status.success()));
    }

    #[test]
    fn an_observer_that_cannot_be_armed_is_reported_and_the_child_is_reaped() {
        let bystander = blocked_child();
        let pid = std::cell::Cell::new(0);
        let error = run_test_child_with(
            &mut fixture("block"),
            Duration::from_secs(10),
            |child, deadline| {
                pid.set(child.id());
                wait_for_child_with(child, deadline, |_| {
                    Err(ProcessExitError::Io(io_error("kqueue refused")))
                })
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("arm process-exit observer for child"),
            "{error}"
        );
        assert!(error.contains("kqueue refused"), "{error}");
        assert!(error.contains("owned child reaped"), "{error}");
        assert_ne!(pid.get(), 0);
        assert!(!pid_exists(pid.get()), "no zombie is left behind");
        assert!(pid_exists(bystander.0.id()), "bystander is still alive");
    }

    #[test]
    fn an_unsupported_observer_on_a_blocked_child_hits_the_deadline_and_reaps() {
        let error = run_test_child_with(
            &mut fixture("block"),
            Duration::from_millis(250),
            |child, deadline| {
                wait_for_child_with(child, deadline, |_| Err(ProcessExitError::Unsupported))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("execution deadline exceeded"), "{error}");
        assert!(error.contains("owned child reaped"), "{error}");
    }

    #[test]
    fn a_refused_kill_is_reported_with_the_pid_and_touches_nothing_else() {
        let mut owned = blocked_child();
        let bystander = blocked_child();
        let pid = owned.0.id();
        let error = reap_owned_child_with(
            &mut owned.0,
            Duration::from_secs(10),
            |_| Err(io_error("kill refused")),
            Child::try_wait,
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains(&format!("terminate owned isolated child {pid}")),
            "{text}"
        );
        assert!(text.contains("kill refused"), "{text}");
        assert!(
            owned.0.try_wait().unwrap().is_none(),
            "the refused kill left it running"
        );
        assert!(bystander.0.id() != pid && pid_exists(bystander.0.id()));
    }

    #[test]
    fn a_child_not_reaped_within_the_cleanup_deadline_is_reported() {
        let mut owned = blocked_child();
        let pid = owned.0.id();
        let error = reap_owned_child_with(&mut owned.0, Duration::ZERO, Child::kill, |_| Ok(None))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "owned child {pid} was not reaped within cleanup deadline"
            )),
            "{error}"
        );
        // The kill itself was real, so the guard's own wait collects it.
        assert!(!owned.0.wait().unwrap().success());
    }

    #[test]
    fn a_wait_error_while_reaping_is_reported() {
        let mut owned = blocked_child();
        let pid = owned.0.id();
        let mut calls = 0;
        let error =
            reap_owned_child_with(&mut owned.0, Duration::from_secs(10), Child::kill, |_| {
                calls += 1;
                if calls == 1 {
                    Ok(None)
                } else {
                    Err(io_error("wait failed"))
                }
            })
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains(&format!("reap owned isolated child {pid}")),
            "{text}"
        );
        assert!(text.contains("wait failed"), "{text}");
    }

    #[test]
    fn a_failing_cleanup_is_reported_through_the_wrapper() {
        let pid = std::cell::Cell::new(0);
        let error = run_test_child_with_cleanup(
            &mut fixture("block"),
            Duration::from_millis(250),
            wait_for_child,
            |child| {
                // End the child so the failing cleanup still leaves no process.
                pid.set(child.id());
                child.kill()?;
                child.wait()?;
                bail!("reap refused")
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("execution deadline exceeded"), "{error}");
        assert!(error.contains("cleanup failed: reap refused"), "{error}");
        assert!(!error.contains("owned child reaped"), "{error}");
        assert!(!pid_exists(pid.get()));
    }

    #[test]
    fn an_oversized_error_text_is_bounded_on_a_char_boundary() {
        let huge = format!("start-{}-end", "é".repeat(ERROR_TEXT_LIMIT * 4));
        let summary = failure_summary(
            Err(anyhow::anyhow!(huge.clone())),
            Err(anyhow::anyhow!(huge)),
        );
        assert!(summary.len() < 4 * ERROR_TEXT_LIMIT, "{}", summary.len());
        assert!(summary.contains("exit observation failed: start-"));
        assert!(summary.contains("middle omitted"), "{summary}");
        assert!(
            summary.contains("-end; cleanup failed: start-"),
            "{summary}"
        );
        assert!(summary.ends_with("-end"));
    }

    #[test]
    fn short_error_text_passes_through_unchanged() {
        let at_limit = "x".repeat(ERROR_TEXT_LIMIT);
        assert_eq!(bounded_error_text(at_limit.clone()), at_limit);
        let summary = failure_summary(Err(anyhow::anyhow!("a")), Err(anyhow::anyhow!("b")));
        assert_eq!(summary, "exit observation failed: a; cleanup failed: b");
    }
}
