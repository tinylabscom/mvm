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
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    let observer = ProcessExitObserver::arm(i32::try_from(child.id())?);
    match observer {
        Ok(observer) => match observer.wait_event(deadline)? {
            ProcessExitWait::Exited => Ok(collect_after_exit_event(deadline, || child.try_wait())?),
            ProcessExitWait::TimedOut => Ok(None),
        },
        // Keep the same deadline on kernels without a process-exit primitive.
        Err(ProcessExitError::Unsupported) => {
            Ok(collect_after_exit_event(deadline, || child.try_wait())?)
        }
        Err(error) => Err(error.into()),
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
    let waited = wait_for_child(&mut child, started + within);
    match waited {
        Ok(Some(status)) => Ok(Output {
            status,
            stdout: captured_output(&mut stdout)?,
            stderr: captured_output(&mut stderr)?,
        }),
        outcome => {
            // The retained Child is the authority; never rediscover or signal a PID.
            let cleanup = (|| -> anyhow::Result<ExitStatus> {
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
                child.kill().context("terminate owned isolated child")?;
                collect_after_exit_event(Instant::now() + CLEANUP_DEADLINE, || child.try_wait())?
                    .context("owned child was not reaped within cleanup deadline")
            })();
            let reason = match outcome {
                Ok(None) => "execution deadline exceeded".to_owned(),
                Err(error) => format!("exit observation failed: {error:#}"),
                Ok(Some(_)) => unreachable!(),
            };
            let cleanup = match cleanup {
                Ok(status) => format!("owned child reaped: {status}"),
                Err(error) => format!("cleanup failed: {error:#}"),
            };
            bail!(
                "child {pid} after {:?}: {reason}; {cleanup}\nstdout:\n{}\nstderr:\n{}",
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

    const MODE: &str = "MVM_ISOLATED_HELPER_TEST_MODE";

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
    fn diagnostic_capture_is_bounded() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        file.write_all(b"capture-tail").unwrap();
        let bytes = captured_output(&mut file).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("middle omitted; 1 MiB retained"));
        assert!(bytes.ends_with(b"capture-tail"));
        assert!(bytes.len() < 1024 * 1024 + 100);
    }
}
