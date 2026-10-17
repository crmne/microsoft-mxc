// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tells a workload's exit from `bwrap` failing before the workload started.
//!
//! `bwrap` exits with status 1 when it cannot set the sandbox up (a refused
//! namespace, a mount it cannot make), which is also the most common exit
//! status of a workload. Reporting that as the workload's exit code hides the
//! failure from the caller (microsoft/mxc#1494).
//!
//! `--json-status-fd` settles it. `bwrap` writes a `child-pid` document once it
//! has forked the sandbox and an `exit-code` document when the workload exits;
//! a sandbox whose setup fails, in `bwrap` or in its child before `exec`,
//! never gets the second one. So a `bwrap` that exited on its own without an
//! `exit-code` document never ran the workload.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::unistd::pipe2;

/// More than `bwrap` ever writes; anything past it is ignored.
const MAX_STATUS_BYTES: usize = 64 * 1024;

/// The read end of `bwrap`'s `--json-status-fd` pipe, and until spawn its
/// write end.
pub(crate) struct WorkloadStatus {
    reader: File,
    writer: Option<OwnedFd>,
    received: Vec<u8>,
}

impl WorkloadStatus {
    /// Create the pipe. Both ends are close-on-exec here; only `bwrap` gets
    /// the write end, through [`Self::prepare_command`].
    pub(crate) fn new() -> Result<Self, String> {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC)
            .map_err(|error| format!("Bubblewrap: failed to create the status pipe: {error}"))?;
        // `bwrap` has exited before the parent reads, so everything it wrote
        // is already in the pipe; never wait for more.
        fcntl(reader.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|error| format!("Bubblewrap: failed to configure the status pipe: {error}"))?;
        Ok(Self {
            reader: File::from(reader),
            writer: Some(writer),
            received: Vec::new(),
        })
    }

    /// The `bwrap` options that hand it the write end.
    pub(crate) fn args(&self) -> Vec<String> {
        match self.writer.as_ref() {
            Some(writer) => vec![
                "--json-status-fd".to_string(),
                writer.as_raw_fd().to_string(),
            ],
            None => Vec::new(),
        }
    }

    /// Let `bwrap`, and no other child, inherit the write end.
    ///
    /// `FD_CLOEXEC` is per process, so it is cleared in the forked child rather
    /// than on the parent's copy, which a concurrent spawn would also inherit.
    pub(crate) fn prepare_command(&self, command: &mut Command) {
        let Some(fd) = self.writer.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        // SAFETY: runs between fork and exec; `fcntl` is async-signal-safe and
        // the closure allocates nothing.
        unsafe {
            command.pre_exec(move || {
                fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty()))
                    .map(|_| ())
                    .map_err(std::io::Error::from)
            });
        }
    }

    /// Close the parent's copy of the write end once `bwrap` has its own, so
    /// the pipe ends with `bwrap`.
    pub(crate) fn child_spawned(&mut self) {
        self.writer.take();
    }

    /// Why `bwrap`'s exit is not the workload's: `Some` when `bwrap` exited
    /// on its own without reporting the workload's exit.
    ///
    /// A `bwrap` killed by a signal is not judged: MXC kills it on timeout and
    /// on `kill()`, and those paths report themselves.
    pub(crate) fn setup_failure(&mut self, status: ExitStatus) -> Option<String> {
        let code = status.code()?;
        self.drain();
        if workload_exited(&self.received) {
            return None;
        }
        Some(format!(
            "Bubblewrap: bwrap could not set up the sandbox and never started the workload \
             (bwrap exited with status {code}; its message is on the run's stderr). If it \
             could not create namespaces, this host blocks unprivileged user namespaces, and \
             containment \"process\" or \"landlock\" runs on Landlock instead."
        ))
    }

    fn drain(&mut self) {
        let mut chunk = [0_u8; 1024];
        while self.received.len() < MAX_STATUS_BYTES {
            match self.reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => self.received.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
}

/// Whether `bwrap`'s status documents include the workload's exit.
fn workload_exited(received: &[u8]) -> bool {
    serde_json::Deserializer::from_slice(received)
        .into_iter::<serde_json::Value>()
        .map_while(Result::ok)
        .any(|document| document.get("exit-code").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn an_exit_code_document_means_the_workload_ran() {
        let documents = br#"{ "child-pid": 42, "pid-namespace": 1 }
{ "exit-code": 1 }
"#;
        assert!(workload_exited(documents));
    }

    #[test]
    fn a_child_pid_alone_means_setup_failed_in_the_sandbox() {
        assert!(!workload_exited(br#"{ "child-pid": 42 }"#));
        assert!(!workload_exited(b""));
        assert!(!workload_exited(b"not json"));
    }

    #[test]
    fn a_bwrap_that_wrote_nothing_and_exited_1_never_started_the_workload() {
        let mut status = WorkloadStatus::new().expect("pipe");
        status.child_spawned();
        let failure = status
            .setup_failure(ExitStatus::from_raw(1 << 8))
            .expect("a setup failure");
        assert!(failure.contains("never started the workload"), "{failure}");
        assert!(failure.contains("status 1"), "{failure}");
    }

    #[test]
    fn a_bwrap_killed_by_a_signal_is_left_to_the_kill_paths() {
        let mut status = WorkloadStatus::new().expect("pipe");
        status.child_spawned();
        assert_eq!(status.setup_failure(ExitStatus::from_raw(9)), None);
    }

    #[test]
    fn the_write_end_is_offered_only_until_spawn() {
        let mut status = WorkloadStatus::new().expect("pipe");
        assert_eq!(status.args()[0], "--json-status-fd");
        status.child_spawned();
        assert!(status.args().is_empty());
    }
}
