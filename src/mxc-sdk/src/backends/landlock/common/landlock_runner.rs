// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LandlockScriptRunner`: runs the workload as a direct child that confines
//! itself with Landlock and a seccomp filter before `exec`.
//!
//! The runner shares Bubblewrap's request semantics where Landlock can hold
//! them, and refuses the request where it cannot (see [`super::fs_plan`] and
//! [`super::network`]). It needs no privileges, no namespaces, and no helper
//! binaries, which is why the engine falls back to it when `bwrap` cannot
//! create its namespaces.

use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::mxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{
    ExecutionRequest, FailurePhase, SandboxOutputMetadata, ScriptResponse,
};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, group_kill,
    spawn_discard, take_boxed_read, take_boxed_write, wait_with_timeout, NativeStdio, PtySize,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser, WaitError,
};
use crate::mxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};
use crate::mxc_pty::{LivePty, PtySize as UnixPtySize};
use crate::mxc_unix_resources::{ChildAccounting, UnixResourceLimits};

use super::abi::{self, LandlockAbi};
use super::fs_plan::{self, PolicyPaths};
use super::network::{self, NetworkPosture};
use super::restriction::Restriction;

/// The shell that runs `process.commandLine`, as Bubblewrap's `sh -c`.
const SHELL: &str = "/bin/sh";

/// `PATH` for the child, the same as Bubblewrap's.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `TERM` for the child, the same as Bubblewrap's.
const DEFAULT_TERM: &str = "xterm-256color";

/// Landlock sandbox runner. Uses only shared `ContainerPolicy` fields.
#[derive(Default)]
pub struct LandlockScriptRunner;

impl LandlockScriptRunner {
    pub fn new() -> Self {
        Self
    }

    /// `validate`, plus the kernel's ABI and the network posture it settled.
    fn validate_prepared(
        &self,
        request: &ExecutionRequest,
    ) -> Result<(LandlockAbi, NetworkPosture), ScriptResponse> {
        self.validate_prepared_with_probe(request, abi::probe)
    }

    /// `validate_prepared` with an injectable ABI probe, so tests can drive
    /// every kernel without one.
    fn validate_prepared_with_probe<F>(
        &self,
        request: &ExecutionRequest,
        probe: F,
    ) -> Result<(LandlockAbi, NetworkPosture), ScriptResponse>
    where
        F: FnOnce() -> Result<LandlockAbi, abi::LandlockUnavailable>,
    {
        validate_network_policy_support(request, self.network_policy_support())?;
        if request.script_code.is_empty() {
            return Err(ScriptResponse::error(
                "script_code is empty — nothing to execute.",
            ));
        }
        // Input checks first, so a request is told what is wrong with it even
        // on a kernel without Landlock.
        let posture =
            network::posture(request).map_err(|error| ScriptResponse::rejected(&error))?;
        let abi = probe().map_err(|error| ScriptResponse {
            failure_phase: FailurePhase::BackendUnavailable,
            ..ScriptResponse::error(&error.to_string())
        })?;
        Ok((abi, posture))
    }
}

impl SandboxBackend for LandlockScriptRunner {
    /// Landlock understands the outbound and inbound defaults and the host
    /// loopback, and holds only the two postures [`network::posture`]
    /// accepts. Address rules, a runtime proxy, and proxy peer identity are
    /// left undeclared, so shared validation refuses them.
    fn network_policy_support(&self) -> NetworkPolicySupport {
        NetworkPolicySupport::EGRESS_DEFAULT
            | NetworkPolicySupport::INGRESS_DEFAULT
            | NetworkPolicySupport::HOST_LOOPBACK
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        self.validate_prepared(request).map(|_| ())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        let (abi, posture) = self.validate_prepared(request)?;

        // The same alias tightening and delegation check as Bubblewrap: the
        // strictest intent wins for one host object, and the sandbox never
        // gets access its caller lacks.
        let normalized;
        let request = match crate::mxc_common::filesystem_object::normalize_object_conflicts(
            &request.policy,
            logger,
        ) {
            Ok(Some(policy)) => {
                normalized = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &normalized
            }
            Ok(None) => request,
            Err(message) => return Err(ScriptResponse::error(&message)),
        };
        if let Err(message) =
            crate::mxc_common::filesystem_access::check_delegation(&request.policy)
        {
            return Err(ScriptResponse::error(&message));
        }

        let env = resolved_env(request);
        // Bubblewrap gives every run a private /tmp. Landlock cannot remap
        // paths, so a run that names no TMPDIR gets a private directory of
        // its own and TMPDIR pointing at it; the host's /tmp stays out of
        // reach.
        let private_tmp = if env.iter().any(|entry| entry.starts_with("TMPDIR=")) {
            None
        } else {
            Some(
                tempfile::Builder::new()
                    .prefix("mxc-landlock-")
                    .tempdir()
                    .map_err(|error| {
                        ScriptResponse::error(&format!(
                            "Landlock: failed to create the private temporary directory: {error}"
                        ))
                    })?,
            )
        };

        let plan = fs_plan::plan(
            &PolicyPaths {
                readonly: &request.policy.readonly_paths,
                readwrite: &request.policy.readwrite_paths,
                denied: &request.policy.denied_paths,
            },
            private_tmp.as_ref().map(tempfile::TempDir::path),
        )
        .map_err(|error| ScriptResponse::rejected(&error))?;
        let restriction =
            Restriction::new(&plan, abi, posture).map_err(|error| ScriptResponse::error(&error))?;

        logger.log_line(&abi.summary());
        let warnings: Vec<String> = abi
            .gaps()
            .into_iter()
            .filter(|gap| gap.contains("signalling"))
            .map(|gap| format!("{gap}."))
            .collect();

        let mut command = Command::new(SHELL);
        command.arg("-c").arg(&request.script_code);
        command.env_clear();
        for entry in &env {
            if let Some((key, value)) = entry.split_once('=') {
                command.env(key, value);
            }
        }
        if let Some(tmp) = private_tmp.as_ref() {
            command.env("TMPDIR", tmp.path());
        }
        if let Some(dir) = start_directory(request) {
            command.current_dir(dir);
        }

        let pty = match stdio {
            StdioMode::Pipes => {
                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                // A session of its own: a group to tree-kill, and no
                // controlling terminal shared with the caller.
                // SAFETY: `setsid` is async-signal-safe; nothing allocates.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                None
            }
            StdioMode::Inherit => {
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                None
            }
            StdioMode::Pty(size) => Some(
                LivePty::attach(
                    &mut command,
                    UnixPtySize {
                        rows: size.rows,
                        cols: size.cols,
                        pixel_width: size.pixel_width,
                        pixel_height: size.pixel_height,
                    },
                    &[],
                )
                .map_err(|error| {
                    ScriptResponse::error(&format!("Landlock: failed to allocate PTY: {error}"))
                })?,
            ),
        };
        let group = stdio != StdioMode::Inherit;

        let resource_limits = request
            .policy
            .resources
            .as_ref()
            .map(UnixResourceLimits::new);
        if let Some(limits) = resource_limits {
            limits.apply_to(&mut command);
        }
        // Last, so the workload is confined only after every other step.
        restriction.apply_to(&mut command);

        let mut child = command.spawn().map_err(|error| {
            ScriptResponse::error(&format!("Landlock: failed to start the workload: {error}"))
        })?;

        let (stdin, stdout, stderr) = match stdio {
            StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
            StdioMode::Inherit | StdioMode::Pty(_) => (None, None, None),
        };
        let (stdout, stdout_canceller, stderr, stderr_canceller) =
            match (wrap_pipe(stdout), wrap_pipe(stderr)) {
                (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                    (out, out_canceller, err, err_canceller)
                }
                (out_result, err_result) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let error = out_result.err().or(err_result.err());
                    return Err(ScriptResponse::error(&format!(
                        "Landlock: failed to wrap stdio pipes: {}",
                        error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                    )));
                }
            };

        Ok(Box::new(LandlockSandboxProcess {
            child,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            pty,
            group,
            timeout: (request.script_timeout != 0)
                .then(|| Duration::from_millis(u64::from(request.script_timeout))),
            started: Instant::now(),
            timed_out: false,
            termination_error: None,
            accounting: resource_limits.map(ChildAccounting::new),
            output_metadata: None,
            warnings,
            private_tmp,
        }))
    }
}

/// The directory the child starts in, as Bubblewrap's `--chdir` names it.
fn start_directory(request: &ExecutionRequest) -> Option<String> {
    Some(request.working_directory.as_str())
        .filter(|dir| !dir.is_empty())
        .map(crate::mxc_common::models::sandbox_absolute_path)
}

/// The child's environment: the caller's, or Bubblewrap's default of `PATH`,
/// `TERM`, and `HOME` naming the start directory.
fn resolved_env(request: &ExecutionRequest) -> Vec<String> {
    crate::mxc_common::default_env::resolve_env(request, || {
        let mut entries = vec![("PATH".to_string(), DEFAULT_PATH.to_string())];
        if let Some(home) = start_directory(request) {
            entries.push(("HOME".to_string(), home));
        }
        entries.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
        entries
    })
}

/// A running Landlock workload.
struct LandlockSandboxProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    pty: Option<LivePty>,
    /// `true` when the workload leads its own session and group (pipes and
    /// PTY), so termination signals the whole group.
    group: bool,
    timeout: Option<Duration>,
    started: Instant,
    timed_out: bool,
    termination_error: Option<String>,
    accounting: Option<ChildAccounting>,
    output_metadata: Option<SandboxOutputMetadata>,
    warnings: Vec<String>,
    /// Removed once the workload has been reaped.
    private_tmp: Option<tempfile::TempDir>,
}

impl LandlockSandboxProcess {
    /// Reap the workload if it has exited, after first killing what it left
    /// running in its group.
    ///
    /// Bubblewrap's PID namespace ends with its workload, taking every
    /// background process with it. Here the group is swept while the exited
    /// leader is still unreaped, so its pid, which is the group's id, cannot
    /// have been reused. A process that left the group with `setsid` is out of
    /// reach, as it is on Seatbelt.
    fn try_wait_child(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if self.group && self.child_exited_unreaped()? {
            // SAFETY: plain kill(2) on our own unreaped child's group.
            unsafe {
                libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
            }
        }
        match self.accounting.as_mut() {
            Some(accounting) => accounting.try_wait(&mut self.child),
            None => self.child.try_wait(),
        }
    }

    /// Whether the workload has exited, without reaping it. `false` once
    /// `Child` has reaped it, since `waitid` then has nothing to report.
    fn child_exited_unreaped(&self) -> std::io::Result<bool> {
        // SAFETY: a zeroed siginfo_t is a valid output buffer for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid on our own child with WNOWAIT leaves it unreaped.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            // Already reaped through `Child`.
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(false);
            }
            return Err(error);
        }
        // SAFETY: waitid filled `info`; si_pid is 0 when nothing has exited.
        Ok(unsafe { info.si_pid() } != 0)
    }

    /// Wait for the workload to exit, at most until `deadline`.
    fn reap_until(&mut self, deadline: Option<Instant>) -> Result<ExitStatus, WaitError> {
        const MIN_POLL: Duration = Duration::from_millis(1);
        const MAX_POLL: Duration = Duration::from_millis(50);
        let mut interval = MIN_POLL;
        loop {
            match self.try_wait_child() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) => return Err(WaitError::Io(error)),
            }
            let mut nap = interval;
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return Err(WaitError::Timeout);
                }
                nap = nap.min(deadline - now);
            }
            std::thread::sleep(nap);
            interval = (interval * 2).min(MAX_POLL);
        }
    }

    fn reap_with_timeout(&mut self, timeout: Option<Duration>) -> Result<ExitStatus, WaitError> {
        self.reap_until(timeout.map(|timeout| Instant::now() + timeout))
    }

    fn finish_accounting(&mut self, natural_exit: bool) {
        if let Some(metadata) = self
            .accounting
            .as_ref()
            .and_then(|accounting| accounting.output_metadata(natural_exit))
        {
            self.output_metadata = Some(metadata);
        }
    }

    fn timed_out_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "Landlock: script timed out")
    }

    fn pty(&self) -> std::io::Result<&LivePty> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Landlock process has no PTY"))
    }

    /// Kill on timeout and record the timeout, or why teardown failed.
    fn time_out(&mut self) -> std::io::Error {
        match self.kill_for_timeout() {
            Ok(()) => Self::timed_out_error(),
            Err(error) => {
                let error = format!("Landlock: script timed out, and teardown failed: {error}");
                self.termination_error = Some(error.clone());
                std::io::Error::other(error)
            }
        }
    }
}

impl SandboxProcess for LandlockSandboxProcess {
    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_ref()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        if let Some(pty) = self.pty.as_ref() {
            let stdio = pty.take_native_stdio()?;
            return Ok(Some(NativeStdio {
                stdin: Some(stdio.stdin),
                stdout: Some(stdio.stdout),
                stderr: None,
            }));
        }
        let stdio = duplicate_and_take_native_stdio(
            &mut self.stdin,
            &mut self.stdout,
            &mut self.stderr,
            |stream| stream.as_fd().try_clone_to_owned(),
            InterruptibleReader::try_clone_owned_fd,
            InterruptibleReader::try_clone_owned_fd,
        )?;
        if stdio.is_some() {
            self.stdout_canceller.take();
            self.stderr_canceller.take();
        }
        Ok(stdio)
    }

    fn is_pty(&self) -> bool {
        self.pty.is_some()
    }

    fn pty_clone_reader(&self) -> std::io::Result<Box<dyn std::io::Read + Send>> {
        self.pty()?.try_clone_reader()
    }

    fn pty_clone_reader_with_closer(
        &self,
    ) -> std::io::Result<crate::mxc_common::sandbox_process::PtyReaderWithCloser> {
        let (reader, closer) = self.pty()?.try_clone_reader_with_canceller()?;
        Ok((reader, Some(Box::new(closer))))
    }

    fn pty_take_writer(&self) -> std::io::Result<Box<dyn std::io::Write + Send>> {
        self.pty()?.take_writer()
    }

    fn pty_resize(&self, size: PtySize) -> std::io::Result<()> {
        self.pty()?.resize(UnixPtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
    }

    fn pty_size(&self) -> std::io::Result<PtySize> {
        let size = self.pty()?.size();
        Ok(PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if let Some(error) = self.termination_error.as_ref() {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.timed_out {
            return Err(Self::timed_out_error());
        }
        if let Some(status) = self.try_wait_child()? {
            self.finish_accounting(true);
            return Ok(Some(status.code().unwrap_or(-1)));
        }
        if self
            .timeout
            .is_some_and(|timeout| self.started.elapsed() >= timeout)
        {
            return Err(self.time_out());
        }
        Ok(None)
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // A reaped child's pid and group can be recycled; never signal them.
        if self.try_wait_child()?.is_some() {
            return Ok(());
        }
        if self.group {
            group_kill(&mut self.child)
        } else {
            // Inherit mode shares the caller's group; only the workload's own
            // process can be signalled without hitting the caller.
            self.child.kill()
        }
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        const REAP_TIMEOUT: Duration = Duration::from_secs(5);

        self.kill()?;
        match self.reap_with_timeout(Some(REAP_TIMEOUT)) {
            Ok(_) => {
                self.finish_accounting(false);
                self.timed_out = true;
                Ok(())
            }
            Err(WaitError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Landlock: killed process did not become reapable within 5 seconds",
            )),
            Err(WaitError::Io(error)) => Err(error),
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any stdin not taken, so the child sees EOF.
        self.stdin.take();
        if let Some(pty) = self.pty.as_ref() {
            pty.close_writer();
        }

        // Drain streams nobody took, so the child cannot block on a full pipe.
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());
        let (pty_thread, pty_canceller, pty_setup_error) = match self.pty.as_ref() {
            Some(pty) => match pty.take_unclaimed_reader() {
                Ok(Some((reader, canceller))) => {
                    (spawn_discard(Some(reader)), Some(canceller), None)
                }
                Ok(None) => (None, None, None),
                Err(error) => (None, None, Some(error)),
            },
            None => (None, None, None),
        };

        let result = if let Some(error) = pty_setup_error {
            let _ = self.kill();
            let _ = wait_with_timeout(&mut self.child, Some(Duration::from_secs(5)));
            Err(std::io::Error::other(format!(
                "Landlock: failed to prepare PTY output draining: {error}"
            )))
        } else if let Some(error) = self.termination_error.as_ref() {
            Err(std::io::Error::other(error.clone()))
        } else if self.timed_out {
            Err(Self::timed_out_error())
        } else {
            let deadline = self.timeout.map(|timeout| self.started + timeout);
            match self.reap_until(deadline) {
                Ok(status) => {
                    self.finish_accounting(true);
                    Ok(status.code().unwrap_or(-1))
                }
                Err(WaitError::Timeout) => Err(self.time_out()),
                Err(WaitError::Io(error)) => {
                    let _ = self.kill();
                    let _ = self.child.wait();
                    Err(std::io::Error::other(format!(
                        "Landlock: wait failed: {error}"
                    )))
                }
            }
        };

        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        if let Some(pty) = self.pty.as_ref() {
            pty.finish_native_bridge();
        }
        cancel_and_join_discard(pty_thread, &pty_canceller);
        if result.is_ok() || self.timed_out {
            self.private_tmp.take();
        }
        result
    }
}

impl Drop for LandlockSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap before removing the private temporary directory, so
        // an abandoned workload neither leaks as a zombie nor keeps writing
        // into a directory being deleted.
        let _ = self.kill();
        let _ = self.child.wait();
        self.private_tmp.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy};

    fn request(command: &str) -> ExecutionRequest {
        ExecutionRequest {
            script_code: command.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn input_errors_come_before_the_kernel_probe() {
        let runner = LandlockScriptRunner::new();
        let mut allowed = request("true");
        allowed.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let response = runner
            .validate_prepared_with_probe(&allowed, || panic!("probed before input checks"))
            .unwrap_err();
        assert_eq!(response.failure_phase, FailurePhase::Rejected);
        assert!(response.error_message.contains("loopback"));

        assert!(runner
            .validate_prepared_with_probe(&request(""), || panic!("probed"))
            .is_err());
    }

    #[test]
    fn a_kernel_without_landlock_is_a_missing_backend() {
        let runner = LandlockScriptRunner::new();
        let response = runner
            .validate_prepared_with_probe(&request("true"), || {
                Err(abi::LandlockUnavailable::TooOld(2))
            })
            .unwrap_err();
        assert_eq!(response.failure_phase, FailurePhase::BackendUnavailable);
        assert!(response.error_message.contains("ABI 2"));
    }

    #[test]
    fn the_default_environment_matches_bubblewrap() {
        let mut with_cwd = request("true");
        with_cwd.working_directory = "/work/./dir".to_string();
        let env = resolved_env(&with_cwd);
        assert!(env.contains(&format!("PATH={DEFAULT_PATH}")));
        assert!(env.contains(&"HOME=/work/dir".to_string()));
        assert!(env.contains(&format!("TERM={DEFAULT_TERM}")));
        assert!(!resolved_env(&request("true"))
            .iter()
            .any(|entry| entry.starts_with("HOME=")));
    }
}
