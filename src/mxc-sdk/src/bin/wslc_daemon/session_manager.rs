// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owns the WSLc SDK session and containers on a single dedicated worker
//! thread.
//!
//! The WSLc SDK's `WslcSession` / `WslcContainer` / `WslcProcess` handles are
//! apartment-affine: any thread that has joined the MTA may use them. A single
//! long-lived worker thread owns the container map and every short SDK call;
//! async pipe handlers dispatch typed [`WorkerCommand`]s to it over a channel
//! and await the reply. An image pull and an `exec` both run for an unbounded
//! time, so each takes a thread of its own and posts its outcome back to the
//! worker as another command.
//!
//! State-aware topology: the daemon holds as many `WslcSession`s (each a WSL2
//! utility VM) as it is asked for, booted lazily and amortised across the
//! sandboxes placed in them, plus a `sandbox_id -> container` map in which
//! every entry names the session it belongs to. A request that names no session
//! joins an implicit one.
//!
//! Each session's image store is leased from
//! [`mxc_sdk::wslc_common::store_slots`]. A store's VHDX admits one live
//! session, so the lease is also what stops two sessions colliding. Neither the
//! pool nor this module bounds how many sessions may run.
//!
//! A session is released when nothing is using it any more: its hold is
//! **derived** by scanning the maps (see [`Worker::session_hold`]) rather than
//! counted, and a session observed holding nothing for the empty-session grace
//! is reaped by [`Worker::reap_idle_sessions`].
//!
//! Each phase drives the real WSLc SDK via the reusable steps in
//! [`mxc_sdk::wslc_common::container_steps`] and [`mxc_sdk::wslc_common::image`]: `provision`
//! ensures the session + resolves the image + creates a container with a
//! keepalive init process; `start` boots
//! it; `exec` runs a fresh `WslcCreateContainerProcess` to completion on a
//! thread of its own, streaming its stdout/stderr live to the pipe handler via
//! an [`OutputSink`]; `stop` / `deprovision` stop + delete. The completion reply
//! carries the exit code; output flows over the sink. (Client `Stdin` forwarding
//! is a later fill-in.)

use std::collections::{hash_map::Entry, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::{FailurePhase, ScriptResponse};
use mxc_sdk::wslc_common::container_steps::{
    self, OutStream, OutputSink, ProcessSettings, SessionSizing,
};
use mxc_sdk::wslc_common::daemon_protocol::{
    DeprovisionConfig, DeprovisionSessionConfig, ErrKind, ExecConfig, ExecTerminal, NetworkMode,
    PortMapping, ProvisionConfig, ProvisionSessionConfig, StartConfig, StopConfig,
};
use mxc_sdk::wslc_common::image;
use mxc_sdk::wslc_common::policy_mapping;
use mxc_sdk::wslc_common::process_env::EnvScope;
use mxc_sdk::wslc_common::store_slots::{StoreSlotLease, StoreSlotPool};
use mxc_sdk::wslc_common::wslc_bindings::{
    WslcContainer, WslcContainerGuard, WslcContainerNetworkingMode, WslcSdk, WslcSessionGuard,
};

/// Prefix of the name each session's WSL2 utility VM is created under.
///
/// A second `WslcCreateSession` under a name already in use is untested, so the
/// session id supplies the rest.
const SESSION_NAME_PREFIX: &str = "mxc-wslc-daemon";

/// The name the SDK is given for `session_id`.
fn session_name(session_id: &str) -> String {
    let suffix = session_id
        .rsplit_once(':')
        .map_or(session_id, |(_, suffix)| suffix);
    format!("{SESSION_NAME_PREFIX}-{suffix}")
}

/// Environment override for how long a session holding nothing is kept, in
/// whole seconds.
const SESSION_IDLE_TIMEOUT_ENV: &str = "MXC_WSLC_DAEMON_SESSION_IDLE_SECS";

/// How long a session that holds nothing is kept before it is released.
///
/// Defaults to the daemon's idle window, since a session cannot outlive the
/// daemon it lives in.
fn session_idle_timeout() -> Duration {
    session_grace_from(
        std::env::var(SESSION_IDLE_TIMEOUT_ENV).ok().as_deref(),
        std::env::var(crate::IDLE_TIMEOUT_ENV).ok().as_deref(),
    )
}

/// Pure core of [`session_idle_timeout`], split out so the rule is testable
/// without mutating process-global environment state.
fn session_grace_from(session_override: Option<&str>, daemon_override: Option<&str>) -> Duration {
    crate::resolve_duration(
        session_override,
        crate::resolve_duration(daemon_override, crate::IDLE_TIMEOUT),
    )
}

/// How long teardown has to drain everything that is still running.
///
/// One budget covers the execs and then every session's pulls, so a daemon
/// holding four sessions does not take four times as long to exit as one
/// holding a single session.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Block until `in_flight` reads zero, or `deadline` passes.
///
/// A run that has not reported back is still using the handle it was given, so
/// releasing that handle while one is outstanding would free memory the SDK
/// holds.
fn wait_for_in_flight(in_flight: &AtomicUsize, deadline: Instant) -> bool {
    while in_flight.load(Ordering::SeqCst) > 0 {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// Convert a step helper's `failure_phase` into a typed failure, since the wire
/// carries only a message and an [`ErrKind`].
fn sr_err(resp: ScriptResponse) -> WorkerError {
    let err = anyhow::anyhow!(resp.error_message);
    match resp.failure_phase {
        FailurePhase::BackendUnavailable => WorkerError::Unavailable(err),
        FailurePhase::Rejected => WorkerError::Rejected(err),
        _ => WorkerError::Backend(err),
    }
}

/// A typed worker failure. The control server maps [`WorkerError::kind`] onto
/// the protocol's [`ErrKind`] so clients can react (e.g. distinguish an unknown
/// sandbox from a backend fault) without string-matching the message.
#[derive(Debug)]
pub enum WorkerError {
    /// The referenced sandbox id is unknown to the daemon.
    NotProvisioned(String),

    /// The referenced session id is unknown to the daemon.
    UnknownSession(String),

    /// The sandbox exists but has not been started.
    NotStarted(String),

    /// An exec already holds this container's single-flight slot.
    Busy(String),

    /// The host cannot run WSLc at all.
    Unavailable(anyhow::Error),

    /// The request cannot be honored as written.
    Rejected(anyhow::Error),

    /// A backend/SDK-level failure, or an internal worker/channel fault.
    Backend(anyhow::Error),
}

impl WorkerError {
    /// The protocol classification the control server returns for this error.
    pub fn kind(&self) -> ErrKind {
        match self {
            WorkerError::NotProvisioned(_) => ErrKind::NotProvisioned,
            WorkerError::UnknownSession(_) => ErrKind::NotProvisioned,
            WorkerError::NotStarted(_) => ErrKind::NotStarted,
            WorkerError::Busy(_) => ErrKind::Busy,
            WorkerError::Unavailable(_) => ErrKind::Unavailable,
            WorkerError::Rejected(_) => ErrKind::Rejected,
            WorkerError::Backend(_) => ErrKind::Backend,
        }
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::NotProvisioned(id) => write!(f, "unknown sandbox {id}"),
            WorkerError::UnknownSession(id) => write!(f, "unknown session {id}"),
            WorkerError::NotStarted(id) => write!(f, "sandbox {id} is not started"),
            WorkerError::Busy(id) => write!(f, "sandbox {id} already has an exec in flight"),
            WorkerError::Unavailable(e) | WorkerError::Rejected(e) | WorkerError::Backend(e) => {
                write!(f, "{e:#}")
            }
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<anyhow::Error> for WorkerError {
    fn from(e: anyhow::Error) -> Self {
        WorkerError::Backend(e)
    }
}

/// A unit of work dispatched from an async pipe handler to the WSLc worker
/// thread. Each variant carries a `oneshot` reply channel the worker fulfils.
pub enum WorkerCommand {
    /// Boot a sized session, returning its minted id.
    ProvisionSession {
        config: ProvisionSessionConfig,
        reply: oneshot::Sender<Result<String, WorkerError>>,
    },

    /// Release a session nothing is using any more.
    DeprovisionSession {
        config: DeprovisionSessionConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    Provision {
        config: ProvisionConfig,
        reply: oneshot::Sender<Result<String, WorkerError>>,
    },
    /// Anything addressed to one container. Routing every such command through
    /// a single variant is what forces it through [`Worker::dispatch`], so a new
    /// one cannot reach a container whose exec is still using its handle.
    Container(ContainerWork),

    /// Report an off-worker session boot, from its boot thread.
    SessionBooted {
        session_id: String,
        outcome: Result<BootedSession, WorkerError>,
    },
    /// Report a parked provision's pull, from the pull thread or its deadline.
    PullFinished {
        token: u64,
        outcome: Result<(), ScriptResponse>,
    },
    /// Report an off-worker exec, from its run thread.
    ExecFinished {
        sandbox_id: String,
        report: ExecReport,
    },
    /// Give up on a sandbox whose provision reply never reached a client.
    Retire {
        sandbox_id: String,
        reply: oneshot::Sender<()>,
    },
    /// Report the current live-container count (drives the idle watchdog).
    ContainerCount { reply: oneshot::Sender<usize> },

    /// Release every container and session and stop the worker thread.
    Shutdown { reply: oneshot::Sender<()> },
}

/// A resource an exec holds against the daemon's capacity, shared by the client
/// handler and the run so it is released only once both are done with it.
///
/// Opaque so the worker never names the control server's permit type.
pub type ExecSlotGuard = Arc<dyn Send + Sync>;

/// Everything an admitted exec needs, kept together so it travels as one value
/// from the pipe handler to the run thread.
pub struct ExecRequest {
    pub config: ExecConfig,

    /// Live-output sink the worker hands to `exec_in_container`, carrying the
    /// SDK's stdout/stderr chunks to the pipe handler as bytes arrive.
    pub sink: OutputSink,
    pub cancellation: Arc<AtomicBool>,
    pub(crate) registration: Arc<ExecRegistration>,
    pub admit: oneshot::Sender<Result<(), WorkerError>>,
    pub done: oneshot::Sender<Result<ExecTerminal, WorkerError>>,

    /// Counts this run against the daemon's exec capacity until it reports
    /// back, so a disconnecting client does not free the slot while its run
    /// thread and container process are still going.
    pub slot: Option<ExecSlotGuard>,
}

/// What an off-worker exec thread hands back, already classified.
///
/// Quarantine stays on the worker because it mutates the container map and
/// issues its own SDK delete, so an unconfirmed run reports the detail instead
/// of acting on it.
#[derive(Debug)]
pub enum ExecReport {
    Finished(Result<ExecTerminal, WorkerError>),
    Unconfirmed(String),
}

/// Everything an off-worker exec needs, in a form that can cross a thread.
struct ExecJob {
    sdk: *const WslcSdk,
    container: WslcContainer,
    config: ExecConfig,
    sink: OutputSink,
    cancellation: Arc<AtomicBool>,
}

// SAFETY: the SDK is apartment-affine, not thread-affine. Both the worker and
// the spawned thread join the MTA, where a handle may be used from any member
// thread. Measured with two containers in one session running `sleep 5` from two
// MTA threads: both processes started within 0.5ms of each other and overlapped
// for 5.1100s of a 5.1177s wall clock, both exited 0, and each process's output
// arrived only on its own capture buffer and live sink.
unsafe impl Send for ExecJob {}

/// Keeps the in-flight count accurate even if the run panics, so teardown
/// cannot be blocked forever by a thread that is already gone.
struct ExecCount(Arc<AtomicUsize>);

impl ExecCount {
    fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for ExecCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Run an exec on a thread of its own, reporting back to the worker.
///
/// Returns as soon as the thread starts. The caller keeps `sdk` loaded and the
/// container handle alive until [`WorkerCommand::ExecFinished`] lands -- see
/// [`wait_for_execs_in_flight`].
fn start_exec(
    job: ExecJob,
    worker: mpsc::UnboundedSender<WorkerCommand>,
    in_flight: &Arc<AtomicUsize>,
) -> Result<(), std::io::Error> {
    let counted = ExecCount::enter(in_flight);
    let spawned = std::thread::Builder::new()
        .name("wslc-exec".to_string())
        .spawn(move || {
            let job = job;

            // Releasing the count only after the report is queued is what lets a
            // teardown that sees zero rely on finding it.
            let _counted = counted;
            let sandbox_id = job.config.sandbox_id.clone();

            let run = std::panic::AssertUnwindSafe(|| match ComApartment::enter() {
                Err(e) => ExecReport::Finished(Err(WorkerError::Backend(e))),
                Ok(_apartment) => {
                    let mut log = Logger::new(Mode::Console);
                    run_exec(job, &mut log)
                }
            });

            // A panic leaves the process's fate unknown, which is what
            // `Unconfirmed` already means.
            let report = std::panic::catch_unwind(run).unwrap_or_else(|_| {
                ExecReport::Unconfirmed("the exec thread panicked".to_string())
            });

            let _ = worker.send(WorkerCommand::ExecFinished { sandbox_id, report });
        });

    // A spawn failure drops the guard along with the closure, so there is no
    // release to do here.
    spawned.map(|_| ())
}

/// The off-worker half of an exec: run it to completion and classify it.
fn run_exec(job: ExecJob, logger: &mut Logger) -> ExecReport {
    let ExecJob {
        sdk,
        container,
        config,
        sink,
        cancellation,
    } = job;

    // ProcessSettings::build expects `NAME=VALUE` env entries.
    let env: Vec<String> = config
        .env
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    // SAFETY: `sdk` is valid and `container` is a live, started handle; the
    // worker releases neither while this run is still counted in flight.
    let outcome = unsafe {
        container_steps::exec_in_container(
            &*sdk,
            container,
            &config.script_code,
            &env,
            config.env_scope,
            &config.working_directory,
            config.timeout_ms,
            &cancellation,
            Some(sink),
            logger,
        )
    };

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => return ExecReport::Finished(Err(sr_err(e))),
    };

    match outcome.completion {
        container_steps::ProcessCompletion::TerminationUnconfirmed => ExecReport::Unconfirmed(
            outcome
                .post_launch_error
                .map(|error| error.error_message)
                .unwrap_or_else(|| "process termination could not be confirmed".to_string()),
        ),
        container_steps::ProcessCompletion::Confirmed(terminal) => {
            ExecReport::Finished(Ok(terminal))
        }
    }
}

/// A chunk of live process output streamed from the worker to the pipe handler:
/// which stream it came from and the bytes (owned, so it can cross the channel).
pub type OutputChunk = (OutStream, Vec<u8>);

/// Bound on the number of unconsumed live-output chunks buffered between the
/// SDK's I/O callback threads and the pipe handler. The channel is bounded (not
/// unbounded) so a container emitting output faster than a slow client drains it
/// cannot grow the queue without limit and OOM the persistent daemon, taking
/// down every sandbox it owns — the same hazard the capture-buffer cap guards
/// against. When the queue is full the sink does **not** block (see
/// [`enqueue_output`]): it latches a truncation flag and drops further bytes so
/// the SDK callback thread — which also delivers the process-exit callback — is
/// never parked. Stalling that thread could otherwise block exit delivery and
/// wedge teardown for every sandbox sharing the daemon.
pub(crate) const LIVE_OUTPUT_CHANNEL_CAPACITY: usize = 256;

/// Max bytes per enqueued live-output chunk. A single SDK callback can deliver
/// an arbitrarily large buffer; splitting it here bounds each queue entry's
/// allocation and keeps the resulting `Stdout`/`Stderr` frame well under the
/// protocol's `MAX_FRAME_SIZE` (a `Vec<u8>` serializes as a JSON number array,
/// ~4x expansion), so a large callback can never overflow a frame and abort the
/// stream before its terminal frame.
pub(crate) const LIVE_OUTPUT_MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Enqueue an SDK output callback, splitting it into `LIVE_OUTPUT_MAX_CHUNK_BYTES`
/// pieces so each queue entry and its resulting frame stay bounded regardless of
/// the callback's buffer size.
///
/// This runs **synchronously on the SDK's I/O callback thread**, which also
/// delivers the process-exit callback. It must therefore never block: a
/// [`try_send`](mpsc::Sender::try_send) that finds the bounded queue full does
/// **not** apply backpressure (that would park this thread and could deadlock
/// exit delivery and teardown for every sandbox on the daemon). Instead it
/// latches `overflowed` and stops enqueuing; the pipe handler turns a latched
/// overflow into a terminal `Error` frame so the client sees an explicit
/// truncation rather than a silently short stream. Once latched, subsequent
/// callbacks return immediately so the client receives a clean truncated prefix
/// rather than a gapped stream. A closed receiver (client left / leak-path
/// `close()`) likewise stops enqueuing.
fn enqueue_output(
    tx: &mpsc::Sender<OutputChunk>,
    overflowed: &AtomicBool,
    kind: OutStream,
    bytes: &[u8],
) {
    if overflowed.load(Ordering::Relaxed) {
        return;
    }
    for chunk in bytes.chunks(LIVE_OUTPUT_MAX_CHUNK_BYTES) {
        match tx.try_send((kind, chunk.to_vec())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                overflowed.store(true, Ordering::Relaxed);
                return;
            }
            Err(TrySendError::Closed(_)) => return,
        }
    }
}

/// An admitted exec: the completion receiver (the run's exit code), the
/// live-output receiver the pipe handler drains into `Stdout`/`Stderr` frames,
/// and the `overflowed` latch the sink sets when it had to drop output because a
/// slow client let the bounded queue fill. The registration keeps the exec id
/// reserved until the pipe handler finishes terminal delivery. The pipe handler
/// reports a set overflow latch as a terminal `Error` frame.
#[derive(Debug)]
pub struct ExecStream {
    pub done: oneshot::Receiver<Result<ExecTerminal, WorkerError>>,
    pub output: mpsc::Receiver<OutputChunk>,
    pub overflowed: Arc<AtomicBool>,
    pub(crate) registration: Arc<ExecRegistration>,
}

pub(crate) type ActiveExecs = Arc<Mutex<HashMap<String, ActiveExec>>>;

#[derive(Debug)]
pub(crate) struct ActiveExec {
    run_token: String,
    cancellation: Weak<AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct ExecRegistration {
    exec_id: String,
    run_token: String,
    active_execs: ActiveExecs,
    cancellation: Arc<AtomicBool>,
}

impl Drop for ExecRegistration {
    fn drop(&mut self) {
        let mut active_execs = self
            .active_execs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active_execs.get(&self.exec_id).is_some_and(|current| {
            current.run_token == self.run_token
                && current
                    .cancellation
                    .ptr_eq(&Arc::downgrade(&self.cancellation))
        }) {
            active_execs.remove(&self.exec_id);
        }
    }
}

pub(crate) fn register_exec(
    active_execs: &ActiveExecs,
    exec_id: &str,
    run_token: &str,
    cancellation: &Arc<AtomicBool>,
) -> Result<ExecRegistration, WorkerError> {
    let active_exec = ActiveExec {
        run_token: run_token.to_string(),
        cancellation: Arc::downgrade(cancellation),
    };
    let mut active_execs_guard = active_execs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match active_execs_guard.entry(exec_id.to_string()) {
        Entry::Occupied(mut entry) if entry.get().cancellation.upgrade().is_none() => {
            entry.insert(active_exec);
        }
        Entry::Occupied(_) => {
            return Err(WorkerError::Rejected(anyhow::anyhow!(
                "exec id {exec_id:?} is already active"
            )));
        }
        Entry::Vacant(entry) => {
            entry.insert(active_exec);
        }
    }
    drop(active_execs_guard);

    Ok(ExecRegistration {
        exec_id: exec_id.to_string(),
        run_token: run_token.to_string(),
        active_execs: Arc::clone(active_execs),
        cancellation: Arc::clone(cancellation),
    })
}

/// A cheap, clonable handle async tasks use to drive the worker thread.
#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::UnboundedSender<WorkerCommand>,
    active_execs: ActiveExecs,
}

impl SessionHandle {
    /// The live-exec registry, so a test can observe what [`Self::cancel_exec`]
    /// reached.
    #[cfg(test)]
    pub(crate) fn active_execs(&self) -> &ActiveExecs {
        &self.active_execs
    }

    /// Boot a session, returning its minted `session_id`.
    pub async fn provision_session(
        &self,
        config: ProvisionSessionConfig,
    ) -> Result<String, WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::ProvisionSession { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Release a session nothing is using any more.
    pub async fn deprovision_session(
        &self,
        config: DeprovisionSessionConfig,
    ) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::DeprovisionSession { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Provision a container, returning its minted `sandbox_id`.
    pub async fn provision(&self, config: ProvisionConfig) -> Result<String, WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Provision { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Start a provisioned container.
    pub async fn start(&self, config: StartConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Container(ContainerWork::Start {
            config,
            reply,
        }))?;
        rx.await.map_err(worker_gone)?
    }

    /// Admit and run a command in a started container. Awaits the worker's
    /// **admission** decision first: on rejection (unknown / not-started /
    /// already-busy sandbox) this returns the typed error *before* the caller
    /// writes any admission to the client. On admission it returns an
    /// [`ExecStream`] — the completion receiver (the run's exit code) plus the
    /// live-output receiver, which the caller drains into `Stdout`/`Stderr`
    /// frames as bytes arrive. Admission and
    /// the claim on the container are atomic on the worker thread, so no
    /// lifecycle command can invalidate the checked state before the run starts.
    pub async fn exec(
        &self,
        config: ExecConfig,
        slot: Option<ExecSlotGuard>,
    ) -> Result<ExecStream, WorkerError> {
        let (admit, admit_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let (stream_tx, output) = mpsc::channel::<OutputChunk>(LIVE_OUTPUT_CHANNEL_CAPACITY);
        // The sink is invoked from the SDK's I/O callback threads (native OS
        // threads, never the async runtime). Those same threads deliver the
        // process-exit callback, so the sink must never block: [`enqueue_output`]
        // uses a non-blocking `try_send` and, on a full queue, latches
        // `overflowed` and drops further bytes instead of parking the thread.
        // Memory stays bounded by the channel capacity; a slow/non-reading
        // client can no longer wedge exit delivery or teardown for every sandbox
        // on the daemon. The pipe handler reports a set latch as a terminal
        // `Error` frame so truncation is explicit rather than silent.
        let overflowed = Arc::new(AtomicBool::new(false));
        let sink_overflowed = Arc::clone(&overflowed);
        let sink: OutputSink = Box::new(move |kind, bytes| {
            enqueue_output(&stream_tx, &sink_overflowed, kind, bytes);
        });
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration = Arc::new(register_exec(
            &self.active_execs,
            &config.exec_id,
            &config.run_token,
            &cancellation,
        )?);
        self.send(WorkerCommand::Container(ContainerWork::Exec(ExecRequest {
            config,
            sink,
            cancellation,
            registration: Arc::clone(&registration),
            admit,
            done,
            slot,
        })))?;
        admit_rx.await.map_err(worker_gone)??;
        Ok(ExecStream {
            done: done_rx,
            output,
            overflowed,
            registration,
        })
    }

    /// Signal an admitted exec without waiting for the worker, which may not
    /// have reached the run yet.
    pub fn cancel_exec(&self, exec_id: &str, run_token: &str) {
        if let Some(cancellation) = self
            .active_execs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(exec_id)
            .filter(|current| current.run_token == run_token)
            .and_then(|current| current.cancellation.upgrade())
        {
            cancellation.store(true, Ordering::Release);
        }
    }

    /// Stop a running container.
    pub async fn stop(&self, config: StopConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Container(ContainerWork::Stop {
            config,
            reply,
        }))?;
        rx.await.map_err(worker_gone)?
    }

    /// Deprovision (delete) a container.
    pub async fn deprovision(&self, config: DeprovisionConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Container(ContainerWork::Deprovision {
            config,
            reply,
        }))?;
        rx.await.map_err(worker_gone)?
    }

    /// Current number of live containers (0 means the daemon is idle).
    pub async fn container_count(&self) -> Result<usize, WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::ContainerCount { reply })?;
        rx.await.map_err(worker_gone)
    }

    /// Stop counting a sandbox that no client can reach, so the idle watchdog
    /// can shut the daemon down.
    pub async fn retire(&self, sandbox_id: String) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Retire { sandbox_id, reply })?;
        rx.await.map_err(worker_gone)
    }

    /// Ask the worker to release everything and stop. Awaits confirmation.
    pub async fn shutdown(&self) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Shutdown { reply })?;
        rx.await.map_err(worker_gone)
    }

    fn send(&self, cmd: WorkerCommand) -> Result<(), WorkerError> {
        self.tx
            .send(cmd)
            .map_err(|_| WorkerError::Backend(anyhow::anyhow!("WSLc worker thread is gone")))
    }
}

fn worker_gone(_e: oneshot::error::RecvError) -> WorkerError {
    WorkerError::Backend(anyhow::anyhow!("WSLc worker dropped the reply channel"))
}

/// Per-container bookkeeping held by the worker: whether the container is
/// currently started and the live `WslcContainer` handle (kept alive across
/// phases so repeated `exec`s hit a warm container). The sandbox id is the
/// map key.
struct ContainerEntry {
    started: bool,
    quarantined: bool,

    /// Set when a sandbox's provision reply never reached a client, so nobody
    /// can deprovision it.
    ///
    /// Kept in the map rather than dropped so [`Worker::shutdown`] still stops
    /// and deletes the container.
    retired: bool,
    container: WslcContainerGuard,

    /// Which session's utility VM this container lives in.
    ///
    /// The container's handle belongs to that session, so this entry holds the
    /// session open for as long as it exists, `retired` and `quarantined`
    /// included.
    session_id: String,

    /// Keeps a quarantined sandbox counted against exec capacity, because a run
    /// whose termination was never confirmed may still hold a live process.
    exec_slot: Option<ExecSlotGuard>,
}

/// A provision waiting on its image to arrive from a registry.
struct PendingProvision {
    config: ProvisionConfig,
    reply: oneshot::Sender<Result<String, WorkerError>>,

    /// The session this provision will place its container in, pinned for as
    /// long as this entry exists.
    session_id: String,

    /// Held only so dropping this entry retires the deadline thread.
    _retire_deadline: std::sync::mpsc::Sender<()>,
}

/// A command addressed to one container, either about to run or parked behind
/// an exec that is still using that container's handle.
pub(crate) enum ContainerWork {
    /// Validate the sandbox (exists + started) and, if admitted, hand the run to
    /// a thread of its own. The two replies make admission **atomic** with the
    /// claim on the container: the worker validates, claims the container's
    /// in-flight slot, answers `admit` and starts the run thread without
    /// yielding. A later lifecycle command naming that container parks behind
    /// the claim and a later `Exec` is refused with `Busy`, so none can
    /// interleave with the run. `admit` carries the pre-run decision (so an
    /// unknown, not-started or already-busy sandbox is a pre-admission typed
    /// error, never a post-admission stream `Error`); `done` carries the run's
    /// exit code once [`WorkerCommand::ExecFinished`] lands.
    Exec(ExecRequest),
    Start {
        config: StartConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    Stop {
        config: StopConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    Deprovision {
        config: DeprovisionConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
}

impl ContainerWork {
    fn sandbox_id(&self) -> &str {
        match self {
            ContainerWork::Exec(request) => &request.config.sandbox_id,
            ContainerWork::Start { config, .. } => &config.sandbox_id,
            ContainerWork::Stop { config, .. } => &config.sandbox_id,
            ContainerWork::Deprovision { config, .. } => &config.sandbox_id,
        }
    }

    /// Answer this work with `message`, for a daemon that is shutting down.
    fn refuse(self, message: &str) {
        let error = WorkerError::Backend(anyhow::anyhow!("{message}"));
        match self {
            ContainerWork::Exec(request) => {
                let _ = request.admit.send(Err(error));
            }
            ContainerWork::Start { reply, .. }
            | ContainerWork::Stop { reply, .. }
            | ContainerWork::Deprovision { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

/// How [`Worker::begin_exec`] puts a claimed run on its own thread, injected so
/// a worker with no SDK loaded can still reach the claim.
type RunStarter = fn(
    &Worker,
    ExecConfig,
    WslcContainer,
    OutputSink,
    Arc<AtomicBool>,
    &mpsc::UnboundedSender<WorkerCommand>,
) -> Result<(), WorkerError>;

/// Hand a claimed run to its own MTA thread using the SDK this worker loaded.
fn start_run_on_sdk(
    state: &Worker,
    config: ExecConfig,
    container: WslcContainer,
    sink: OutputSink,
    cancellation: Arc<AtomicBool>,
    worker: &mpsc::UnboundedSender<WorkerCommand>,
) -> Result<(), WorkerError> {
    let Some(sdk) = state.sdk.as_ref() else {
        return Err(WorkerError::Backend(anyhow::anyhow!(
            "no active WSLc session"
        )));
    };

    let sandbox_id = config.sandbox_id.clone();
    let job = ExecJob {
        // The box's contents, not the field: teardown may take the field while
        // this run is still dereferencing the SDK.
        sdk: &**sdk as *const WslcSdk,
        container,
        config,
        sink,
        cancellation,
    };

    start_exec(job, worker.clone(), &state.execs_in_flight).map_err(|e| {
        WorkerError::Backend(anyhow::anyhow!(
            "could not start a thread to run exec on sandbox {sandbox_id}: {e}"
        ))
    })
}

/// An exec running on its own thread, and the work that parked behind it.
///
/// `container` is the handle that run is using, so nothing may delete or
/// release it until [`Worker::finish_exec`] removes this entry.
struct InFlightExec {
    container: WslcContainer,
    done: oneshot::Sender<Result<ExecTerminal, WorkerError>>,

    /// Which session's utility VM the run is executing in, so it pins that
    /// session even in the window where its container entry has already gone.
    session_id: String,

    /// Held only so the exec id stays reserved for as long as the run lasts.
    _registration: Arc<ExecRegistration>,

    /// Held only so the run counts against exec capacity until it reports back.
    slot: Option<ExecSlotGuard>,
    parked: Vec<ContainerWork>,
}

/// Everything booting one session needs, in a form that can cross a thread.
struct SessionJob {
    sdk: *const WslcSdk,
    name: String,
    store: String,
    sizing: SessionSizing,
}

// SAFETY: the SDK is apartment-affine, not thread-affine, and both the worker
// and the spawned thread join the MTA, where any member thread may call it. The
// `sdk` pointer addresses the worker's `Box`, which teardown leaks rather than
// frees while a boot is still counted in flight.
unsafe impl Send for SessionJob {}

/// A booted session handle on its way back to the worker.
pub(crate) struct BootedSession(WslcSessionGuard);

// SAFETY: as for `SessionJob`. The guard is moved, never shared, so only one
// thread owns it at a time.
unsafe impl Send for BootedSession {}

/// Counts a session boot against teardown's drain for as long as it runs.
struct SessionCount(Arc<AtomicUsize>);

impl SessionCount {
    fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for SessionCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Boot a session on a thread of its own, reporting back to the worker.
///
/// A boot the host cannot satisfy takes minutes to fail, which on the worker
/// would stall every other sandbox on the daemon for that whole time.
fn start_session_boot(
    job: SessionJob,
    session_id: String,
    worker: mpsc::UnboundedSender<WorkerCommand>,
    in_flight: &Arc<AtomicUsize>,
) -> Result<(), std::io::Error> {
    let counted = SessionCount::enter(in_flight);
    let spawned = std::thread::Builder::new()
        .name("wslc-session-boot".to_string())
        .spawn(move || {
            let job = job;

            // Released only after the report is queued, so a teardown that sees
            // zero can rely on finding it.
            let _counted = counted;

            let outcome = match ComApartment::enter() {
                Err(e) => Err(WorkerError::Backend(e)),
                Ok(_apartment) => {
                    let mut log = Logger::new(Mode::Console);

                    // SAFETY: `sdk` is valid for as long as this is counted in
                    // flight, and this thread is in the MTA.
                    unsafe {
                        container_steps::create_daemon_session(
                            &*job.sdk, &job.name, &job.store, job.sizing, &mut log,
                        )
                    }
                    .map(BootedSession)
                    .map_err(sr_err)
                }
            };

            let _ = worker.send(WorkerCommand::SessionBooted {
                session_id,
                outcome,
            });
        });

    spawned.map(|_| ())
}

/// Where a request's session stands.
#[derive(Debug)]
enum SessionLookup {
    /// Booted and usable now.
    Ready(String),

    /// Still booting on its own thread.
    Booting(String),
}

/// A session whose VM is still booting on its own thread.
struct PendingSession {
    /// Leased before the boot starts, so nothing else is handed this slot
    /// while a VM is opening it.
    store: StoreSlotLease,
    name: String,
    sizing: SessionSizing,

    /// The client waiting for this session's id, absent for the implicit
    /// session that nobody requested directly.
    reply: Option<oneshot::Sender<Result<String, WorkerError>>>,

    /// Provisions that arrived while this session was still booting.
    parked: Vec<(
        ProvisionConfig,
        oneshot::Sender<Result<String, WorkerError>>,
    )>,
}

/// One session the daemon holds: a WSL2 utility VM, its image store, and what
/// it was sized as.
///
/// The session guard is declared before the store lease so the VM stops before
/// its slot returns to the pool; a slot reissued while the VHDX is still
/// mounted cannot be opened.
struct SessionEntry {
    session: WslcSessionGuard,

    /// The store slot this session holds, returned to the pool on release.
    store: StoreSlotLease,

    /// The name the SDK knows this session by.
    name: String,

    /// What this session's VM was sized as.
    sizing: SessionSizing,

    /// Pulls started against this session that have not reported back.
    pulls_in_flight: Arc<AtomicUsize>,

    /// When this session was first observed holding nothing.
    empty_since: Option<Instant>,
}

/// The single-threaded WSLc session owner, constructed and run entirely on the
/// worker thread.
///
/// The SDK, session and container handles are `!Send` raw pointers; ownership
/// stays here, and a pull, boot or exec thread borrows one only for as long as
/// its own in-flight counter says so.
struct Worker {
    logger: Logger,
    start_run: RunStarter,
    pending: HashMap<u64, PendingProvision>,
    exec_in_flight: HashMap<String, InFlightExec>,

    /// Runs this worker started that have not reported back. Shared with the run
    /// threads, which outlive this struct whenever teardown abandons a handle.
    execs_in_flight: Arc<AtomicUsize>,

    /// Session boots that have not reported back, which hold the SDK while
    /// they run.
    sessions_in_flight: Arc<AtomicUsize>,
    next_pull_token: u64,
    store_slots: StoreSlotPool,

    /// Sessions whose VM is still booting, by session id.
    pending_sessions: HashMap<String, PendingSession>,

    /// The session a request that names none joins, minted on first use.
    ///
    /// Random like any other id and never handed to a client, so no caller can
    /// name the session everyone else is sharing.
    default_session: Option<String>,

    // These three drop in declaration order: a container handle into its
    // session, and both into the SDK before `wslcsdk.dll` unloads.
    containers: HashMap<String, ContainerEntry>,
    sessions: HashMap<String, SessionEntry>,

    /// Boxed so an address handed to an off-worker thread survives teardown
    /// taking the field to leak the SDK rather than unload it.
    sdk: Option<Box<WslcSdk>>,
}

impl Worker {
    fn new() -> Self {
        Self {
            logger: Logger::new(Mode::Console),
            start_run: start_run_on_sdk,
            pending: HashMap::new(),
            exec_in_flight: HashMap::new(),
            execs_in_flight: Arc::new(AtomicUsize::new(0)),
            sessions_in_flight: Arc::new(AtomicUsize::new(0)),
            next_pull_token: 0,
            store_slots: StoreSlotPool::new(),
            pending_sessions: HashMap::new(),
            default_session: None,
            containers: HashMap::new(),
            sessions: HashMap::new(),
            sdk: None,
        }
    }

    /// What is still using `session_id`.
    ///
    /// Derived on every call rather than tracked, since containers leave the
    /// map by paths that do not agree and a stored count would drift across
    /// them.
    ///
    /// A pull is counted separately from the provision that started it: the
    /// provision entry goes as soon as either the pull or its deadline reports,
    /// which can be long before the pull thread releases the handle.
    fn session_hold(&self, session_id: &str) -> usize {
        let containers = self
            .containers
            .values()
            .filter(|entry| entry.session_id == session_id)
            .count();
        let pending = self
            .pending
            .values()
            .filter(|provision| provision.session_id == session_id)
            .count();
        let execs = self
            .exec_in_flight
            .values()
            .filter(|exec| exec.session_id == session_id)
            .count();
        let pulls = self
            .sessions
            .get(session_id)
            .map_or(0, |entry| entry.pulls_in_flight.load(Ordering::SeqCst));

        containers + pending + execs + pulls
    }

    /// Lazily load the SDK. Idempotent.
    fn ensure_sdk(&mut self) -> Result<(), WorkerError> {
        if self.sdk.is_none() {
            // SAFETY: the worker thread is already in the MTA (see `ComApartment`).
            let sdk =
                unsafe { container_steps::load_sdk_checked(&mut self.logger) }.map_err(sr_err)?;
            self.sdk = Some(Box::new(sdk));
        }
        Ok(())
    }

    /// Start booting a session, returning the id it will have.
    ///
    /// Nothing bounds how many sessions a daemon holds. A count cannot express
    /// host load, since each session carries its own cpu and memory, and the
    /// host refuses what it cannot supply.
    fn begin_session(
        &mut self,
        sizing: SessionSizing,
        worker: &mpsc::UnboundedSender<WorkerCommand>,
    ) -> Result<String, WorkerError> {
        self.ensure_sdk()?;

        let session_id = format!("wslcsess:{}", uuid::Uuid::new_v4().simple());
        let name = session_name(&session_id);

        // Leased here rather than on the boot thread, so a slot is never
        // handed out twice while a VM is opening the store it points at.
        let (store, ()) = self
            .store_slots
            .lease_with(|_| Ok::<(), std::convert::Infallible>(()))
            .map_err(|e| WorkerError::Backend(anyhow::anyhow!("{e}")))?;

        let sdk = self.sdk.as_ref().expect("sdk loaded above");
        let job = SessionJob {
            // The box's contents, not the field: teardown may take the field
            // while this boot is still dereferencing the SDK.
            sdk: &**sdk as *const WslcSdk,
            name: name.clone(),
            store: store.path().to_string_lossy().to_string(),
            sizing,
        };

        if let Err(e) = start_session_boot(
            job,
            session_id.clone(),
            worker.clone(),
            &self.sessions_in_flight,
        ) {
            // The lease drops with `store` here, returning the slot.
            return Err(WorkerError::Backend(anyhow::anyhow!(
                "could not start a thread to boot session {session_id}: {e}"
            )));
        }

        self.pending_sessions.insert(
            session_id.clone(),
            PendingSession {
                store,
                name,
                sizing,
                reply: None,
                parked: Vec::new(),
            },
        );
        Ok(session_id)
    }

    /// Hand a booting session the client waiting on its id.
    ///
    /// Separate from [`Worker::begin_session`] so a boot that never started
    /// leaves the reply with its caller to answer.
    fn attach_session_reply(
        &mut self,
        session_id: &str,
        reply: oneshot::Sender<Result<String, WorkerError>>,
    ) {
        match self.pending_sessions.get_mut(session_id) {
            Some(pending) => pending.reply = Some(reply),

            // Answered rather than dropped, since a dropped reply reaches the
            // client as a bare "worker gone".
            None => {
                let _ = reply.send(Ok(session_id.to_string()));
            }
        }
    }

    /// Register a session whose VM finished booting, and release whatever
    /// parked behind it.
    fn finish_session(
        &mut self,
        session_id: &str,
        outcome: Result<BootedSession, WorkerError>,
        worker: &mpsc::UnboundedSender<WorkerCommand>,
    ) {
        let Some(pending) = self.pending_sessions.remove(session_id) else {
            return;
        };
        let PendingSession {
            store,
            name,
            sizing,
            reply,
            parked,
        } = pending;

        let booted = match outcome {
            Ok(BootedSession(session)) => session,
            Err(e) => {
                // Retired with the slot, so a later provision boots a fresh
                // implicit session rather than parking behind one that will
                // never arrive.
                if self.default_session.as_deref() == Some(session_id) {
                    self.default_session = None;
                }
                let message = e.to_string();
                if let Some(reply) = reply {
                    let _ = reply.send(Err(e));
                }
                for (_, parked_reply) in parked {
                    let _ = parked_reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                        "the WSLc session this provision was waiting for could not be \
                         created: {message}"
                    ))));
                }
                return;
            }
        };

        self.sessions.insert(
            session_id.to_string(),
            SessionEntry {
                session: booted,
                store,
                name,
                sizing,
                pulls_in_flight: Arc::new(AtomicUsize::new(0)),
                empty_since: None,
            },
        );

        if let Some(reply) = reply {
            let _ = reply.send(Ok(session_id.to_string()));
        }

        // Replayed only now the session is in the map, so each takes the
        // ordinary path.
        for (config, parked_reply) in parked {
            self.begin_provision(config, parked_reply, worker);
        }
    }

    /// Resolve the session a request names, booting the implicit one if it
    /// named none and there is not one already.
    fn ensure_session(
        &mut self,
        requested: Option<&str>,
        worker: &mpsc::UnboundedSender<WorkerCommand>,
    ) -> Result<SessionLookup, WorkerError> {
        if let Some(session_id) = requested {
            return if self.sessions.contains_key(session_id) {
                Ok(SessionLookup::Ready(session_id.to_string()))
            } else if self.pending_sessions.contains_key(session_id) {
                Ok(SessionLookup::Booting(session_id.to_string()))
            } else {
                Err(WorkerError::UnknownSession(session_id.to_string()))
            };
        }

        // A reaped or failed implicit session leaves its id behind, so check
        // the maps rather than trusting the field.
        if let Some(existing) = self.default_session.clone() {
            if self.sessions.contains_key(&existing) {
                return Ok(SessionLookup::Ready(existing));
            }
            if self.pending_sessions.contains_key(&existing) {
                return Ok(SessionLookup::Booting(existing));
            }
        }

        let session_id = self.begin_session(SessionSizing::default(), worker)?;
        self.default_session = Some(session_id.clone());
        Ok(SessionLookup::Booting(session_id))
    }

    /// Release a session a client asked to be rid of.
    ///
    /// Refuses while anything is still using it rather than cascading, since
    /// the sandboxes in a session are addressed individually and their owners
    /// still hold those ids.
    fn release_session(&mut self, session_id: &str) -> Result<(), WorkerError> {
        if !self.sessions.contains_key(session_id) {
            return Err(WorkerError::UnknownSession(session_id.to_string()));
        }

        // The implicit session is shared by every request that named none, so
        // no single caller may release it.
        if self.default_session.as_deref() == Some(session_id) {
            return Err(WorkerError::Rejected(anyhow::anyhow!(
                "session {session_id} is the daemon's implicit session and is released only \
                 once nothing is using it"
            )));
        }

        let hold = self.session_hold(session_id);
        if hold > 0 {
            return Err(WorkerError::Rejected(anyhow::anyhow!(
                "session {session_id} still has {hold} sandbox(es) or operation(s) in it; \
                 deprovision them first"
            )));
        }

        self.release_session_entry(session_id)
    }

    /// Terminate and release one session's VM, returning its store slot.
    ///
    /// The caller has already established that nothing is using it.
    fn release_session_entry(&mut self, session_id: &str) -> Result<(), WorkerError> {
        let Some(entry) = self.sessions.remove(session_id) else {
            return Ok(());
        };
        if self.default_session.as_deref() == Some(session_id) {
            self.default_session = None;
        }

        let SessionEntry {
            session,
            store,
            name,
            sizing,
            ..
        } = entry;

        self.logger.log_line(&format!(
            "releasing session {session_id} ('{name}', slot {}, cpu={}, memory_mb={}, gpu={})",
            store.index(),
            sizing
                .cpu_count
                .map_or_else(|| "host default".to_string(), |cpu| cpu.to_string()),
            sizing
                .memory_mb
                .map_or_else(|| "host default".to_string(), |mb| mb.to_string()),
            sizing.gpu,
        ));

        let released = container_steps::release_daemon_session(session, &name, &mut self.logger);

        // Returned only after the terminate above, so the next lease never
        // reaches a store still mounted.
        drop(store);

        released.map_err(sr_err)
    }

    /// Release sessions that have held nothing for the empty-session grace.
    ///
    /// Waits for nothing, since blocking the watchdog's poll would stall every
    /// other session's requests behind one that is busy.
    fn reap_idle_sessions(&mut self) {
        let grace = session_idle_timeout();
        let now = Instant::now();

        // The hold scan reads the whole worker, so it cannot run while the
        // stamp below borrows one entry.
        let holds: Vec<(String, usize)> = self
            .sessions
            .keys()
            .map(|session_id| (session_id.clone(), self.session_hold(session_id)))
            .collect();

        let mut expired = Vec::new();
        for (session_id, hold) in holds {
            let Some(entry) = self.sessions.get_mut(&session_id) else {
                continue;
            };
            if hold > 0 {
                entry.empty_since = None;
                continue;
            }
            if now.duration_since(*entry.empty_since.get_or_insert(now)) >= grace {
                expired.push(session_id);
            }
        }

        for session_id in expired {
            self.logger.log_line(&format!(
                "session {session_id} has held nothing for {}s",
                grace.as_secs()
            ));
            if let Err(e) = self.release_session_entry(&session_id) {
                self.logger
                    .log_line(&format!("releasing idle session {session_id} failed: {e}"));
            }
        }
    }

    /// Start a provision, parking it if the image has to be pulled.
    ///
    /// Returning without replying is what keeps this thread free: the pull runs
    /// elsewhere and posts [`WorkerCommand::PullFinished`] when it lands, so
    /// every other sandbox keeps being served while a registry is slow.
    fn begin_provision(
        &mut self,
        config: ProvisionConfig,
        reply: oneshot::Sender<Result<String, WorkerError>>,
        worker: &mpsc::UnboundedSender<WorkerCommand>,
    ) {
        let session_id = match self.ensure_session(config.session_id.as_deref(), worker) {
            Ok(SessionLookup::Ready(session_id)) => session_id,
            Ok(SessionLookup::Booting(session_id)) => {
                // Parking rather than waiting is what keeps this thread free,
                // and what stops a second provision booting a second implicit
                // session alongside the first.
                self.pending_sessions
                    .get_mut(&session_id)
                    .expect("ensure_session reported it booting")
                    .parked
                    .push((config, reply));
                return;
            }
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };

        let sdk = self.sdk.as_ref().expect("session ensured");
        let session = self.sessions[&session_id].session.as_raw();

        // The slot this session leased, not the daemon's — a store hint naming
        // another session's slot would send a caller to warm the wrong one.
        let store = image::StoreHint::DaemonSlot(self.sessions[&session_id].store.index());

        // SAFETY: `sdk`/`session` are valid.
        let step = unsafe {
            image::begin_resolve(
                sdk,
                session,
                &config.image,
                config.image_tar_path.as_deref(),
                &store,
                match config.network {
                    NetworkMode::None => image::RegistryAccess::Denied,
                    NetworkMode::Bridged => image::RegistryAccess::Allowed,
                },
                "[WSLC][daemon]",
                &mut self.logger,
            )
        };
        let step = match step {
            Ok(step) => step,
            Err(e) => {
                let _ = reply.send(Err(sr_err(e)));
                return;
            }
        };

        match step {
            image::ImageStep::Ready => {
                let _ = reply.send(self.create_provisioned_container(&config, &session_id));
            }
            image::ImageStep::Pull => {
                let token = self.next_pull_token;
                self.next_pull_token += 1;

                let done = worker.clone();

                // The pending entry below is not enough on its own: the
                // deadline thread can report first, and removing that entry
                // would unpin a session the pull thread still dereferences.
                let counter = Arc::clone(&self.sessions[&session_id].pulls_in_flight);
                let started = unsafe {
                    image::start_pull_counted(
                        sdk,
                        session,
                        &config.image,
                        &store,
                        "[WSLC][daemon]",
                        Some(counter),
                        move |outcome| {
                            let _ = done.send(WorkerCommand::PullFinished { token, outcome });
                        },
                    )
                };
                if let Err(e) = started {
                    let _ = reply.send(Err(sr_err(e)));
                    return;
                }

                // Nothing can stop a stalled pull from outside, so the deadline
                // is enforced by giving up on it rather than by ending it.
                let budget = image::daemon_pull_budget();
                let image_name = config.image.clone();
                let expired = worker.clone();
                let (retire_deadline, retired) = std::sync::mpsc::channel::<()>();
                let armed = std::thread::Builder::new()
                    .name("wslc-pull-deadline".to_string())
                    .spawn(move || {
                        // A pull that lands first drops the sender, so this
                        // returns rather than sleeping out the budget.
                        if retired.recv_timeout(budget)
                            != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                        {
                            return;
                        }
                        let _ = expired.send(WorkerCommand::PullFinished {
                            token,
                            outcome: Err(image::pull_deadline_expired(&image_name, budget)),
                        });
                    });

                if armed.is_err() {
                    // Parking without a deadline is how a provision waits
                    // forever, so refuse instead. The pull carries on, counted
                    // against its session, and warms the cache for a retry.
                    let _ = reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                        "could not arm the pull deadline for image '{}'",
                        config.image
                    ))));
                    return;
                }

                self.pending.insert(
                    token,
                    PendingProvision {
                        config,
                        reply,
                        session_id,
                        _retire_deadline: retire_deadline,
                    },
                );
            }
        }
    }

    /// Resume a parked provision once its pull reported, or its deadline did.
    ///
    /// An unknown token is the loser of that race, and has nothing left to do.
    fn finish_provision(&mut self, token: u64, outcome: Result<(), ScriptResponse>) {
        let Some(PendingProvision {
            config,
            reply,
            session_id,
            _retire_deadline: _,
        }) = self.pending.remove(&token)
        else {
            return;
        };

        if let Err(e) = outcome {
            let _ = reply.send(Err(sr_err(e)));
            return;
        }

        let sdk = self.sdk.as_ref().expect("session ensured");

        // The parked provision and its pull both pin this session, so it
        // cannot be missing. A session released under a running pull has
        // already been used after free, so there is nothing to recover.
        let session = self.sessions[&session_id].session.as_raw();

        // SAFETY: `sdk`/`session` are valid.
        if let Err(e) = unsafe {
            image::report_pulled_digest(
                sdk,
                session,
                &config.image,
                "[WSLC][daemon]",
                &mut self.logger,
            )
        } {
            let _ = reply.send(Err(sr_err(e)));
            return;
        }

        let _ = reply.send(self.create_provisioned_container(&config, &session_id));
    }

    /// Everything after the image is in the store: create the container and
    /// register it under a fresh sandbox id.
    fn create_provisioned_container(
        &mut self,
        config: &ProvisionConfig,
        session_id: &str,
    ) -> Result<String, WorkerError> {
        let sdk = self.sdk.as_ref().expect("session ensured");
        let session = self.sessions[session_id].session.as_raw();

        let mounts: Vec<policy_mapping::VolumeMount> = config
            .volumes
            .iter()
            .map(|v| policy_mapping::VolumeMount {
                windows_path: v.host.clone(),
                container_path: v.container.clone(),
                read_only: v.read_only,
            })
            .collect();
        let net_mode = match config.network {
            NetworkMode::None => WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_NONE,
            NetworkMode::Bridged => {
                WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_BRIDGED
            }
        };
        let port_mappings = to_model_port_mappings(&config.port_mappings);

        // SAFETY: `sdk`/`session` are valid; every buffer the SDK stores pointers
        // into is owned by a stationary local (`keepalive`) until create returns.
        let container = unsafe {
            // Merge keeps the keepalive out of `env -i`, so a container whose
            // execs never replace an environment does not need `/usr/bin/env`
            // in its image.
            let mut keepalive = ProcessSettings::build_detached(
                sdk,
                container_steps::KEEPALIVE_SCRIPT,
                &[],
                EnvScope::Merge,
                "",
            )
            .map_err(sr_err)?;

            container_steps::create_daemon_container(
                sdk,
                session,
                &config.image,
                &mounts,
                &port_mappings,
                net_mode,
                &mut keepalive,
                &mut self.logger,
            )
            .map_err(sr_err)?
        };

        let sandbox_id = format!("wslc:{}", uuid::Uuid::new_v4().simple());
        self.containers.insert(
            sandbox_id.clone(),
            ContainerEntry {
                started: false,
                quarantined: false,
                retired: false,
                container,
                session_id: session_id.to_string(),
                exec_slot: None,
            },
        );
        Ok(sandbox_id)
    }

    fn start(&mut self, config: StartConfig) -> Result<(), WorkerError> {
        // Existence check first, so an unknown sandbox errors without needing the
        // SDK (keeps the no-WSL unit tests self-contained).
        if !self.containers.contains_key(&config.sandbox_id) {
            return Err(WorkerError::NotProvisioned(config.sandbox_id));
        }
        let sdk = self
            .sdk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active WSLc session"))?;
        let entry = self
            .containers
            .get_mut(&config.sandbox_id)
            .expect("checked above");
        if entry.quarantined {
            return Err(WorkerError::Backend(anyhow::anyhow!(
                "sandbox {} is quarantined after an exec whose termination could not be \
                 confirmed; deprovision it before reuse",
                config.sandbox_id
            )));
        }
        // SAFETY: `sdk` is valid and `entry.container` is a live handle.
        unsafe {
            container_steps::start_daemon_container(sdk, entry.container.as_raw(), &mut self.logger)
        }
        .map_err(sr_err)?;
        entry.started = true;
        Ok(())
    }

    /// Validate that a sandbox exists and is started, returning the live handle
    /// needed to run. Sole owner of the exists+started invariant: [`begin_exec`]
    /// trusts the handle it is given and never re-checks, because the worker
    /// validates and claims the container's in-flight slot without yielding, and
    /// no later command naming that container can release the handle while the
    /// claim stands.
    ///
    /// [`begin_exec`]: Worker::begin_exec
    fn validate_exec(&self, sandbox_id: &str) -> Result<WslcContainer, WorkerError> {
        match self.containers.get(sandbox_id) {
            None => Err(WorkerError::NotProvisioned(sandbox_id.to_string())),
            Some(entry) if entry.quarantined => Err(WorkerError::Backend(anyhow::anyhow!(
                "sandbox {sandbox_id} is quarantined after an exec whose termination could not \
                 be confirmed; deprovision it before reuse"
            ))),
            Some(entry) if !entry.started => Err(WorkerError::NotStarted(sandbox_id.to_string())),
            Some(entry) => Ok(entry.container.as_raw()),
        }
    }

    /// Run one container command, refusing a second exec on a container that
    /// already has one and parking lifecycle work behind the run instead.
    fn dispatch(&mut self, work: ContainerWork, worker: &mpsc::UnboundedSender<WorkerCommand>) {
        if let Some(in_flight) = self.exec_in_flight.get_mut(work.sandbox_id()) {
            match work {
                ContainerWork::Exec(request) => {
                    let ExecRequest { config, admit, .. } = request;
                    let _ = admit.send(Err(WorkerError::Busy(config.sandbox_id)));
                }
                lifecycle => in_flight.parked.push(lifecycle),
            }
            return;
        }

        match work {
            ContainerWork::Exec(request) => self.begin_exec(request, worker),
            ContainerWork::Start { config, reply } => {
                let _ = reply.send(self.start(config));
            }
            ContainerWork::Stop { config, reply } => {
                let _ = reply.send(self.stop(config));
            }
            ContainerWork::Deprovision { config, reply } => {
                let _ = reply.send(self.deprovision(config));
            }
        }
    }

    /// Admit an exec and hand the run to a thread of its own.
    ///
    /// Validation, the admission reply, the claim on the container and the
    /// spawn all happen here without yielding, so nothing can delete the
    /// validated handle before the run thread takes it.
    fn begin_exec(&mut self, request: ExecRequest, worker: &mpsc::UnboundedSender<WorkerCommand>) {
        let ExecRequest {
            config,
            sink,
            cancellation,
            registration,
            admit,
            done,
            slot,
        } = request;

        let container = match self.validate_exec(&config.sandbox_id) {
            Ok(container) => container,
            Err(e) => {
                let _ = admit.send(Err(e));
                return;
            }
        };

        // Recorded here rather than looked up when the run reports, because
        // quarantine can delete the container entry while the run is still
        // going.
        let session_id = self.containers[&config.sandbox_id].session_id.clone();

        if cancellation.load(Ordering::Acquire) {
            if admit.send(Ok(())).is_ok() {
                let _ = done.send(Ok(ExecTerminal::Cancelled));
            }
            return;
        }

        // Starting a run the client handler already abandoned would hold the
        // container's slot for the full timeout with nobody left to read it.
        if admit.send(Ok(())).is_err() {
            return;
        }

        let sandbox_id = config.sandbox_id.clone();
        let start_run = self.start_run;
        if let Err(e) = start_run(self, config, container, sink, cancellation, worker) {
            let _ = done.send(Err(e));
            return;
        }

        self.exec_in_flight.insert(
            sandbox_id,
            InFlightExec {
                container,
                done,
                session_id,
                _registration: registration,
                slot,
                parked: Vec::new(),
            },
        );
    }

    /// Retire a finished exec: answer its client, then release the work that
    /// parked behind it.
    fn finish_exec(
        &mut self,
        sandbox_id: &str,
        report: ExecReport,
        worker: &mpsc::UnboundedSender<WorkerCommand>,
    ) {
        for work in self.retire_exec(sandbox_id, report) {
            self.dispatch(work, worker);
        }
    }

    /// Answer a finished exec and hand back whatever parked behind it.
    ///
    /// Separate from [`Worker::finish_exec`] so teardown can answer the client
    /// without releasing parked work into a daemon that is shutting down.
    fn retire_exec(&mut self, sandbox_id: &str, report: ExecReport) -> Vec<ContainerWork> {
        let Some(in_flight) = self.exec_in_flight.remove(sandbox_id) else {
            return Vec::new();
        };

        let outcome = match report {
            ExecReport::Finished(outcome) => outcome,
            ExecReport::Unconfirmed(detail) => {
                Err(self.quarantine(sandbox_id, in_flight.container, &detail, in_flight.slot))
            }
        };

        if let Err(orphaned) = in_flight.done.send(outcome) {
            // The client handler is gone (e.g. its post-admission Ok write
            // failed) but the run already happened. Record the result so a
            // completed exec is never silently lost.
            self.logger.log_line(&format!(
                "exec on {sandbox_id} completed after the client disconnected; \
                 orphaned result: {orphaned:?}"
            ));
        }

        in_flight.parked
    }

    fn quarantine(
        &mut self,
        sandbox_id: &str,
        container: WslcContainer,
        detail: &str,
        slot: Option<ExecSlotGuard>,
    ) -> WorkerError {
        let delete_result = self.sdk.as_ref().map(|sdk| {
            // SAFETY: `sdk` is valid and `container` is the live handle stored
            // for `sandbox_id`.
            unsafe { container_steps::delete_daemon_container(sdk, container, &mut self.logger) }
        });

        match delete_result {
            Some(Ok(())) => {
                // Deleting the container ends anything still running inside it,
                // so this exec stops counting against capacity.
                drop(slot);
                self.containers.remove(sandbox_id);
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     the container was quarantined and deleted"
                ))
            }
            Some(Err(delete_error)) => {
                if let Some(entry) = self.containers.get_mut(sandbox_id) {
                    entry.quarantined = true;
                    entry.exec_slot = slot;
                }
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     quarantine deletion failed and the sandbox remains blocked until \
                     deprovision succeeds: {}",
                    delete_error.error_message
                ))
            }
            None => {
                if let Some(entry) = self.containers.get_mut(sandbox_id) {
                    entry.quarantined = true;
                    entry.exec_slot = slot;
                }
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     the sandbox remains quarantined because no active WSLc SDK is available"
                ))
            }
        }
    }

    fn stop(&mut self, config: StopConfig) -> Result<(), WorkerError> {
        if !self.containers.contains_key(&config.sandbox_id) {
            return Err(WorkerError::NotProvisioned(config.sandbox_id));
        }
        let sdk = self
            .sdk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active WSLc session"))?;
        let entry = self
            .containers
            .get_mut(&config.sandbox_id)
            .expect("checked above");
        // SAFETY: `sdk` is valid and `entry.container` is a live handle.
        unsafe {
            container_steps::stop_daemon_container(sdk, entry.container.as_raw(), &mut self.logger)
        }
        .map_err(sr_err)?;
        entry.started = false;
        Ok(())
    }

    /// Stop counting a sandbox that no client can reach.
    fn retire(&mut self, sandbox_id: &str) {
        if let Some(entry) = self.containers.get_mut(sandbox_id) {
            entry.retired = true;
        }
    }

    /// Containers a client could still act on.
    ///
    /// Drives the idle watchdog, which shuts the daemon down only at zero. A
    /// parked provision has no container yet, so counting it keeps the daemon
    /// alive for the client still waiting on its pull.
    fn live_container_count(&self) -> usize {
        self.containers.values().filter(|e| !e.retired).count() + self.pending.len()
    }

    fn deprovision(&mut self, config: DeprovisionConfig) -> Result<(), WorkerError> {
        let container_raw = match self.containers.get(&config.sandbox_id) {
            Some(e) => e.container.as_raw(),
            None => return Err(WorkerError::NotProvisioned(config.sandbox_id)),
        };

        if let Some(sdk) = self.sdk.as_ref() {
            // SAFETY: `sdk` is valid and `container_raw` is a live handle.
            unsafe {
                container_steps::delete_daemon_container(sdk, container_raw, &mut self.logger)
            }
            .map_err(sr_err)?;
        }

        // Delete succeeded (or no SDK loaded): drop the handle now. Keeping the
        // entry on failure above leaves it retryable.
        self.containers.remove(&config.sandbox_id);

        // The session and SDK stay loaded so a subsequent provision reuses the
        // already-booted WSL2 VM.
        Ok(())
    }

    /// Give up the SDK handles rather than release them, when an off-worker
    /// thread may still be using one.
    ///
    /// Reached only on an unwind, where [`Worker::shutdown`]'s drain never ran.
    fn abandon_if_borrowed(
        mut self,
        execs_in_flight: usize,
        sessions_in_flight: usize,
        pull_outstanding: bool,
    ) {
        if execs_in_flight > 0 || sessions_in_flight > 0 || pull_outstanding {
            std::mem::forget(std::mem::take(&mut self.containers));

            // Forgets each store lease with its handle, so the slot stays
            // held: an abandoned session keeps its VHDX mounted.
            std::mem::forget(std::mem::take(&mut self.sessions));

            // A boot still running is about to open the store its lease holds,
            // so that slot must stay held too.
            std::mem::forget(std::mem::take(&mut self.pending_sessions));
            std::mem::forget(self.sdk.take());
        }

        // Only the handles are abandoned, so the reply channels close as the
        // bookkeeping drops and a waiting client observes the worker is gone.
    }

    /// Answer a command pulled off the queue during teardown.
    ///
    /// [`WorkerCommand::ExecFinished`] is the one the drain is looking for and
    /// is handled by its caller.
    fn refuse_while_shutting_down(&self, cmd: WorkerCommand) {
        const SHUTTING_DOWN: &str = "the WSLc daemon is shutting down";

        match cmd {
            WorkerCommand::ProvisionSession { reply, .. } => {
                let _ = reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "{SHUTTING_DOWN}"
                ))));
            }
            WorkerCommand::DeprovisionSession { reply, .. } => {
                let _ = reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "{SHUTTING_DOWN}"
                ))));
            }
            // The session this would register was already answered above, and
            // its handle is released by the drain rather than here.
            WorkerCommand::SessionBooted { .. } => {}
            WorkerCommand::Provision { reply, .. } => {
                let _ = reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "{SHUTTING_DOWN}"
                ))));
            }
            WorkerCommand::Container(work) => work.refuse(SHUTTING_DOWN),
            WorkerCommand::Retire { reply, .. } => {
                let _ = reply.send(());
            }
            WorkerCommand::ContainerCount { reply } => {
                let _ = reply.send(self.live_container_count());
            }
            WorkerCommand::Shutdown { reply } => {
                let _ = reply.send(());
            }

            // The provision this would resume was already answered above.
            WorkerCommand::PullFinished { .. } => {}
            WorkerCommand::ExecFinished { .. } => {}
        }
    }

    /// Release every container and every session.
    ///
    /// `drain_budget` bounds the whole teardown rather than each wait inside
    /// it, so a daemon holding several sessions cannot spend one budget per
    /// session.
    fn shutdown(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<WorkerCommand>,
        drain_budget: Duration,
    ) {
        let deadline = Instant::now() + drain_budget;

        for (_, pending) in self.pending.drain() {
            let _ = pending.reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                "the WSLc daemon shut down while pulling image '{}'",
                pending.config.image
            ))));
        }

        // A session still booting has clients waiting on it twice over: the one
        // that asked for the session, and every provision parked behind it.
        for (session_id, pending) in self.pending_sessions.iter_mut() {
            if let Some(reply) = pending.reply.take() {
                let _ = reply.send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "the WSLc daemon shut down while session {session_id} was booting"
                ))));
            }
            for (_, parked) in std::mem::take(&mut pending.parked) {
                let _ = parked.send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "the WSLc daemon shut down while session {session_id} was booting"
                ))));
            }
        }

        // An off-worker exec is still using its container handle, so nothing
        // below may stop, delete or release one until the runs report back.
        let execs_drained = wait_for_in_flight(&self.execs_in_flight, deadline);

        if execs_drained {
            // Every drained run queued its report before releasing its count, so
            // the reports are all in the channel now. Collecting them is what
            // lets a finished exec keep its own exit code instead of the
            // shutdown error below. Anything else found along the way is
            // answered rather than dropped, since a dropped reply reaches its
            // client as a bare "worker gone".
            while !self.exec_in_flight.is_empty() {
                let Ok(cmd) = rx.try_recv() else {
                    break;
                };
                match cmd {
                    WorkerCommand::ExecFinished { sandbox_id, report } => {
                        for work in self.retire_exec(&sandbox_id, report) {
                            work.refuse(&format!(
                                "the WSLc daemon shut down before sandbox {sandbox_id} was free"
                            ));
                        }
                    }
                    other => self.refuse_while_shutting_down(other),
                }
            }
        }

        for (sandbox_id, in_flight) in self.exec_in_flight.drain() {
            let _ = in_flight
                .done
                .send(Err(WorkerError::Backend(anyhow::anyhow!(
                    "the WSLc daemon shut down while running an exec on sandbox {sandbox_id}"
                ))));
            for work in in_flight.parked {
                work.refuse(&format!(
                    "the WSLc daemon shut down before sandbox {sandbox_id} was free"
                ));
            }
        }

        if !execs_drained {
            self.logger.log_line(
                "a WSLC exec is still running; leaking every session rather than \
                 releasing handles it is using",
            );
            std::mem::forget(std::mem::take(&mut self.containers));
            std::mem::forget(std::mem::take(&mut self.sessions));

            // A boot still running is about to open the store its lease holds.
            std::mem::forget(std::mem::take(&mut self.pending_sessions));
            std::mem::forget(self.sdk.take());
            return;
        }

        if let Some(sdk) = self.sdk.as_ref() {
            for (_, entry) in self.containers.drain() {
                // SAFETY: `sdk` is valid and `entry.container` is a live handle.
                unsafe {
                    if entry.started {
                        let _ = container_steps::stop_daemon_container(
                            sdk,
                            entry.container.as_raw(),
                            &mut self.logger,
                        );
                    }
                    let _ = container_steps::delete_daemon_container(
                        sdk,
                        entry.container.as_raw(),
                        &mut self.logger,
                    );
                }
                // entry (WslcContainerGuard) drops here, releasing the handle.
            }
        } else {
            self.containers.clear();
        }

        self.release_sessions_for_shutdown(deadline);
    }

    /// Release the sessions nothing is still using and abandon the rest.
    ///
    /// Runs while the SDK is still loaded, since a session handle's `Drop`
    /// calls into it.
    fn release_sessions_for_shutdown(&mut self, deadline: Instant) {
        let mut abandoned = false;

        // A boot still running holds the SDK and is about to open the store
        // its lease points at.
        if !wait_for_in_flight(&self.sessions_in_flight, deadline) {
            self.logger.log_line(
                "a WSLC session is still booting; leaking its store lease rather than \
                 returning a slot the boot is about to open",
            );
            std::mem::forget(std::mem::take(&mut self.pending_sessions));
            abandoned = true;
        } else {
            // Every drained boot queued its report before releasing its count,
            // so anything still pending here never got one. Dropping the entry
            // returns its slot, which is correct: no VM was ever created on it.
            self.pending_sessions.clear();
        }

        for (session_id, entry) in self.sessions.drain() {
            if !wait_for_in_flight(&entry.pulls_in_flight, deadline) {
                self.logger.log_line(&format!(
                    "a WSLC image pull is still running on session {session_id}; leaking it \
                     rather than releasing a handle the pull is using"
                ));

                // Forgets the store lease with the session, so the slot stays
                // held: the leaked session keeps the store's VHDX mounted.
                std::mem::forget(entry);
                abandoned = true;
                continue;
            }

            let SessionEntry {
                session,
                store,
                name,
                ..
            } = entry;
            if let Err(e) =
                container_steps::release_daemon_session(session, &name, &mut self.logger)
            {
                self.logger.log_line(&format!(
                    "releasing session {session_id} reported a failure: {}",
                    e.error_message
                ));
            }
            drop(store);
        }

        // Last, and only once every session that could be released has been:
        // dropping a session handle after this would call into an unloaded
        // `wslcsdk.dll`.
        if abandoned {
            std::mem::forget(self.sdk.take());
        } else {
            self.sdk = None;
        }
    }
}

/// Spawn the WSLc worker thread and return a handle to it.
///
/// The thread joins the MTA for its entire lifetime (WSLc SDK apartment
/// affinity) and processes [`WorkerCommand`]s until a [`WorkerCommand::Shutdown`]
/// is received or the command channel closes.
pub fn spawn() -> Result<SessionHandle> {
    let (tx, mut rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let active_execs = Arc::new(Mutex::new(HashMap::new()));

    // A parked provision or a finished exec resumes by posting back into this
    // queue.
    let worker_tx = tx.clone();

    std::thread::Builder::new()
        .name("wslc-session-worker".to_string())
        .spawn(move || {
            #[cfg(windows)]
            let _com = match ComApartment::enter() {
                Ok(com) => com,
                Err(e) => {
                    eprintln!("[wslc-daemon] worker COM initialisation failed: {e:#}");
                    return;
                }
            };

            let mut worker = Worker::new();

            // A panic here would otherwise drop the container handles an exec
            // thread is still using, so the unwind is caught and the handles
            // are abandoned instead.
            let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        WorkerCommand::ProvisionSession { config, reply } => {
                            let sizing = SessionSizing {
                                cpu_count: config.cpu_count,
                                memory_mb: config.memory_mb,
                                gpu: config.gpu,
                            };

                            // The reply travels with the pending session and is
                            // answered once the VM is up, so a slow boot does
                            // not hold this thread.
                            match worker.begin_session(sizing, &worker_tx) {
                                Ok(session_id) => {
                                    worker.attach_session_reply(&session_id, reply);
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                        WorkerCommand::SessionBooted {
                            session_id,
                            outcome,
                        } => {
                            worker.finish_session(&session_id, outcome, &worker_tx);
                        }
                        WorkerCommand::DeprovisionSession { config, reply } => {
                            let _ = reply.send(worker.release_session(&config.session_id));
                        }
                        WorkerCommand::Provision { config, reply } => {
                            worker.begin_provision(config, reply, &worker_tx);
                        }
                        WorkerCommand::PullFinished { token, outcome } => {
                            worker.finish_provision(token, outcome);
                        }
                        WorkerCommand::Container(work) => {
                            worker.dispatch(work, &worker_tx);
                        }
                        WorkerCommand::ExecFinished { sandbox_id, report } => {
                            worker.finish_exec(&sandbox_id, report, &worker_tx);
                        }
                        WorkerCommand::Retire { sandbox_id, reply } => {
                            worker.retire(&sandbox_id);
                            let _ = reply.send(());
                        }
                        WorkerCommand::ContainerCount { reply } => {
                            // This poll is the daemon's only periodic tick, so
                            // the session reaper rides along on it.
                            worker.reap_idle_sessions();
                            let _ = reply.send(worker.live_container_count());
                        }
                        WorkerCommand::Shutdown { reply } => {
                            worker.shutdown(&mut rx, DRAIN_TIMEOUT);
                            let _ = reply.send(());
                            break;
                        }
                    }
                }
            }));

            if served.is_err() {
                let in_flight = worker.execs_in_flight.load(Ordering::SeqCst);
                let booting = worker.sessions_in_flight.load(Ordering::SeqCst);

                // A pull borrows the SDK and session the same way a run does.
                let pull_outstanding = !image::wait_for_pulls_in_flight(Duration::ZERO);
                worker.abandon_if_borrowed(in_flight, booting, pull_outstanding);
            }
        })
        .map_err(|e| anyhow::anyhow!("spawn WSLc worker thread: {e}"))?;

    Ok(SessionHandle { tx, active_execs })
}

/// RAII guard that keeps the calling thread in the COM MTA for the WSLc SDK.
#[cfg(windows)]
struct ComApartment;

#[cfg(windows)]
impl ComApartment {
    fn enter() -> Result<Self> {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        // SAFETY: called once at worker-thread startup. On success the matching
        // `CoUninitialize` runs in `Drop`; on failure no guard is produced, so
        // `CoUninitialize` is never called for an apartment we did not enter.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() {
            anyhow::bail!("CoInitializeEx(MTA) failed: {hr:?}");
        }
        Ok(Self)
    }
}

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        use windows::Win32::System::Com::CoUninitialize;
        // SAFETY: balances the CoInitializeEx in `enter`, on the same thread.
        unsafe {
            CoUninitialize();
        }
    }
}

/// The daemon IPC frame carries no protocol, so every mapping is rebuilt as TCP.
fn to_model_port_mappings(
    mappings: &[PortMapping],
) -> Vec<mxc_sdk::mxc_common::models::PortMapping> {
    mappings
        .iter()
        .map(|mapping| mxc_sdk::mxc_common::models::PortMapping {
            windows_port: mapping.windows_port,
            container_port: mapping.container_port,
            protocol: "tcp".to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(handle: &SessionHandle) -> usize {
        handle.container_count().await.unwrap()
    }

    // ---- No-WSL unit tests (run everywhere, never touch the SDK) ----

    #[test]
    fn port_mappings_convert_to_tcp_models_in_order() {
        let converted = to_model_port_mappings(&[
            PortMapping {
                windows_port: 8080,
                container_port: 80,
            },
            PortMapping {
                windows_port: 8443,
                container_port: 443,
            },
        ]);

        assert_eq!(
            converted,
            vec![
                mxc_sdk::mxc_common::models::PortMapping {
                    windows_port: 8080,
                    container_port: 80,
                    protocol: "tcp".to_string(),
                },
                mxc_sdk::mxc_common::models::PortMapping {
                    windows_port: 8443,
                    container_port: 443,
                    protocol: "tcp".to_string(),
                },
            ]
        );
    }

    #[test]
    fn no_port_mappings_convert_to_an_empty_list() {
        assert!(to_model_port_mappings(&[]).is_empty());
    }

    /// The session every test fixture attributes its containers and work to.
    const TEST_SESSION: &str = "wslcsess:test";

    /// Build a worker entry around a handle that is never dereferenced.
    fn test_entry(retired: bool) -> ContainerEntry {
        unsafe extern "C" fn release_noop(
            _: mxc_sdk::wslc_common::wslc_bindings::WslcContainer,
        ) -> i32 {
            0
        }

        // Non-null only because the guard rejects null; the value is never used
        // as a pointer.
        let sentinel = std::ptr::dangling_mut();
        ContainerEntry {
            started: false,
            quarantined: false,
            retired,
            // SAFETY: `release_noop` never dereferences the handle, so the guard
            // owns a value it can release without touching memory.
            container: unsafe { WslcContainerGuard::from_raw(sentinel, release_noop) },
            session_id: TEST_SESSION.to_string(),
            exec_slot: None,
        }
    }

    /// A parked provision has no container yet, so the watchdog would retire
    /// the daemon out from under the client still waiting on its pull.
    /// A timer that outlived its pull would sit for the rest of the budget, so
    /// sequential cache misses would pile up sleeping threads.
    #[test]
    fn a_pull_that_lands_first_retires_its_deadline_thread() {
        let (retire_deadline, retired) = std::sync::mpsc::channel::<()>();
        let woke = std::thread::spawn(move || {
            retired.recv_timeout(Duration::from_secs(30))
                == Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        });

        drop(retire_deadline);

        assert!(
            woke.join().expect("timer thread"),
            "dropping the parked provision must wake its deadline immediately"
        );
    }

    #[test]
    fn a_pending_pull_keeps_the_daemon_alive() {
        let mut worker = Worker::new();
        assert_eq!(worker.live_container_count(), 0);

        let (reply, _rx) = oneshot::channel();
        worker.pending.insert(
            7,
            PendingProvision {
                config: ProvisionConfig {
                    image: "alpine:latest".to_string(),
                    image_tar_path: None,
                    volumes: Vec::new(),
                    network: Default::default(),
                    port_mappings: Vec::new(),
                    session_id: None,
                },
                reply,
                session_id: TEST_SESSION.to_string(),
                _retire_deadline: std::sync::mpsc::channel().0,
            },
        );

        assert_eq!(
            worker.live_container_count(),
            1,
            "a provision still waiting on its image must hold the daemon open"
        );
    }

    /// The pull and its deadline race, and both report.
    #[test]
    fn only_the_first_report_of_a_pull_answers_the_client() {
        let mut worker = Worker::new();
        let (reply, mut rx) = oneshot::channel();
        worker.pending.insert(
            3,
            PendingProvision {
                config: ProvisionConfig {
                    image: "alpine:latest".to_string(),
                    image_tar_path: None,
                    volumes: Vec::new(),
                    network: Default::default(),
                    port_mappings: Vec::new(),
                    session_id: None,
                },
                reply,
                session_id: TEST_SESSION.to_string(),
                _retire_deadline: std::sync::mpsc::channel().0,
            },
        );

        worker.finish_provision(
            3,
            Err(image::pull_deadline_expired("alpine:latest", DRAIN_TIMEOUT)),
        );
        assert!(rx.try_recv().is_ok(), "the first report answers the client");

        // The loser of the race: nothing left to answer, and no panic.
        worker.finish_provision(3, Ok(()));
        assert_eq!(worker.live_container_count(), 0);
    }

    #[test]
    fn a_retired_sandbox_stops_holding_the_daemon_open() {
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:orphan".to_string(), test_entry(false));
        assert_eq!(worker.live_container_count(), 1);

        worker.retire("wslc:orphan");

        assert_eq!(
            worker.live_container_count(),
            0,
            "a retired sandbox must not keep the daemon alive"
        );
        assert!(
            worker.containers.contains_key("wslc:orphan"),
            "the handle stays so shutdown can still delete the container"
        );
    }

    #[test]
    fn retiring_one_sandbox_leaves_the_others_counted() {
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:orphan".to_string(), test_entry(false));
        worker
            .containers
            .insert("wslc:live".to_string(), test_entry(false));

        worker.retire("wslc:orphan");

        assert_eq!(worker.live_container_count(), 1);
    }

    /// Retirement is driven by a failed release, which can name a sandbox that
    /// is already gone.
    #[test]
    fn retiring_an_unknown_sandbox_is_a_no_op() {
        let mut worker = Worker::new();
        worker.retire("wslc:never-existed");
        assert_eq!(worker.live_container_count(), 0);
    }

    // ---- Session bookkeeping (no WSL host; the handles are never used) ----

    /// A worker whose store pool is a scratch directory, so leasing a slot
    /// neither touches nor fills the real per-user pool.
    fn worker_with_scratch_pool() -> (tempfile::TempDir, Worker) {
        let root = tempfile::tempdir().expect("create scratch pool root");
        let mut worker = Worker::new();
        worker.store_slots = StoreSlotPool::with_root(root.path().to_path_buf());
        (root, worker)
    }

    /// Register a session whose handle is never dereferenced.
    fn register_test_session(worker: &mut Worker, session_id: &str) {
        unsafe extern "C" fn session_noop(
            _: mxc_sdk::wslc_common::wslc_bindings::WslcSession,
        ) -> i32 {
            0
        }

        // Non-null only because the guard rejects null; never used as a pointer.
        let sentinel = std::ptr::dangling_mut();
        let (store, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease a scratch slot");

        worker.sessions.insert(
            session_id.to_string(),
            SessionEntry {
                // SAFETY: neither function pointer dereferences the handle, so
                // the guard owns a value it can release without touching
                // memory.
                session: unsafe {
                    WslcSessionGuard::from_raw(sentinel, session_noop, session_noop)
                },
                store,
                name: session_name(session_id),
                sizing: SessionSizing::default(),
                pulls_in_flight: Arc::new(AtomicUsize::new(0)),
                empty_since: None,
            },
        );
    }

    /// Register a session whose boot is still running.
    fn register_booting_session(worker: &mut Worker, session_id: &str) {
        let (store, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease a scratch slot");

        worker.pending_sessions.insert(
            session_id.to_string(),
            PendingSession {
                store,
                name: session_name(session_id),
                sizing: SessionSizing::default(),
                reply: None,
                parked: Vec::new(),
            },
        );
    }

    /// A provision that names no session, so it joins the implicit one.
    fn test_provision_config() -> ProvisionConfig {
        ProvisionConfig {
            image: "alpine:latest".to_string(),
            image_tar_path: None,
            volumes: Vec::new(),
            network: Default::default(),
            port_mappings: Vec::new(),
            session_id: None,
        }
    }

    #[test]
    fn a_retired_container_still_holds_its_session_but_not_the_daemon() {
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:orphan".to_string(), test_entry(true));

        assert_eq!(
            worker.session_hold(TEST_SESSION),
            1,
            "releasing a session out from under a live container handle would \
             leave that handle dangling"
        );
        assert_eq!(
            worker.live_container_count(),
            0,
            "a retired sandbox must still not hold the daemon open"
        );
    }

    /// Quarantine keeps the entry when its delete failed, so a process may
    /// still be live in that container.
    #[test]
    fn a_quarantined_container_still_holds_its_session() {
        let mut worker = Worker::new();
        worker.containers.insert(
            "wslc:quarantined".to_string(),
            ContainerEntry {
                quarantined: true,
                ..test_entry(false)
            },
        );

        assert_eq!(worker.session_hold(TEST_SESSION), 1);
    }

    #[test]
    fn a_container_in_another_session_does_not_hold_this_one() {
        let mut worker = Worker::new();
        worker.containers.insert(
            "wslc:elsewhere".to_string(),
            ContainerEntry {
                session_id: "wslcsess:other".to_string(),
                ..test_entry(false)
            },
        );

        assert_eq!(worker.session_hold(TEST_SESSION), 0);
        assert_eq!(worker.session_hold("wslcsess:other"), 1);
    }

    #[test]
    fn a_parked_provision_holds_its_session() {
        let mut worker = Worker::new();
        let (reply, _rx) = oneshot::channel();
        worker.pending.insert(
            1,
            PendingProvision {
                config: ProvisionConfig {
                    image: "alpine:latest".to_string(),
                    image_tar_path: None,
                    volumes: Vec::new(),
                    network: Default::default(),
                    port_mappings: Vec::new(),
                    session_id: None,
                },
                reply,
                session_id: TEST_SESSION.to_string(),
                _retire_deadline: std::sync::mpsc::channel().0,
            },
        );

        assert_eq!(worker.session_hold(TEST_SESSION), 1);
    }

    #[test]
    fn an_in_flight_exec_holds_its_session() {
        let mut worker = Worker::new();
        let (in_flight, _done) = in_flight_exec("exec-1");
        worker
            .exec_in_flight
            .insert("wslc:running".to_string(), in_flight);

        assert_eq!(
            worker.session_hold(TEST_SESSION),
            1,
            "a run is still using a container handle from this session, even \
             once quarantine has taken the container entry away"
        );
    }

    /// A pull and its deadline race, and the deadline winning removes the
    /// pending entry while the pull thread still holds the session handle.
    #[test]
    fn an_in_flight_pull_holds_its_session_after_its_parked_provision_is_gone() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);

        worker.sessions[TEST_SESSION]
            .pulls_in_flight
            .fetch_add(1, Ordering::SeqCst);

        assert!(
            worker.pending.is_empty(),
            "the deadline already answered and removed the parked provision"
        );
        assert_eq!(
            worker.session_hold(TEST_SESSION),
            1,
            "the pull thread still holds the session handle; reaping here is a \
             use-after-free"
        );
    }

    #[test]
    fn a_session_holding_something_is_not_reaped() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);
        worker
            .containers
            .insert("wslc:live".to_string(), test_entry(false));

        age_out(&mut worker, TEST_SESSION);
        worker.reap_idle_sessions();

        assert!(
            worker.sessions.contains_key(TEST_SESSION),
            "a session with a container in it must never be released"
        );
    }

    #[test]
    fn an_empty_session_is_kept_until_its_grace_elapses() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);

        worker.reap_idle_sessions();

        assert!(
            worker.sessions.contains_key(TEST_SESSION),
            "an empty session is kept for the grace, so a caller that is about \
             to place a container in it still can"
        );
        assert!(
            worker.sessions[TEST_SESSION].empty_since.is_some(),
            "the first pass that finds it empty must start its clock"
        );
    }

    #[test]
    fn an_empty_session_is_released_once_its_grace_elapses() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);
        let slot = worker.sessions[TEST_SESSION].store.path().to_path_buf();

        age_out(&mut worker, TEST_SESSION);
        worker.reap_idle_sessions();

        assert!(
            worker.sessions.is_empty(),
            "an orphaned session would otherwise pin a VM, a store slot and the \
             daemon itself, with nothing able to reclaim any of them"
        );

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease after the reap");
        assert_eq!(
            relet.path(),
            slot,
            "releasing a session must give its store slot back to the pool"
        );
    }

    /// An empty session holding the daemon open would let its grace run before
    /// the idle timeout even started, doubling teardown.
    #[test]
    fn an_empty_session_does_not_hold_the_daemon_open() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);

        assert_eq!(worker.live_container_count(), 0);
    }

    #[test]
    fn a_session_that_becomes_busy_again_restarts_its_grace() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);

        worker.reap_idle_sessions();
        assert!(worker.sessions[TEST_SESSION].empty_since.is_some());

        worker
            .containers
            .insert("wslc:live".to_string(), test_entry(false));
        worker.reap_idle_sessions();

        assert!(
            worker.sessions[TEST_SESSION].empty_since.is_none(),
            "work arriving must clear the clock, not leave a stale start time \
             that reaps the session the moment it next goes empty"
        );
    }

    #[test]
    fn a_daemon_holds_as_many_sessions_as_it_is_asked_for() {
        let (_root, mut worker) = worker_with_scratch_pool();

        for index in 0..16 {
            register_test_session(&mut worker, &format!("wslcsess:many{index}"));
        }

        assert_eq!(worker.sessions.len(), 16);

        let slots: std::collections::BTreeSet<usize> = worker
            .sessions
            .values()
            .map(|entry| entry.store.index())
            .collect();
        assert_eq!(
            slots.len(),
            16,
            "the store pool must mint a distinct slot per session rather than \
             bounding them; two sessions sharing a store is the sharing \
             violation the pool exists to prevent"
        );
    }

    #[test]
    fn an_unknown_session_id_is_refused_rather_than_quietly_defaulted() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut worker = Worker::new();

        let refusal = worker
            .ensure_session(Some("wslcsess:never-existed"), &tx)
            .expect_err("an unknown session must be refused");

        assert_eq!(refusal.kind(), ErrKind::NotProvisioned);
        assert!(
            !refusal.to_string().contains("sandbox"),
            "an unknown session must not be reported as an unknown sandbox: {refusal}"
        );
    }

    #[test]
    fn releasing_a_session_still_in_use_is_refused() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);
        worker
            .containers
            .insert("wslc:live".to_string(), test_entry(false));

        let refusal = worker
            .release_session(TEST_SESSION)
            .expect_err("a session with a sandbox in it must not be released");

        assert_eq!(refusal.kind(), ErrKind::Rejected);
        assert!(
            worker.sessions.contains_key(TEST_SESSION),
            "a refused release must leave the session alone"
        );
    }

    /// The implicit session is shared by every request that named none, so one
    /// caller releasing it would destroy another's sandboxes.
    #[test]
    fn releasing_the_implicit_session_is_refused() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);
        worker.default_session = Some(TEST_SESSION.to_string());

        let refusal = worker
            .release_session(TEST_SESSION)
            .expect_err("the implicit session must not be releasable by id");

        assert_eq!(refusal.kind(), ErrKind::Rejected);
        assert!(worker.sessions.contains_key(TEST_SESSION));
    }

    #[test]
    fn releasing_an_unknown_session_is_refused() {
        let mut worker = Worker::new();

        let refusal = worker
            .release_session("wslcsess:never-existed")
            .expect_err("an unknown session must be refused");

        assert_eq!(refusal.kind(), ErrKind::NotProvisioned);
    }

    #[test]
    fn the_reaper_does_not_wait_on_a_session_that_is_still_pulling() {
        let (_root, mut worker) = worker_with_scratch_pool();
        register_test_session(&mut worker, TEST_SESSION);
        worker.sessions[TEST_SESSION]
            .pulls_in_flight
            .fetch_add(1, Ordering::SeqCst);

        age_out(&mut worker, TEST_SESSION);
        let started = Instant::now();
        worker.reap_idle_sessions();

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the reaper must read the hold and move on; blocking here stalls \
             every other session's requests behind this one"
        );
        assert!(worker.sessions.contains_key(TEST_SESSION));
    }

    #[test]
    fn a_session_name_is_derived_from_its_id() {
        assert_eq!(
            session_name("wslcsess:0123456789abcdef"),
            "mxc-wslc-daemon-0123456789abcdef",
            "two sessions under one name is an untested SDK failure mode"
        );
        assert_ne!(
            session_name("wslcsess:aaaa"),
            session_name("wslcsess:bbbb"),
            "distinct sessions must get distinct names"
        );
    }

    /// Backdate a session's empty clock past any plausible grace.
    fn age_out(worker: &mut Worker, session_id: &str) {
        let aged = Instant::now() - Duration::from_secs(24 * 60 * 60);
        worker
            .sessions
            .get_mut(session_id)
            .expect("session is registered")
            .empty_since = Some(aged);
    }

    #[test]
    fn the_session_grace_defaults_to_the_daemon_idle_window() {
        assert_eq!(
            session_grace_from(None, None),
            crate::IDLE_TIMEOUT,
            "a session cannot outlive the daemon, so its grace must not claim a \
             longer window than the daemon's own"
        );
    }

    #[test]
    fn shortening_the_daemon_idle_window_shortens_the_session_grace() {
        assert_eq!(
            session_grace_from(None, Some("20")),
            Duration::from_secs(20),
            "a test that drives teardown sets one knob, not two"
        );
    }

    #[test]
    fn the_session_grace_can_be_set_on_its_own() {
        assert_eq!(
            session_grace_from(Some("45"), Some("20")),
            Duration::from_secs(45)
        );
    }

    // ---- Teardown with several sessions (C5) ----

    #[test]
    fn shutdown_releases_a_session_nothing_is_using() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_test_session(&mut worker, TEST_SESSION);
        let slot = worker.sessions[TEST_SESSION].store.path().to_path_buf();

        worker.shutdown(&mut rx, Duration::from_millis(100));

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease after teardown");
        assert_eq!(
            relet.path(),
            slot,
            "a cleanly released session must give its store slot back"
        );
    }

    #[test]
    fn shutdown_abandons_a_pulling_session_and_keeps_its_slot_leased() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_test_session(&mut worker, TEST_SESSION);
        let held = worker.sessions[TEST_SESSION].store.path().to_path_buf();
        worker.sessions[TEST_SESSION]
            .pulls_in_flight
            .fetch_add(1, Ordering::SeqCst);

        worker.shutdown(&mut rx, Duration::from_millis(100));

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("the pool still has a free slot");
        assert_ne!(
            relet.path(),
            held,
            "reissuing an abandoned session's slot hands out a store nothing \
             can open"
        );
    }

    #[test]
    fn shutdown_releases_the_clean_sessions_alongside_a_dirty_one() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_test_session(&mut worker, "wslcsess:dirty");
        register_test_session(&mut worker, "wslcsess:clean");
        let clean = worker.sessions["wslcsess:clean"].store.path().to_path_buf();
        worker.sessions["wslcsess:dirty"]
            .pulls_in_flight
            .fetch_add(1, Ordering::SeqCst);

        worker.shutdown(&mut rx, Duration::from_millis(100));

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("the clean session's slot came back");
        assert_eq!(
            relet.path(),
            clean,
            "only the session a pull is still using may be abandoned"
        );
    }

    #[test]
    fn a_shutdown_drain_spends_one_budget_across_every_session() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        let budget = Duration::from_millis(300);
        for session_id in ["wslcsess:a", "wslcsess:b", "wslcsess:c", "wslcsess:d"] {
            register_test_session(&mut worker, session_id);
            worker.sessions[session_id]
                .pulls_in_flight
                .fetch_add(1, Ordering::SeqCst);
        }

        let started = Instant::now();
        worker.shutdown(&mut rx, budget);
        let spent = started.elapsed();

        assert!(
            spent < budget * 2,
            "four stuck sessions took {spent:?} against a {budget:?} budget; the \
             deadline must be shared, not spent once per session"
        );
    }

    /// The worker has no SDK here, so the pending entry stands in for a boot
    /// that is still running.
    #[test]
    fn a_booting_session_does_not_stall_the_worker() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_root, mut worker) = worker_with_scratch_pool();
        register_booting_session(&mut worker, TEST_SESSION);
        worker
            .containers
            .insert("wslc:live".to_string(), started_entry());

        // A command for an unrelated sandbox, dispatched while the boot stands.
        let (work, mut reply) = stop_work("wslc:live");
        worker.dispatch(work, &tx);

        assert!(
            reply.try_recv().is_ok(),
            "a sandbox in another session must be served while one session boots"
        );
    }

    /// Two implicit sessions would mean two VMs where the caller asked for
    /// none.
    #[test]
    fn a_provision_during_the_implicit_boot_parks_rather_than_booting_a_second() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_root, mut worker) = worker_with_scratch_pool();
        register_booting_session(&mut worker, TEST_SESSION);
        worker.default_session = Some(TEST_SESSION.to_string());

        let (reply, mut rx) = oneshot::channel();
        worker.begin_provision(test_provision_config(), reply, &tx);

        assert_eq!(
            worker.pending_sessions.len(),
            1,
            "a provision mid-boot must not boot a second implicit session"
        );
        assert_eq!(
            worker.pending_sessions[TEST_SESSION].parked.len(),
            1,
            "it must park behind the boot already under way"
        );
        assert!(
            rx.try_recv().is_err(),
            "a parked provision is answered when its session is up, not before"
        );
    }

    #[test]
    fn a_failed_boot_answers_everything_parked_behind_it() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_root, mut worker) = worker_with_scratch_pool();
        register_booting_session(&mut worker, TEST_SESSION);
        worker.default_session = Some(TEST_SESSION.to_string());
        let slot = worker.pending_sessions[TEST_SESSION]
            .store
            .path()
            .to_path_buf();

        let (session_reply, mut session_rx) = oneshot::channel();
        worker.attach_session_reply(TEST_SESSION, session_reply);
        let (reply, mut rx) = oneshot::channel();
        worker.begin_provision(test_provision_config(), reply, &tx);

        worker.finish_session(
            TEST_SESSION,
            Err(WorkerError::Backend(anyhow::anyhow!(
                "ERROR_NO_SYSTEM_RESOURCES"
            ))),
            &tx,
        );

        assert!(
            session_rx.try_recv().expect("the session asker").is_err(),
            "the client that asked for the session must be told it failed"
        );
        assert!(
            rx.try_recv().expect("the parked provision").is_err(),
            "a provision parked behind a boot that failed must be answered, not \
             left waiting on a session that will never exist"
        );
        assert!(
            worker.default_session.is_none(),
            "a failed implicit boot must retire its id, so the next provision \
             starts a fresh one instead of parking behind a corpse"
        );

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease after the failed boot");
        assert_eq!(
            relet.path(),
            slot,
            "a boot that never created a VM must give its slot straight back"
        );
    }

    /// A boot still running is about to create a VM on the store its lease
    /// points at.
    #[test]
    fn a_shutdown_that_gives_up_on_an_exec_keeps_a_booting_sessions_slot() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_booting_session(&mut worker, TEST_SESSION);
        let held = worker.pending_sessions[TEST_SESSION]
            .store
            .path()
            .to_path_buf();
        worker
            .containers
            .insert("wslc:busy".to_string(), test_entry(false));
        let (in_flight, _done) = in_flight_exec("running");
        worker
            .exec_in_flight
            .insert("wslc:busy".to_string(), in_flight);

        // The run never reports, so the drain can only expire.
        let _counted = ExecCount::enter(&worker.execs_in_flight);
        worker.shutdown(&mut rx, Duration::from_millis(100));

        // The leases share the pool's bookkeeping, so moving it out keeps it
        // live while the worker's maps drop the way the worker thread drops
        // them.
        let pool = std::mem::replace(&mut worker.store_slots, StoreSlotPool::new());
        drop(worker);

        let (relet, ()) = pool
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("the pool still has a free slot");
        assert_ne!(
            relet.path(),
            held,
            "reissuing a booting session's slot hands the next lease a store a \
             VM is about to mount"
        );
    }

    #[test]
    fn a_shutdown_that_gives_up_on_a_boot_keeps_its_slot() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_booting_session(&mut worker, TEST_SESSION);
        let held = worker.pending_sessions[TEST_SESSION]
            .store
            .path()
            .to_path_buf();

        let _counted = SessionCount::enter(&worker.sessions_in_flight);
        worker.shutdown(&mut rx, Duration::from_millis(100));

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("the pool still has a free slot");
        assert_ne!(relet.path(), held);
    }

    #[test]
    fn a_shutdown_with_no_boot_running_returns_a_pending_slot() {
        let (_root, mut worker) = worker_with_scratch_pool();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        register_booting_session(&mut worker, TEST_SESSION);
        let slot = worker.pending_sessions[TEST_SESSION]
            .store
            .path()
            .to_path_buf();

        worker.shutdown(&mut rx, Duration::from_millis(100));

        let (relet, ()) = worker
            .store_slots
            .lease_with(|_| Ok::<(), ()>(()))
            .expect("lease after teardown");
        assert_eq!(relet.path(), slot);
    }

    #[test]
    fn sr_err_carries_the_step_failure_phase() {
        for (phase, expected) in [
            (FailurePhase::BackendUnavailable, ErrKind::Unavailable),
            (FailurePhase::Rejected, ErrKind::Rejected),
            (FailurePhase::LaunchFailed, ErrKind::Backend),
            (FailurePhase::PostLaunchFailed, ErrKind::Backend),
            (FailurePhase::None, ErrKind::Backend),
        ] {
            let resp = ScriptResponse {
                exit_code: -1,
                error_message: "boom".to_string(),
                failure_phase: phase.clone(),
                ..Default::default()
            };
            assert_eq!(sr_err(resp).kind(), expected, "phase {phase:?}");
        }
    }

    #[test]
    fn sr_err_preserves_the_step_message() {
        let resp = ScriptResponse {
            exit_code: -1,
            error_message: "WSLc components are missing".to_string(),
            failure_phase: FailurePhase::BackendUnavailable,
            ..Default::default()
        };
        assert_eq!(sr_err(resp).to_string(), "WSLc components are missing");
    }

    #[tokio::test]
    async fn start_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .start(StartConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exec_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .exec(
                ExecConfig {
                    exec_id: "unknown-1".to_string(),
                    run_token: "run-unknown-1".to_string(),
                    sandbox_id: "wslc:does-not-exist".to_string(),
                    script_code: "echo hi".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 0,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stop_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .stop(StopConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deprovision_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .deprovision(DeprovisionConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        assert_eq!(count(&handle).await, 0);
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unknown_sandbox_maps_to_not_provisioned_kind() {
        let handle = spawn().unwrap();
        let err = handle
            .start(StartConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrKind::NotProvisioned);
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exec_unknown_sandbox_admission_is_not_provisioned() {
        let handle = spawn().unwrap();
        let err = handle
            .exec(
                ExecConfig {
                    exec_id: "unknown-2".to_string(),
                    run_token: "run-unknown-2".to_string(),
                    sandbox_id: "wslc:does-not-exist".to_string(),
                    script_code: "echo hi".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 0,
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrKind::NotProvisioned);
        handle.shutdown().await.unwrap();
    }

    #[test]
    fn cancel_exec_marks_the_registered_run() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "run-1".to_string(),
                cancellation: Arc::downgrade(&cancellation),
            },
        )])));
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("exec-1", "run-1");

        assert!(cancellation.load(Ordering::Acquire));
    }

    #[test]
    fn delayed_cancellation_does_not_target_reused_exec_id() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let registration =
            register_exec(&active_execs, "exec-1", "replacement-run", &cancellation).unwrap();
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("exec-1", "completed-run");
        assert!(!cancellation.load(Ordering::Acquire));

        handle.cancel_exec("exec-1", "replacement-run");
        assert!(cancellation.load(Ordering::Acquire));
        drop(registration);
    }

    #[test]
    fn duplicate_live_exec_id_is_rejected_without_replacing_registration() {
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let registration = register_exec(&active_execs, "exec-1", "run-1", &first).unwrap();

        let error = register_exec(&active_execs, "exec-1", "run-2", &second).unwrap_err();

        assert_eq!(error.kind(), ErrKind::Rejected);
        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &first));
        drop(registration);
    }

    #[test]
    fn stale_exec_id_can_be_registered_again() {
        let stale = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "stale-run".to_string(),
                cancellation: Arc::downgrade(&stale),
            },
        )])));
        drop(stale);
        let cancellation = Arc::new(AtomicBool::new(false));

        let registration =
            register_exec(&active_execs, "exec-1", "replacement-run", &cancellation).unwrap();

        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &cancellation));
        drop(registration);
        assert!(!active_execs.lock().unwrap().contains_key("exec-1"));
    }

    #[test]
    fn older_registration_does_not_remove_replacement() {
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let first = Arc::new(AtomicBool::new(false));
        let first_registration = register_exec(&active_execs, "exec-1", "run-1", &first).unwrap();
        let second = Arc::new(AtomicBool::new(false));
        active_execs.lock().unwrap().insert(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "run-2".to_string(),
                cancellation: Arc::downgrade(&second),
            },
        );

        drop(first_registration);

        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &second));
    }

    #[test]
    fn cancelling_unknown_or_stale_exec_id_is_a_no_op() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let stale = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "stale".to_string(),
            ActiveExec {
                run_token: "stale-run".to_string(),
                cancellation: Arc::downgrade(&stale),
            },
        )])));
        drop(stale);
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("unknown", "unknown-run");
        handle.cancel_exec("stale", "stale-run");
    }

    #[tokio::test]
    async fn large_callback_split_into_frame_safe_chunks() {
        use mxc_sdk::wslc_common::daemon_protocol::{encode_frame, StreamFrame, MAX_FRAME_SIZE};

        let (tx, mut rx) = mpsc::channel::<OutputChunk>(LIVE_OUTPUT_CHANNEL_CAPACITY);
        // A single callback far larger than one chunk (and, unsplit, larger than
        // one frame once number-array-encoded): must arrive as many bounded chunks.
        let payload = vec![b'x'; LIVE_OUTPUT_MAX_CHUNK_BYTES * 3 + 7];
        let producer = tokio::task::spawn_blocking({
            let payload = payload.clone();
            move || {
                let overflowed = AtomicBool::new(false);
                enqueue_output(&tx, &overflowed, OutStream::Stdout, &payload)
            }
        });

        let mut reassembled = Vec::new();
        let mut chunks = 0usize;
        while let Some((kind, data)) = rx.recv().await {
            assert_eq!(kind, OutStream::Stdout);
            assert!(data.len() <= LIVE_OUTPUT_MAX_CHUNK_BYTES);
            let encoded = encode_frame(&StreamFrame::Stdout { data: data.clone() }).unwrap();
            assert!(encoded.len() <= MAX_FRAME_SIZE);
            reassembled.extend_from_slice(&data);
            chunks += 1;
        }
        producer.await.unwrap();
        assert_eq!(reassembled, payload);
        assert!(
            chunks >= 4,
            "expected the callback to be split, got {chunks}"
        );
    }

    /// A started container, so [`Worker::validate_exec`] admits an exec on it.
    fn started_entry() -> ContainerEntry {
        ContainerEntry {
            started: true,
            ..test_entry(false)
        }
    }

    /// A container whose handle release is observable, so a test can tell a
    /// deliberate leak from a normal drop.
    fn flagged_entry(
        release: unsafe extern "C" fn(mxc_sdk::wslc_common::wslc_bindings::WslcContainer) -> i32,
    ) -> ContainerEntry {
        let sentinel = std::ptr::dangling_mut();
        ContainerEntry {
            started: false,
            quarantined: false,
            retired: false,

            // SAFETY: `release` never dereferences the handle, so the guard owns
            // a value it can release without touching memory.
            container: unsafe { WslcContainerGuard::from_raw(sentinel, release) },
            session_id: TEST_SESSION.to_string(),
            exec_slot: None,
        }
    }

    /// An exec occupying a container's in-flight slot, with the completion
    /// receiver a test uses to observe what the worker answers.
    fn in_flight_exec(
        exec_id: &str,
    ) -> (
        InFlightExec,
        oneshot::Receiver<Result<ExecTerminal, WorkerError>>,
    ) {
        let (done, done_rx) = oneshot::channel();
        let active_execs: ActiveExecs = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration =
            Arc::new(register_exec(&active_execs, exec_id, "run", &cancellation).unwrap());
        (
            InFlightExec {
                container: std::ptr::dangling_mut(),
                done,
                session_id: TEST_SESSION.to_string(),
                _registration: registration,
                slot: None,
                parked: Vec::new(),
            },
            done_rx,
        )
    }

    /// An exec command and the handles a test needs to observe it.
    struct TestExec {
        work: ContainerWork,
        admit: oneshot::Receiver<Result<(), WorkerError>>,
        done: oneshot::Receiver<Result<ExecTerminal, WorkerError>>,
        cancellation: Arc<AtomicBool>,
    }

    fn exec_work(sandbox_id: &str, exec_id: &str) -> TestExec {
        exec_work_with_slot(sandbox_id, exec_id, None)
    }

    fn exec_work_with_slot(
        sandbox_id: &str,
        exec_id: &str,
        slot: Option<ExecSlotGuard>,
    ) -> TestExec {
        let (admit, admit_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let active_execs: ActiveExecs = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration =
            Arc::new(register_exec(&active_execs, exec_id, "run", &cancellation).unwrap());
        let sink: OutputSink = Box::new(|_, _| {});
        TestExec {
            work: ContainerWork::Exec(ExecRequest {
                config: ExecConfig {
                    exec_id: exec_id.to_string(),
                    run_token: "run".to_string(),
                    sandbox_id: sandbox_id.to_string(),
                    script_code: "echo hi".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 0,
                },
                sink,
                cancellation: Arc::clone(&cancellation),
                registration,
                admit,
                done,
                slot,
            }),
            admit: admit_rx,
            done: done_rx,
            cancellation,
        }
    }

    /// A worker holding one started container with an exec already in flight.
    fn worker_with_exec_in_flight() -> (Worker, oneshot::Receiver<Result<ExecTerminal, WorkerError>>)
    {
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:busy".to_string(), started_entry());
        let (in_flight, done) = in_flight_exec("running");
        worker
            .exec_in_flight
            .insert("wslc:busy".to_string(), in_flight);
        (worker, done)
    }

    /// A worker holding one started container it can start runs on without an
    /// SDK loaded.
    fn worker_that_can_run() -> Worker {
        fn start_nothing(
            _: &Worker,
            _: ExecConfig,
            _: WslcContainer,
            _: OutputSink,
            _: Arc<AtomicBool>,
            _: &mpsc::UnboundedSender<WorkerCommand>,
        ) -> Result<(), WorkerError> {
            Ok(())
        }

        let mut worker = Worker::new();
        worker.start_run = start_nothing;
        worker
            .containers
            .insert("wslc:ready".to_string(), started_entry());
        worker
    }

    fn start_work(sandbox_id: &str) -> (ContainerWork, oneshot::Receiver<Result<(), WorkerError>>) {
        let (reply, reply_rx) = oneshot::channel();
        (
            ContainerWork::Start {
                config: StartConfig {
                    sandbox_id: sandbox_id.to_string(),
                },
                reply,
            },
            reply_rx,
        )
    }

    fn stop_work(sandbox_id: &str) -> (ContainerWork, oneshot::Receiver<Result<(), WorkerError>>) {
        let (reply, reply_rx) = oneshot::channel();
        (
            ContainerWork::Stop {
                config: StopConfig {
                    sandbox_id: sandbox_id.to_string(),
                },
                reply,
            },
            reply_rx,
        )
    }

    fn deprovision_work(
        sandbox_id: &str,
    ) -> (ContainerWork, oneshot::Receiver<Result<(), WorkerError>>) {
        let (reply, reply_rx) = oneshot::channel();
        (
            ContainerWork::Deprovision {
                config: DeprovisionConfig {
                    sandbox_id: sandbox_id.to_string(),
                },
                reply,
            },
            reply_rx,
        )
    }

    /// Deleting the container would free the handle the run thread is using, so
    /// lifecycle work waits instead of being refused.
    #[test]
    fn lifecycle_work_parks_behind_an_exec_rather_than_being_refused() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let (start, mut start_reply) = start_work("wslc:busy");
        let (stop, mut stop_reply) = stop_work("wslc:busy");
        let (deprovision, mut deprovision_reply) = deprovision_work("wslc:busy");

        worker.dispatch(start, &tx);
        worker.dispatch(stop, &tx);
        worker.dispatch(deprovision, &tx);

        assert!(start_reply.try_recv().is_err());
        assert!(stop_reply.try_recv().is_err());
        assert!(deprovision_reply.try_recv().is_err());
        assert_eq!(worker.exec_in_flight["wslc:busy"].parked.len(), 3);
    }

    #[test]
    fn deprovision_parks_behind_an_exec_using_the_same_container() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let (work, mut reply) = deprovision_work("wslc:busy");

        worker.dispatch(work, &tx);

        assert!(
            reply.try_recv().is_err(),
            "a deprovision must not run while an exec holds the container"
        );
        assert!(
            worker.containers.contains_key("wslc:busy"),
            "the container handle must survive until the run reports back"
        );
        assert_eq!(worker.exec_in_flight["wslc:busy"].parked.len(), 1);
    }

    #[test]
    fn an_exec_does_not_park_work_for_another_container() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        worker
            .containers
            .insert("wslc:idle".to_string(), test_entry(false));
        let (work, mut reply) = deprovision_work("wslc:idle");

        worker.dispatch(work, &tx);

        assert!(
            reply.try_recv().expect("idle container answered").is_ok(),
            "a command for an idle container must not wait on another container's exec"
        );
        assert!(!worker.containers.contains_key("wslc:idle"));
    }

    #[test]
    fn finishing_an_exec_releases_the_work_parked_behind_it() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, mut done) = worker_with_exec_in_flight();
        let (work, mut reply) = deprovision_work("wslc:busy");
        worker.dispatch(work, &tx);

        worker.finish_exec(
            "wslc:busy",
            ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
            &tx,
        );

        assert_eq!(done.try_recv().unwrap().unwrap(), ExecTerminal::Exited(0));
        assert!(reply
            .try_recv()
            .expect("the parked deprovision must be answered")
            .is_ok());
        assert!(!worker.containers.contains_key("wslc:busy"));
    }

    /// A disconnected client leaves its run going, so the slot it claimed must
    /// travel to the worker and stay claimed until that run reports back.
    #[tokio::test]
    async fn an_exec_slot_outlives_the_client_that_admitted_it() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = SessionHandle {
            tx,
            active_execs: Arc::new(Mutex::new(HashMap::new())),
        };
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&limiter).try_acquire_owned().unwrap();

        let exec = tokio::spawn(async move {
            handle
                .exec(
                    ExecConfig {
                        exec_id: "slotted".to_string(),
                        run_token: "slotted-run".to_string(),
                        sandbox_id: "wslc:busy".to_string(),
                        script_code: "echo hi".to_string(),
                        working_directory: String::new(),
                        env: Vec::new(),
                        env_scope: EnvScope::Merge,
                        timeout_ms: 0,
                    },
                    Some(Arc::new(permit)),
                )
                .await
        });

        let Some(WorkerCommand::Container(ContainerWork::Exec(request))) = rx.recv().await else {
            panic!("the exec never reached the worker");
        };
        assert!(
            request.slot.is_some(),
            "the admitting client's exec slot must reach the worker"
        );

        // Stand in for the worker: claim the slot for the run, then drop the
        // client's end as a disconnect would.
        let (mut worker, _done) = worker_with_exec_in_flight();
        worker.exec_in_flight.get_mut("wslc:busy").unwrap().slot = request.slot;
        let _ = request.admit.send(Ok(()));
        exec.await.unwrap().unwrap();
        assert_eq!(
            limiter.available_permits(),
            0,
            "a client that disconnected mid-run must not free its exec slot"
        );

        let (worker_tx, _worker_rx) = mpsc::unbounded_channel();
        worker.finish_exec(
            "wslc:busy",
            ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
            &worker_tx,
        );

        assert_eq!(
            limiter.available_permits(),
            1,
            "the slot must be released once the run reports back"
        );
    }

    #[test]
    fn the_worker_claims_the_slot_when_it_starts_the_run() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut worker = worker_that_can_run();
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&limiter).try_acquire_owned().unwrap();
        let exec = exec_work_with_slot("wslc:ready", "claimed", Some(Arc::new(permit)));

        worker.dispatch(exec.work, &tx);

        assert_eq!(
            limiter.available_permits(),
            0,
            "the started run must hold the slot its request carried"
        );

        worker.finish_exec(
            "wslc:ready",
            ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
            &tx,
        );
        assert_eq!(
            limiter.available_permits(),
            1,
            "retiring the run must release the slot"
        );
    }

    #[test]
    fn parked_lifecycle_work_replays_in_the_order_it_arrived() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let (stop, mut stop_reply) = stop_work("wslc:busy");
        let (deprovision, mut deprovision_reply) = deprovision_work("wslc:busy");
        worker.dispatch(stop, &tx);
        worker.dispatch(deprovision, &tx);

        worker.finish_exec(
            "wslc:busy",
            ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
            &tx,
        );

        let stopped = stop_reply
            .try_recv()
            .expect("the parked stop must be answered");
        assert!(
            !matches!(stopped, Err(WorkerError::NotProvisioned(_))),
            "the stop must run while its container still exists, got {stopped:?}"
        );
        assert!(deprovision_reply
            .try_recv()
            .expect("the parked deprovision must be answered")
            .is_ok());
    }

    #[test]
    fn a_second_exec_on_the_same_container_is_refused_as_busy() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let mut second = exec_work("wslc:busy", "second");

        worker.dispatch(second.work, &tx);

        let err = second
            .admit
            .try_recv()
            .expect("a refused exec must be answered through admit")
            .unwrap_err();
        assert_eq!(err.kind(), ErrKind::Busy);
        assert!(
            worker.exec_in_flight["wslc:busy"].parked.is_empty(),
            "a refused exec must not also queue behind the first"
        );
    }

    #[test]
    fn execs_on_different_containers_are_both_admitted() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        worker
            .containers
            .insert("wslc:idle".to_string(), started_entry());
        let mut other = exec_work("wslc:idle", "other");

        worker.dispatch(other.work, &tx);

        assert!(
            other
                .admit
                .try_recv()
                .expect("idle container answered")
                .is_ok(),
            "a container of its own must not inherit another container's slot"
        );
    }

    /// The guarantee a cancellation must keep: observed before the run starts,
    /// it reports cancelled rather than creating the process.
    #[test]
    fn an_exec_cancelled_before_it_starts_never_runs() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:idle".to_string(), started_entry());
        let mut queued = exec_work("wslc:idle", "queued");
        queued.cancellation.store(true, Ordering::Release);

        worker.dispatch(queued.work, &tx);

        assert!(queued.admit.try_recv().unwrap().is_ok());
        assert_eq!(
            queued.done.try_recv().unwrap().unwrap(),
            ExecTerminal::Cancelled
        );
        assert!(
            !worker.exec_in_flight.contains_key("wslc:idle"),
            "a cancelled exec must not claim the container's slot"
        );
    }

    #[test]
    fn a_cancelled_exec_never_reaches_the_runner() {
        static STARTED: AtomicBool = AtomicBool::new(false);

        fn record_start(
            _: &Worker,
            _: ExecConfig,
            _: WslcContainer,
            _: OutputSink,
            _: Arc<AtomicBool>,
            _: &mpsc::UnboundedSender<WorkerCommand>,
        ) -> Result<(), WorkerError> {
            STARTED.store(true, Ordering::SeqCst);
            Ok(())
        }

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut worker = worker_that_can_run();
        worker.start_run = record_start;
        let mut queued = exec_work("wslc:ready", "cancelled-before-start");
        queued.cancellation.store(true, Ordering::Release);

        worker.dispatch(queued.work, &tx);

        assert!(
            !STARTED.load(Ordering::SeqCst),
            "a cancelled exec must not reach the runner that creates the process"
        );
        assert_eq!(
            queued.done.try_recv().unwrap().unwrap(),
            ExecTerminal::Cancelled
        );
    }

    #[test]
    fn an_unconfirmed_exec_keeps_its_slot_claimed() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&limiter).try_acquire_owned().unwrap();
        worker.exec_in_flight.get_mut("wslc:busy").unwrap().slot = Some(Arc::new(permit));

        worker.finish_exec(
            "wslc:busy",
            ExecReport::Unconfirmed("the exit callback never fired".to_string()),
            &tx,
        );

        assert_eq!(
            limiter.available_permits(),
            0,
            "a quarantined sandbox whose process may still be running must keep its slot"
        );
    }

    #[test]
    fn deprovisioning_a_quarantined_sandbox_frees_its_slot() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, _done) = worker_with_exec_in_flight();
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&limiter).try_acquire_owned().unwrap();
        worker.exec_in_flight.get_mut("wslc:busy").unwrap().slot = Some(Arc::new(permit));
        worker.finish_exec(
            "wslc:busy",
            ExecReport::Unconfirmed("the exit callback never fired".to_string()),
            &tx,
        );
        assert_eq!(
            limiter.available_permits(),
            0,
            "the quarantine holds a slot"
        );

        worker
            .deprovision(DeprovisionConfig {
                sandbox_id: "wslc:busy".to_string(),
            })
            .unwrap();

        assert_eq!(
            limiter.available_permits(),
            1,
            "deprovisioning the quarantined sandbox must return its slot"
        );
    }

    #[test]
    fn an_unconfirmed_exec_is_quarantined_on_the_worker() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut worker, mut done) = worker_with_exec_in_flight();

        worker.finish_exec(
            "wslc:busy",
            ExecReport::Unconfirmed("the exit callback never fired".to_string()),
            &tx,
        );

        let err = done.try_recv().unwrap().unwrap_err();
        assert!(err.to_string().contains("quarantined"), "got {err}");
        assert!(worker.containers["wslc:busy"].quarantined);
    }

    /// A report can outlive its slot: shutdown drains the run and clears the
    /// map before the posted command is serviced.
    #[test]
    fn a_report_for_a_container_with_no_exec_in_flight_is_a_no_op() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut worker = Worker::new();

        worker.finish_exec(
            "wslc:never-ran",
            ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
            &tx,
        );

        assert_eq!(worker.live_container_count(), 0);
    }

    /// A run that has not reported back is still holding its container handle,
    /// so a teardown that gives up waiting must abandon the handles rather than
    /// release them.
    #[test]
    fn a_timed_out_shutdown_answers_clients_without_releasing_live_handles() {
        static RELEASED: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn release(_: mxc_sdk::wslc_common::wslc_bindings::WslcContainer) -> i32 {
            RELEASED.store(true, Ordering::SeqCst);
            0
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:busy".to_string(), flagged_entry(release));
        let (in_flight, mut done) = in_flight_exec("running");
        worker
            .exec_in_flight
            .insert("wslc:busy".to_string(), in_flight);
        let (work, mut parked_reply) = stop_work("wslc:busy");
        worker.dispatch(work, &tx);

        // The run never reports, so the drain can only expire.
        let _counted = ExecCount::enter(&worker.execs_in_flight);

        worker.shutdown(&mut rx, Duration::from_millis(100));

        assert!(
            !RELEASED.load(Ordering::SeqCst),
            "a container handle the run thread still holds must not be released"
        );
        assert!(
            done.try_recv()
                .expect("the running exec must be answered")
                .is_err(),
            "the client gets a typed error rather than a dropped channel"
        );
        assert!(parked_reply
            .try_recv()
            .expect("parked work must be answered")
            .is_err());
    }

    /// A command that reaches the queue ahead of the exec report must not cost
    /// the exec its result, nor be swallowed on its way past.
    #[test]
    fn shutdown_answers_a_command_queued_ahead_of_the_exec_report() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut worker, mut done) = worker_with_exec_in_flight();

        let (queued, mut queued_reply) = stop_work("wslc:other");
        tx.send(WorkerCommand::Container(queued)).unwrap();
        tx.send(WorkerCommand::ExecFinished {
            sandbox_id: "wslc:busy".to_string(),
            report: ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
        })
        .unwrap();

        worker.shutdown(&mut rx, DRAIN_TIMEOUT);

        assert_eq!(
            done.try_recv()
                .expect("the finished exec must be answered")
                .unwrap(),
            ExecTerminal::Exited(0),
            "a command ahead of the report must not cost the exec its exit code"
        );
        assert!(
            queued_reply
                .try_recv()
                .expect("the queued command must be answered, not dropped")
                .is_err(),
            "a command consumed during teardown gets a typed error"
        );
    }

    /// A run that finished before teardown keeps its own exit code: the drain
    /// found its report already queued.
    #[test]
    fn shutdown_delivers_a_finished_execs_real_outcome() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut worker, mut done) = worker_with_exec_in_flight();
        let (work, mut reply) = stop_work("wslc:busy");
        worker.dispatch(work, &tx);
        tx.send(WorkerCommand::ExecFinished {
            sandbox_id: "wslc:busy".to_string(),
            report: ExecReport::Finished(Ok(ExecTerminal::Exited(0))),
        })
        .unwrap();

        worker.shutdown(&mut rx, DRAIN_TIMEOUT);

        assert_eq!(
            done.try_recv()
                .expect("the finished exec must be answered")
                .unwrap(),
            ExecTerminal::Exited(0),
            "a run that completed before teardown must keep its exit code"
        );
        assert!(
            reply
                .try_recv()
                .expect("the parked stop must be answered rather than dropped")
                .is_err(),
            "parked work is refused once the daemon is shutting down"
        );
    }

    /// The synthetic error is for a run whose report never arrived.
    #[test]
    fn shutdown_answers_an_exec_whose_report_never_arrived() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut worker, mut done) = worker_with_exec_in_flight();
        let (work, mut reply) = stop_work("wslc:busy");
        worker.dispatch(work, &tx);

        worker.shutdown(&mut rx, DRAIN_TIMEOUT);

        assert!(done
            .try_recv()
            .expect("the running exec must be answered")
            .is_err());
        assert!(reply
            .try_recv()
            .expect("the parked stop must be answered rather than dropped")
            .is_err());
    }

    /// A thread that unwinds never reaches its own release statement, so the
    /// count has to come off in `Drop` or teardown waits out the full budget.
    #[test]
    fn a_panicking_run_still_releases_its_in_flight_count() {
        let count = Arc::new(AtomicUsize::new(0));

        let panicked = std::panic::catch_unwind({
            let count = Arc::clone(&count);
            move || {
                let _counted = ExecCount::enter(&count);
                assert_eq!(count.load(Ordering::SeqCst), 1);
                panic!("the run exploded");
            }
        });

        assert!(panicked.is_err());
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "a panicking run must not leave itself counted forever"
        );
    }

    /// A client awaiting a reply learns the worker is gone from its channel
    /// closing, so an unwind must not take the reply channels with it.
    #[test]
    fn an_unwind_closes_the_reply_channels_it_abandons() {
        let (mut worker, mut done) = worker_with_exec_in_flight();
        let (work, mut parked_reply) = stop_work("wslc:busy");
        worker
            .exec_in_flight
            .get_mut("wslc:busy")
            .unwrap()
            .parked
            .push(work);
        let (reply, mut pending_reply) = oneshot::channel();
        worker.pending.insert(
            1,
            PendingProvision {
                config: ProvisionConfig {
                    image: "alpine:latest".to_string(),
                    image_tar_path: None,
                    volumes: Vec::new(),
                    network: Default::default(),
                    port_mappings: Vec::new(),
                    session_id: None,
                },
                reply,
                session_id: TEST_SESSION.to_string(),
                _retire_deadline: std::sync::mpsc::channel().0,
            },
        );

        worker.abandon_if_borrowed(1, 0, false);

        assert!(
            matches!(done.try_recv(), Err(oneshot::error::TryRecvError::Closed)),
            "the running exec's client must see its channel close"
        );
        assert!(
            matches!(
                parked_reply.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "parked work's client must see its channel close"
        );
        assert!(
            matches!(
                pending_reply.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "a parked provision's client must see its channel close"
        );
    }

    /// Releasing a container handle is an SDK call; a run thread still holding
    /// one must outlive the worker that owned it.
    #[test]
    fn an_unwind_with_a_run_still_counted_keeps_container_handles() {
        static RELEASED: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn release(_: mxc_sdk::wslc_common::wslc_bindings::WslcContainer) -> i32 {
            RELEASED.store(true, Ordering::SeqCst);
            0
        }

        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:busy".to_string(), flagged_entry(release));

        worker.abandon_if_borrowed(1, 0, false);

        assert!(
            !RELEASED.load(Ordering::SeqCst),
            "a handle the run thread is still using must not be released"
        );
    }

    #[test]
    fn an_unwind_with_a_pull_outstanding_keeps_container_handles() {
        static RELEASED: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn release(_: mxc_sdk::wslc_common::wslc_bindings::WslcContainer) -> i32 {
            RELEASED.store(true, Ordering::SeqCst);
            0
        }

        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:pulling".to_string(), flagged_entry(release));

        worker.abandon_if_borrowed(0, 0, true);

        assert!(
            !RELEASED.load(Ordering::SeqCst),
            "a pull still borrows the SDK and session, so the handles must be kept"
        );
    }

    #[test]
    fn an_unwind_with_no_run_counted_releases_container_handles() {
        static RELEASED: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn release(_: mxc_sdk::wslc_common::wslc_bindings::WslcContainer) -> i32 {
            RELEASED.store(true, Ordering::SeqCst);
            0
        }

        let mut worker = Worker::new();
        worker
            .containers
            .insert("wslc:idle".to_string(), flagged_entry(release));

        worker.abandon_if_borrowed(0, 0, false);

        assert!(
            RELEASED.load(Ordering::SeqCst),
            "with nothing in flight the handles must be released normally"
        );
    }

    /// Teardown asks whether *its own* handles are free, so one worker's run
    /// must not hold another's drain open.
    #[test]
    fn one_workers_run_does_not_count_against_anothers_drain() {
        let busy = Worker::new();
        let idle = Worker::new();

        let _counted = ExecCount::enter(&busy.execs_in_flight);

        assert_eq!(busy.execs_in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(
            idle.execs_in_flight.load(Ordering::SeqCst),
            0,
            "a run on one worker must not be counted against another's teardown"
        );
    }

    /// Teardown must not free a container handle a run thread is still using.
    #[test]
    fn a_counted_exec_keeps_the_drain_from_reporting_clear() {
        let in_flight = AtomicUsize::new(1);

        assert!(!wait_for_in_flight(
            &in_flight,
            Instant::now() + Duration::from_millis(100)
        ));

        in_flight.store(0, Ordering::SeqCst);
        assert!(wait_for_in_flight(
            &in_flight,
            Instant::now() + Duration::from_millis(100)
        ));
    }

    // ---- Multi-session behaviour on a live WSL2 host ----
    //
    // Each of these boots real utility VMs, so they are `#[ignore]`d and run
    // explicitly, one at a time:
    //
    //   cargo test -p mxc-sdk --features wslc --bin wxc-wslc-daemon \
    //       -- --ignored --nocapture --test-threads=1
    //
    // They lease from the real per-user slot pool, so warm it first with
    // `scripts\setup-wslc.ps1 -DaemonSlots 2`.

    /// The SDK has to accept the name derived from a session id. Two sessions
    /// under one name is an untested failure mode, so the names must be
    /// distinct *and* usable.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with the WSLc SDK installed"]
    async fn two_sessions_coexist_in_one_daemon() {
        let handle = spawn().unwrap();

        let first = handle
            .provision_session(ProvisionSessionConfig::default())
            .await
            .expect("first session");
        let second = handle
            .provision_session(ProvisionSessionConfig::default())
            .await
            .expect("second session must not collide with the first");

        assert_ne!(first, second);
        assert!(
            first.starts_with("wslcsess:"),
            "a session id must be recognisable as one: {first}"
        );

        handle
            .deprovision_session(DeprovisionSessionConfig {
                session_id: first.clone(),
            })
            .await
            .expect("release the first session");
        handle
            .deprovision_session(DeprovisionSessionConfig { session_id: second })
            .await
            .expect("releasing one session must leave the other usable");

        handle.shutdown().await.unwrap();
    }

    /// Host physical memory still available, in MB.
    ///
    /// Sampled around a session to answer whether `memoryMb` reserves memory or
    /// merely caps it — the two have completely different consequences for
    /// whether an oversized request is legitimate.
    #[cfg(windows)]
    fn available_memory_mb() -> u64 {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };

        // SAFETY: `status` is a valid `MEMORYSTATUSEX` with `dwLength` set.
        unsafe { GlobalMemoryStatusEx(&mut status) }.expect("read memory status");
        status.ullAvailPhys / (1024 * 1024)
    }

    /// Measurement, not an assertion: are `memoryMb` and `cpuCount` caps or
    /// reservations, and what does each do when asked for more than the host
    /// has?
    ///
    /// The two parameters fail differently, so asking for both at once cannot
    /// say which one was refused.
    #[tokio::test]
    #[ignore = "measurement: boots sessions sized past host capacity"]
    async fn measure_whether_session_sizing_reserves_or_caps() {
        let host = host_specs();
        println!(
            "host: {} MB installed, {} logical cpus, {} MB available\n",
            host.total_memory_mb,
            host.logical_cpus,
            available_memory_mb()
        );

        let cases: Vec<(&str, Option<u32>, Option<u64>)> = vec![
            ("baseline (host defaults)", None, None),
            ("memory = 1x installed", None, Some(host.total_memory_mb)),
            (
                "memory = 2x installed",
                None,
                Some(host.total_memory_mb * 2),
            ),
            ("cpus = 1x logical", Some(host.logical_cpus), None),
            ("cpus = 2x logical", Some(host.logical_cpus * 2), None),
            ("cpus = 4x logical", Some(host.logical_cpus * 4), None),
        ];

        let handle = spawn().unwrap();
        for (label, cpu_count, memory_mb) in cases {
            let before = available_memory_mb();
            let started = Instant::now();
            let outcome = handle
                .provision_session(ProvisionSessionConfig {
                    cpu_count,
                    memory_mb,
                    gpu: false,
                })
                .await;
            let elapsed = started.elapsed();

            match outcome {
                Err(e) => println!("{label}: REFUSED in {elapsed:.1?} -- {e}\n"),
                Ok(session_id) => {
                    let delta = before as i64 - available_memory_mb() as i64;
                    let guest = guest_resources(&handle, &session_id).await;
                    println!(
                        "{label}: BOOTED in {elapsed:.1?}, host delta {delta} MB, \
                         guest sees {guest}\n"
                    );
                    handle
                        .deprovision_session(DeprovisionSessionConfig { session_id })
                        .await
                        .expect("release");
                }
            }
        }
        handle.shutdown().await.unwrap();
    }

    /// Boot a throwaway sandbox in `session_id` and report what the guest
    /// believes its cpu count and memory are.
    async fn guest_resources(handle: &SessionHandle, session_id: &str) -> String {
        let sandbox_id = match handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
                session_id: Some(session_id.to_string()),
            })
            .await
        {
            Ok(sandbox_id) => sandbox_id,
            Err(e) => return format!("(could not provision to ask: {e})"),
        };
        if let Err(e) = handle
            .start(StartConfig {
                sandbox_id: sandbox_id.clone(),
            })
            .await
        {
            return format!("(could not start to ask: {e})");
        }

        let mut stream = handle
            .exec(
                ExecConfig {
                    exec_id: format!("probe-{sandbox_id}"),
                    run_token: "probe-run".to_string(),
                    sandbox_id: sandbox_id.clone(),
                    script_code: "echo cpus=$(nproc) mem=$(free -m | awk '/Mem:/{print $2}')MB"
                        .to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 30_000,
                },
                None,
            )
            .await
            .expect("exec");

        let mut text = String::new();
        while let Some((_, bytes)) = stream.output.recv().await {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
        let _ = stream.done.await;
        handle
            .deprovision(DeprovisionConfig { sandbox_id })
            .await
            .ok();
        text.trim().to_string()
    }

    /// The host's installed memory and processor count.
    #[cfg(windows)]
    fn host_specs() -> container_steps::HostCapacity {
        use windows::Win32::System::SystemInformation::{
            GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
        };

        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };

        // SAFETY: `status` is a valid `MEMORYSTATUSEX` with `dwLength` set.
        unsafe { GlobalMemoryStatusEx(&mut status) }.expect("read memory status");
        let mut info = SYSTEM_INFO::default();

        // SAFETY: `info` is a valid, writable `SYSTEM_INFO`.
        unsafe { GetSystemInfo(&mut info) };

        container_steps::HostCapacity {
            total_memory_mb: status.ullTotalPhys / (1024 * 1024),
            logical_cpus: info.dwNumberOfProcessors,
        }
    }

    /// `memoryMb` is a ceiling the host backs on demand, so a session may ask
    /// for more memory than the host has installed and the guest really gets
    /// it.
    ///
    /// This is what makes refusing an oversized `memoryMb` the wrong thing to
    /// do, so it is worth defending rather than leaving in a measurement's
    /// output.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest cached in the daemon store slots"]
    async fn memory_past_what_the_host_has_installed_boots_and_the_guest_gets_it() {
        let host = host_specs();
        let requested_mb = host.total_memory_mb * 2;
        let handle = spawn().unwrap();

        let session_id = handle
            .provision_session(ProvisionSessionConfig {
                cpu_count: None,
                memory_mb: Some(requested_mb),
                gpu: false,
            })
            .await
            .expect("a ceiling past installed memory must be accepted");

        let guest = guest_resources(&handle, &session_id).await;
        println!(
            "requested {requested_mb} MB on a {} MB host; {guest}",
            host.total_memory_mb
        );

        let guest_mb: u64 = guest
            .split("mem=")
            .nth(1)
            .and_then(|rest| rest.trim_end_matches("MB").trim().parse().ok())
            .unwrap_or_else(|| panic!("could not read the guest's memory from {guest:?}"));

        assert!(
            guest_mb > host.total_memory_mb,
            "the guest reported {guest_mb} MB against a host with {} MB installed; \
             if this ever fails, memoryMb stopped being a ceiling and the \
             validator must start refusing oversized requests",
            host.total_memory_mb
        );

        handle
            .deprovision_session(DeprovisionSessionConfig { session_id })
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }

    /// The SDK refuses an impossible processor count on its own, but names the
    /// image store while doing it. This holds the ground that the refusal says
    /// what actually went wrong.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with the WSLc SDK installed"]
    async fn too_many_processors_is_refused_naming_processors() {
        let host = host_specs();
        let handle = spawn().unwrap();

        let refusal = handle
            .provision_session(ProvisionSessionConfig {
                cpu_count: Some(host.logical_cpus * 2),
                memory_mb: None,
                gpu: false,
            })
            .await
            .expect_err("more processors than the host has must be refused");

        println!("refused as {:?}: {refusal}", refusal.kind());
        assert_eq!(refusal.kind(), ErrKind::Rejected);
        let message = refusal.to_string();
        assert!(
            message.contains("cpu_count") && message.contains("logical processors"),
            "the refusal must name the processor count: {message}"
        );
        assert!(
            !message.contains("image store"),
            "blaming the image store for a processor problem is what this \
             replaces: {message}"
        );

        handle.shutdown().await.unwrap();
    }

    /// Nothing in mxc bounds a session's size, so the host's own refusal is the
    /// only limit.
    ///
    /// `WslcCreateSession` accepts the request and the refusal arrives at the
    /// store probe that follows, which is why this takes minutes rather than
    /// seconds.
    #[tokio::test]
    #[ignore = "requires a WSL2 host; takes ~15 minutes to fail"]
    async fn a_session_larger_than_the_host_is_refused() {
        let handle = spawn().unwrap();

        let started = Instant::now();
        let outcome = handle
            .provision_session(ProvisionSessionConfig {
                cpu_count: None,

                // Far past any real host, and past what the SDK takes as MB.
                memory_mb: Some(64 * 1024 * 1024),
                gpu: false,
            })
            .await;
        let elapsed = started.elapsed();

        let refusal = match outcome {
            Err(refusal) => refusal,
            Ok(session_id) => {
                handle
                    .deprovision_session(DeprovisionSessionConfig { session_id })
                    .await
                    .ok();
                handle.shutdown().await.unwrap();
                panic!(
                    "a host that cannot supply the memory must refuse; silently \
                     clamping would mean sizing is not enforced and the host is \
                     not the backstop the no-limit design assumes"
                );
            }
        };

        println!(
            "refused after {elapsed:?} as {:?}: {refusal}",
            refusal.kind()
        );
        assert_eq!(
            refusal.kind(),
            ErrKind::Backend,
            "the host's own diagnosis is what the caller has to act on"
        );

        handle.shutdown().await.unwrap();
    }

    /// Sizing is applied at create, so a session asking for more than the host
    /// has must fail as a session failure rather than at some later phase.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with the WSLc SDK installed"]
    async fn a_sized_session_boots() {
        let handle = spawn().unwrap();

        let session_id = handle
            .provision_session(ProvisionSessionConfig {
                cpu_count: Some(2),
                memory_mb: Some(2048),
                gpu: false,
            })
            .await
            .expect("a modestly sized session must boot");

        handle
            .deprovision_session(DeprovisionSessionConfig { session_id })
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }

    /// A container provisioned into a named session must live in that session,
    /// not in the implicit one.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest cached in the daemon store slots"]
    async fn a_sandbox_can_be_placed_in_a_named_session() {
        let handle = spawn().unwrap();
        let session_id = handle
            .provision_session(ProvisionSessionConfig::default())
            .await
            .expect("session");

        let sandbox_id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
                session_id: Some(session_id.clone()),
            })
            .await
            .expect("provision into the named session");

        let refusal = handle
            .deprovision_session(DeprovisionSessionConfig {
                session_id: session_id.clone(),
            })
            .await
            .expect_err("a session holding a sandbox must not be released");
        assert_eq!(refusal.kind(), ErrKind::Rejected);

        handle
            .deprovision(DeprovisionConfig {
                sandbox_id: sandbox_id.clone(),
            })
            .await
            .unwrap();
        handle
            .deprovision_session(DeprovisionSessionConfig { session_id })
            .await
            .expect("an emptied session releases");

        handle.shutdown().await.unwrap();
    }

    /// Provision and start a sandbox on the live host, returning its id.
    async fn provisioned_and_started(handle: &SessionHandle) -> String {
        let id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
                session_id: None,
            })
            .await
            .unwrap();
        handle
            .start(StartConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();
        id
    }

    async fn stop_and_deprovision(handle: &SessionHandle, sandbox_id: String) {
        handle
            .stop(StopConfig {
                sandbox_id: sandbox_id.clone(),
            })
            .await
            .unwrap();
        handle
            .deprovision(DeprovisionConfig { sandbox_id })
            .await
            .unwrap();
    }

    fn sleep_exec(exec_id: &str, sandbox_id: &str, seconds: u32) -> ExecConfig {
        ExecConfig {
            exec_id: exec_id.to_string(),
            run_token: format!("{exec_id}-run"),
            sandbox_id: sandbox_id.to_string(),
            script_code: format!("sleep {seconds}"),
            working_directory: String::new(),
            env: Vec::new(),
            env_scope: EnvScope::Merge,
            timeout_ms: 30_000,
        }
    }

    /// A run that prints an epoch second either side of its sleep.
    fn stamped_sleep_exec(exec_id: &str, sandbox_id: &str, seconds: u32) -> ExecConfig {
        ExecConfig {
            script_code: format!("date +%s; sleep {seconds}; date +%s"),
            ..sleep_exec(exec_id, sandbox_id, seconds)
        }
    }

    /// Drain a stamped run's output and return the epoch seconds it reported
    /// either side of its sleep.
    async fn stamped_interval(exec: &mut ExecStream) -> (i64, i64) {
        let mut stdout = Vec::new();
        while let Some((stream, data)) = exec.output.recv().await {
            if stream == OutStream::Stdout {
                stdout.extend_from_slice(&data);
            }
        }
        let text = String::from_utf8_lossy(&stdout);
        let stamps: Vec<i64> = text
            .lines()
            .filter_map(|line| line.trim().parse::<i64>().ok())
            .collect();
        assert!(
            stamps.len() >= 2,
            "a stamped run must report a start and an end, got {text:?}"
        );
        (stamps[0], stamps[stamps.len() - 1])
    }

    // Exercises the real SDK path end to end: provision (boot VM + create
    // container) → start → exec → stop → deprovision → refcount back to 0. It
    // provisions with the default isolated posture, which refuses a registry
    // pull, so `alpine:latest` has to be cached in the store slot this worker
    // leases — slot 0 of the pool, since it holds one session. Warm it with
    // `scripts\setup-wslc.ps1 -DaemonSlots 1`. It is `#[ignore]`d and run
    // explicitly with `cargo test -p mxc-sdk --features wslc --lib -- --ignored`.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest cached in daemon store slot 0"]
    async fn full_lifecycle_on_wsl_host() {
        let handle = spawn().unwrap();
        assert_eq!(count(&handle).await, 0);

        let id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
                session_id: None,
            })
            .await
            .unwrap();
        assert_eq!(count(&handle).await, 1);

        handle
            .start(StartConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        let mut exec = handle
            .exec(
                ExecConfig {
                    exec_id: "full-lifecycle".to_string(),
                    run_token: "full-lifecycle-run".to_string(),
                    sandbox_id: id.clone(),
                    script_code: "echo hi".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 30_000,
                },
                None,
            )
            .await
            .unwrap();
        // Drain the live output stream, then await the exit code.
        let mut stdout = Vec::new();
        while let Some((kind, data)) = exec.output.recv().await {
            if kind == OutStream::Stdout {
                stdout.extend_from_slice(&data);
            }
        }
        let code = exec.done.await.unwrap().unwrap();
        assert_eq!(code, ExecTerminal::Exited(0));
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hi");

        handle
            .stop(StopConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        handle
            .deprovision(DeprovisionConfig { sandbox_id: id })
            .await
            .unwrap();
        assert_eq!(count(&handle).await, 0);

        handle.shutdown().await.unwrap();
    }

    /// The guarantee a cancellation must keep against the live SDK: observed
    /// before the worker reaches the run, it creates no process.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
    async fn cancelled_queued_exec_never_starts_process() {
        let handle = spawn().unwrap();
        let id = provisioned_and_started(&handle).await;

        // Occupy the worker with a container creation, so the exec below is
        // still queued when the cancellation lands. Spawned tasks are polled in
        // order, so this provision reaches the worker first.
        let blocker_handle = handle.clone();
        let blocker = tokio::spawn(async move {
            blocker_handle
                .provision(ProvisionConfig {
                    image: "alpine:latest".to_string(),
                    image_tar_path: None,
                    volumes: Vec::new(),
                    network: Default::default(),
                    port_mappings: Vec::new(),
                    session_id: None,
                })
                .await
        });

        let queued_handle = handle.clone();
        let queued_id = id.clone();
        let queued = tokio::spawn(async move {
            queued_handle
                .exec(
                    ExecConfig {
                        exec_id: "cancelled-queued".to_string(),
                        run_token: "cancelled-queued-run".to_string(),
                        sandbox_id: queued_id,
                        script_code: "touch /tmp/mxc-cancelled-queued-marker".to_string(),
                        working_directory: String::new(),
                        env: Vec::new(),
                        env_scope: EnvScope::Merge,
                        timeout_ms: 30_000,
                    },
                    None,
                )
                .await
        });

        for _ in 0..100 {
            if handle
                .active_execs
                .lock()
                .unwrap()
                .contains_key("cancelled-queued")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            handle
                .active_execs
                .lock()
                .unwrap()
                .contains_key("cancelled-queued"),
            "queued exec was not registered"
        );
        handle.cancel_exec("cancelled-queued", "cancelled-queued-run");

        let blocker_id = blocker.await.unwrap().unwrap();
        let queued = queued.await.unwrap().unwrap();
        assert_eq!(queued.done.await.unwrap().unwrap(), ExecTerminal::Cancelled);

        let marker_check = handle
            .exec(
                ExecConfig {
                    exec_id: "marker-check".to_string(),
                    run_token: "marker-check-run".to_string(),
                    sandbox_id: id.clone(),
                    script_code: "test ! -e /tmp/mxc-cancelled-queued-marker".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 30_000,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            marker_check.done.await.unwrap().unwrap(),
            ExecTerminal::Exited(0)
        );

        stop_and_deprovision(&handle, id).await;
        handle
            .deprovision(DeprovisionConfig {
                sandbox_id: blocker_id,
            })
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }

    /// A second exec on a container that already has one is refused before any
    /// admission reaches the client.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
    async fn a_second_exec_on_a_busy_container_is_refused() {
        let handle = spawn().unwrap();
        let id = provisioned_and_started(&handle).await;

        let first = handle
            .exec(sleep_exec("busy-first", &id, 3), None)
            .await
            .unwrap();

        let refused = handle
            .exec(
                ExecConfig {
                    exec_id: "busy-second".to_string(),
                    run_token: "busy-second-run".to_string(),
                    sandbox_id: id.clone(),
                    script_code: "echo hi".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 30_000,
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), ErrKind::Busy);

        assert_eq!(first.done.await.unwrap().unwrap(), ExecTerminal::Exited(0));

        stop_and_deprovision(&handle, id).await;
        handle.shutdown().await.unwrap();
    }

    /// Two sandboxes must run at the same time rather than one after the other.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
    async fn execs_on_two_sandboxes_overlap() {
        let handle = spawn().unwrap();
        let first_id = provisioned_and_started(&handle).await;
        let second_id = provisioned_and_started(&handle).await;

        let mut first = handle
            .exec(stamped_sleep_exec("overlap-first", &first_id, 6), None)
            .await
            .unwrap();
        let mut second = handle
            .exec(stamped_sleep_exec("overlap-second", &second_id, 6), None)
            .await
            .unwrap();

        // Both sandboxes share one utility VM, so their clocks agree.
        let (first_start, first_end) = stamped_interval(&mut first).await;
        let (second_start, second_end) = stamped_interval(&mut second).await;
        assert_eq!(first.done.await.unwrap().unwrap(), ExecTerminal::Exited(0));
        assert_eq!(second.done.await.unwrap().unwrap(), ExecTerminal::Exited(0));

        let overlap = first_end.min(second_end) - first_start.max(second_start);
        assert!(
            overlap >= 2,
            "the two 6s runs overlapped by {overlap}s, so they were serialized: \
             first {first_start}..{first_end}, second {second_start}..{second_end}"
        );

        stop_and_deprovision(&handle, first_id).await;
        stop_and_deprovision(&handle, second_id).await;
        handle.shutdown().await.unwrap();
    }

    /// A deprovision that reaches the worker mid-run would delete the container
    /// and free the handle the run thread is using.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
    async fn deprovision_during_an_exec_waits_for_the_run() {
        let handle = spawn().unwrap();
        let id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
                session_id: None,
            })
            .await
            .unwrap();
        handle
            .start(StartConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        let mut exec = handle
            .exec(
                ExecConfig {
                    exec_id: "deprovision-overlap".to_string(),
                    run_token: "deprovision-overlap-run".to_string(),
                    sandbox_id: id.clone(),
                    script_code: "sleep 5; echo survived".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    env_scope: EnvScope::Merge,
                    timeout_ms: 30_000,
                },
                None,
            )
            .await
            .unwrap();

        // Admission has returned, so the run thread already holds the handle.
        let deprovision = tokio::spawn({
            let handle = handle.clone();
            let sandbox_id = id.clone();
            async move { handle.deprovision(DeprovisionConfig { sandbox_id }).await }
        });

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !deprovision.is_finished(),
            "deprovision must wait for the run rather than delete the container under it"
        );

        let mut stdout = Vec::new();
        while let Some((kind, data)) = exec.output.recv().await {
            if kind == OutStream::Stdout {
                stdout.extend_from_slice(&data);
            }
        }
        assert_eq!(exec.done.await.unwrap().unwrap(), ExecTerminal::Exited(0));
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "survived");

        deprovision.await.unwrap().unwrap();
        assert_eq!(count(&handle).await, 0);

        handle.shutdown().await.unwrap();
    }
}
