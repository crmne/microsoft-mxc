# Landlock Backend

> **Audience:** MXC consumers and developers

The Landlock backend provides **unprivileged Linux sandboxing without
namespaces**. The workload runs as a direct child of MXC that confines itself
with the [Landlock](https://docs.kernel.org/userspace-api/landlock.html) LSM and
a seccomp filter before it executes the command.

> **Status:** Development contract only (`1.1.0-alpha`). Selected explicitly as
> `"containment": "landlock"`, and used for `"containment": "process"` on Linux
> when Bubblewrap cannot run.

## Why it exists

Bubblewrap needs unprivileged user namespaces, and many hosts take them away:

- Ubuntu 23.10 and later restrict them with AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns=1`).
- `user.max_user_namespaces=0`, or Debian's `kernel.unprivileged_userns_clone=0`.
- Container runtimes whose seccomp profile refuses `unshare` and `clone` with
  `CLONE_NEWUSER`, which is Docker's default.

On those hosts every Bubblewrap run fails. Landlock needs no namespaces, no
privileges, and no helper binaries, only a kernel with Landlock enabled.

## Selection and fallback

| Request | Bubblewrap usable | Bubblewrap unusable |
|---------|-------------------|---------------------|
| `"process"` (or no `containment`) | Bubblewrap | Landlock, with a warning naming why |
| `"bubblewrap"` | Bubblewrap | Error naming the namespace failure |
| `"landlock"` | Landlock | Landlock |

A backend the caller named is never substituted. The fallback runs the same
policy or refuses it: it never runs a weaker policy than the request asked for.

"Bubblewrap usable" means more than `bwrap --version`: the platform probe also
starts one sandbox with the namespaces and mounts every run uses
(`--unshare-user`, `-pid`, `-ipc`, `-uts`, `-net`, `--proc`, `--dev`). A host
that refuses them reports Bubblewrap unavailable in `platform_support()` and
`available_backends()`, and a request naming Bubblewrap fails validation with
the reason, instead of reporting `bwrap`'s exit status 1 as the workload's.

`platform_support()` lists `"landlock"` among `available_methods` when the
kernel's ABI is supported, and `available_backends()` reports it with a warning
for each thing its ABI cannot confine (see [Kernel requirements](#kernel-requirements)).

## Kernel requirements

The backend asks the kernel for its Landlock ABI on every run and refuses to run
below ABI 3.

| ABI | Linux | What the backend does with it |
|-----|-------|-------------------------------|
| 1-2 | 5.13, 5.19 | Refused: these ABIs do not restrict truncation, so a workload could empty files it may only read |
| 3 | 6.2 | Filesystem read, write, execute, and truncate |
| 4 | 6.7 | Also refuses every TCP `bind` and `connect` when the network is denied (the seccomp filter already refuses the sockets) |
| 5 | 6.10 | Also restricts device `ioctl`s to `/dev/null`, `/dev/full`, and `/dev/tty` |
| 6 | 6.12 | Also keeps the workload from signalling processes outside the sandbox and from reaching abstract Unix sockets |
| 9 | 7.1 | Also confines pathname Unix sockets to granted paths, so `AF_UNIX` sockets are allowed |

Below ABI 6 a workload can send signals to the user's other processes, which
Bubblewrap's PID namespace would prevent: each run reports this as a warning.
Below ABI 9 `socket(AF_UNIX)` and datagram `socketpair` are refused, since
Landlock could not keep the workload away from sockets such as the user's D-Bus
session bus or a container daemon; stream `socketpair` still works. A kernel
newer than ABI 9 enforces everything ABI 9 does; the rights it adds are not
requested.

The backend supports x86_64 and aarch64, the architectures it has a seccomp
filter for.

## How it works

Everything that can fail for a reason the caller should hear happens before
the fork: resolving the policy paths, creating the Landlock ruleset, compiling
the seccomp filter. Between `fork` and `exec` the child only makes three system
calls: `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self`, and
`prctl(PR_SET_SECCOMP)`. If any fails, the spawn fails.

The workload runs `/bin/sh -c <commandLine>`, in a session of its own (pipes
and PTY modes), with the same default environment as Bubblewrap (`PATH`,
`TERM`, and `HOME` naming the start directory).

### Filesystem

Landlock allows access to whole file hierarchies and has no rule that takes
access away, so the policy maps onto it as follows:

| Policy | Landlock rights |
|--------|-----------------|
| `readonlyPaths` | read, list, execute |
| `readwritePaths` | read, list, execute, write, truncate, create, remove, rename, connect to Unix sockets (ABI 9) |
| Baseline (Bubblewrap's `/usr/bin`, `/usr/lib`, `/etc`, `/run/systemd/resolve`, ...) | read, list, execute |
| `/dev/null`, `/dev/full`, `/dev/tty` | read, write, truncate, `ioctl` |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | read |
| `/proc` | read, list |
| Private temporary directory | read, list, execute, write |

Paths are compared after resolving symlinks, since Landlock rules apply to the
file a path reaches. A policy path that does not exist is refused, because
Landlock grants only existing files.

What Landlock cannot express is refused before anything runs
(`policy_validation`):

- A `deniedPaths` entry inside a `readonlyPaths` or `readwritePaths` entry.
  The grant covers its whole tree, so the denied path would be granted too.
- A `readonlyPaths` entry inside a `readwritePaths` entry, which would be
  writable.

A `deniedPaths` entry inside a baseline path is honoured: the baseline grant is
replaced with grants on the entries beside the denied one (symlinks get no
grant of their own). Denying a whole baseline path drops it.

Bubblewrap gives each run a private `/tmp`. Landlock cannot remap paths, so a
run that sets no `TMPDIR` gets a private directory under the host's temporary
directory, `TMPDIR` pointing at it, and the directory is removed when the run
ends. The host's `/tmp` itself is not reachable unless the policy grants it.

`/proc` is the host's, not a fresh one: the workload can list the user's other
processes and read their command lines, but Landlock's ptrace restrictions keep
it from their memory and environment.

### Network

The workload runs in the host's network namespace. The seccomp filter decides
which socket families may exist and Landlock restricts TCP by port, so neither
can tell one address from another. The backend has two postures:

| Policy | Posture |
|--------|---------|
| No `network`, or `egress.default: "deny"` with no rules | **Isolated**: `socket()` for `AF_INET`, `AF_INET6`, `AF_NETLINK`, and every other network family fails with `EACCES`; on ABI 4 and newer Landlock also refuses every TCP `bind` and `connect` |
| `egress.default: "allow"` with `ingress.default: "allow"` and `ingress.hostLoopback: "allow"` | **Host network**: `AF_INET`, `AF_INET6`, and `AF_NETLINK` are allowed, unrestricted |

Everything else is refused rather than widened:

- `egress.default: "allow"` while inbound connections or the host loopback are
  denied (the defaults). The host's network namespace includes its loopback, so
  outbound access would also reach every local service.
- `network.egress` allow and deny rules, and `runtimeConfig.networkProxy`.
  Landlock would have to open a port on every address to reach one.
- Inbound access while outbound access is denied.

The isolated posture is stricter than Bubblewrap's: the sandbox has no loopback
of its own, so a workload cannot listen on `127.0.0.1` even for itself.

### What the seccomp filter refuses

| System calls | Error | Why |
|--------------|-------|-----|
| `socket` for families the posture does not allow, and `AF_UNIX` below ABI 9 | `EACCES` | See [Network](#network) and [Kernel requirements](#kernel-requirements) |
| `socketpair(AF_UNIX, SOCK_DGRAM)` below ABI 9 | `EACCES` | `sendto` on it can name any pathname socket |
| `io_uring_setup` | `ENOSYS` | Its socket operations bypass the `socket` check; callers fall back |
| System V IPC (`shmget`, `msgget`, `semget`, and their operations), `mq_open` | `EPERM` | Private under Bubblewrap's `--unshare-ipc` |
| `keyctl`, `add_key`, `request_key` | `EPERM` | The caller's session keyring |
| `ioctl(TIOCSTI)`, `ioctl(TIOCLINUX)` | `EPERM` | Pushing input into a terminal shared with the caller |
| Any 32-bit or x32 system call | `ENOSYS` | Their numbers and socket multiplexer are not checked |
| Metadata changes by path: `chmod`, `fchmodat`, `fchmodat2`, `chown`, `lchown`, `fchownat`, `utime`, `utimes`, `futimesat`, `utimensat` with a path, `setxattr`, `lsetxattr`, `setxattrat`, `removexattr`, `lremovexattr`, `removexattrat` | `EPERM` | Landlock does not govern metadata, so a workload could otherwise change the mode, owner, timestamps, or extended attributes of any file the user owns, even one outside every grant. A read-only bind mount refuses them under Bubblewrap |

The descriptor-based calls (`fchmod`, `fchown`, `futimens`, which is
`utimensat` without a path, `fsetxattr`, `fremovexattr`) stay allowed. They
need a descriptor of a file the workload could open, which Landlock already
decided; the kernel refuses them on `O_PATH` descriptors, which Landlock does
not check.

### Resource limits

`resources` works as on Bubblewrap: `cpuTimeMs` (`RLIMIT_CPU`), `memoryMb`
(`RLIMIT_DATA`), and `priority` (a nice value) are set on the workload before
`exec`, and `resourceUsage` is reported. `maxProcesses` is rejected for the same
reason. The workload is MXC's direct child, so no `--as-pid-1` is needed for its
usage to reach MXC.

### Lifecycle

A timeout or `kill()` kills the workload's process group. When the workload
exits on its own, MXC kills what it left running in its group before reaping
it, as Bubblewrap's PID namespace would. A process that leaves the group with
`setsid` is out of reach, as on Seatbelt. In inherit mode the workload shares
the caller's process group, so only the workload's own process is killed.

If the process that started the workload dies, the workload is not killed:
`PR_SET_PDEATHSIG` fires when the starting *thread* exits, and an SDK caller
may spawn from a thread that ends before the workload does.

## Testing

```bash
cd src
cargo test -p mxc-sdk --lib -- landlock host_fallback
cargo test -p mxc-sdk --test streaming_landlock
```

Set `MXC_LANDLOCK_TESTS_REQUIRE_EXECUTION=1` to fail instead of skipping when
Landlock is unavailable.

To test the fallback on a host that allows user namespaces, run the tests in a
user namespace that cannot create another. This changes nothing on the host:

```bash
uid=$(id -u) gid=$(id -g)
unshare -Ur sh -c "echo 1 > /proc/sys/user/max_user_namespaces &&
  exec unshare -U --map-user=$uid --map-group=$gid \
  cargo test -p mxc-sdk --test streaming_landlock --test streaming_bubblewrap"
```

The outer namespace may create one namespace, the inner one, so nothing inside
the inner one can create another.

Inside it `bwrap` fails with `ENOSPC`, the Bubblewrap suite skips with the
namespace reason, and the Landlock suite also checks that `"process"` falls back
and that `"bubblewrap"` fails as a sandbox error.

## Limitations

- Development contract only; the typed V1 Rust request, the Node SDK, and the
  .NET SDK cannot select it by name yet. `"process"` reaches it through any of
  them.
- No address-aware networking: no egress rules, no proxy-only egress, and no
  outbound access without the host loopback.
- No carve-outs inside policy grants.
- No metadata changes by path, even in read-write paths: `chmod +x file`,
  `touch existing-file`, `chown`, and `setfattr` fail with `EPERM`. Set the
  mode when creating a file (`open` with a mode, as compilers and `install`
  do), or change it through an open descriptor (`fchmod`, `futimens`).
  `touch` on a file the workload can open for writing works, since it changes
  the times through the descriptor; `touch` of a new file works too.
- The workload sees the host's `/proc` and, below ABI 6, can signal the user's
  other processes.
