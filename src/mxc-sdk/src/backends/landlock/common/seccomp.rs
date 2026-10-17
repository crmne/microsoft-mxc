// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The seccomp filter that covers what Landlock does not.
//!
//! Bubblewrap's namespaces isolate more than files: the network, System V and
//! POSIX IPC, abstract Unix sockets. Landlock runs the workload in the host's
//! namespaces, so the backend refuses at the system-call level what those
//! namespaces would have hidden and Landlock cannot restrict:
//!
//! - `socket(2)` for every family the network posture does not allow. In the
//!   isolated posture that is everything but `AF_UNIX`; Landlock's TCP rights
//!   (ABI 4) do not cover UDP, raw, or other sockets.
//! - `AF_UNIX` sockets, unless Landlock restricts pathname sockets (ABI 9).
//!   Without it a workload could reach any socket on the host, such as the
//!   user's D-Bus session bus or a container daemon. `socketpair(2)` stays
//!   available, except for datagram pairs, whose `sendto(2)` can name any
//!   pathname socket.
//! - `io_uring_setup(2)`, whose socket operations bypass the `socket(2)` check.
//! - System V IPC, POSIX message queues, and keyrings, which `bwrap` keeps
//!   private with `--unshare-ipc` and a new user namespace.
//! - The `TIOCSTI` and `TIOCLINUX` ioctls, which push input into a terminal the
//!   workload shares with its caller.
//! - System calls of another ABI (32-bit `int 0x80` or x32 on x86_64), whose
//!   numbers and socket multiplexer the filter does not check.
//!
//! The filter is classic BPF built here and installed between `fork` and
//! `exec`, after `no_new_privs`.

/// Whether the backend has a filter for this target.
pub const ARCH_SUPPORTED: bool = cfg!(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
));

/// Which sockets the workload may create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPolicy {
    /// `AF_INET`, `AF_INET6`, and `AF_NETLINK`: the host network, whole.
    pub host_network: bool,
    /// `AF_UNIX` sockets, because Landlock confines them to granted paths.
    pub unix_sockets: bool,
}

#[cfg(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod filter {
    use super::SocketPolicy;

    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    /// x32 system calls share the x86_64 audit arch and set this bit.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    // `struct seccomp_data`: nr, arch, instruction_pointer, args[6]. The
    // filter compares the low 32 bits of an argument, which is all the kernel
    // reads of an `int` (socket family, type) or `unsigned int` (ioctl
    // request) argument.
    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;
    const fn offset_arg_low(index: u32) -> u32 {
        16 + 8 * index
    }

    const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const BPF_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    #[cfg(target_arch = "x86_64")]
    const BPF_JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const BPF_AND_K: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
    const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

    const SOCK_TYPE_MASK: u32 = 0xf;

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn load(offset: u32) -> libc::sock_filter {
        insn(BPF_LD_W_ABS, 0, 0, offset)
    }

    fn allow() -> libc::sock_filter {
        insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)
    }

    fn fail(errno: i32) -> libc::sock_filter {
        insn(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | (errno as u32 & 0xffff))
    }

    fn verdict(allowed: bool) -> libc::sock_filter {
        if allowed {
            allow()
        } else {
            fail(libc::EACCES)
        }
    }

    /// `if A == value { block }`, where `block` always returns, so the
    /// accumulator is unchanged when the test fails.
    fn when(value: u32, block: Vec<libc::sock_filter>) -> Vec<libc::sock_filter> {
        let skip = u8::try_from(block.len()).expect("a filter block fits a BPF jump");
        let mut out = Vec::with_capacity(block.len() + 1);
        out.push(insn(BPF_JEQ_K, 0, skip, value));
        out.extend(block);
        out
    }

    fn nr(syscall: libc::c_long) -> u32 {
        syscall as u32
    }

    /// System calls refused outright, and the error each returns.
    fn refused() -> Vec<(libc::c_long, i32)> {
        vec![
            // Its socket operations would bypass the socket(2) check; callers
            // fall back to ordinary system calls on ENOSYS.
            (libc::SYS_io_uring_setup, libc::ENOSYS),
            // System V IPC and POSIX message queues, private under bwrap's
            // --unshare-ipc.
            (libc::SYS_shmget, libc::EPERM),
            (libc::SYS_shmat, libc::EPERM),
            (libc::SYS_shmctl, libc::EPERM),
            (libc::SYS_msgget, libc::EPERM),
            (libc::SYS_msgsnd, libc::EPERM),
            (libc::SYS_msgrcv, libc::EPERM),
            (libc::SYS_msgctl, libc::EPERM),
            (libc::SYS_semget, libc::EPERM),
            (libc::SYS_semop, libc::EPERM),
            (libc::SYS_semtimedop, libc::EPERM),
            (libc::SYS_semctl, libc::EPERM),
            (libc::SYS_mq_open, libc::EPERM),
            // The caller's session keyring, which a new user namespace would
            // not reach.
            (libc::SYS_keyctl, libc::EPERM),
            (libc::SYS_add_key, libc::EPERM),
            (libc::SYS_request_key, libc::EPERM),
        ]
    }

    fn socket_block(policy: SocketPolicy) -> Vec<libc::sock_filter> {
        let mut block = vec![load(offset_arg_low(0))];
        block.extend(when(
            libc::AF_UNIX as u32,
            vec![verdict(policy.unix_sockets)],
        ));
        for family in [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
            block.extend(when(family as u32, vec![verdict(policy.host_network)]));
        }
        block.push(fail(libc::EACCES));
        block
    }

    fn socketpair_block(policy: SocketPolicy) -> Vec<libc::sock_filter> {
        let unix = if policy.unix_sockets {
            vec![allow()]
        } else {
            let mut checks = vec![
                load(offset_arg_low(1)),
                insn(BPF_AND_K, 0, 0, SOCK_TYPE_MASK),
            ];
            checks.extend(when(libc::SOCK_DGRAM as u32, vec![fail(libc::EACCES)]));
            checks.push(allow());
            checks
        };
        let mut block = vec![load(offset_arg_low(0))];
        block.extend(when(libc::AF_UNIX as u32, unix));
        block.push(fail(libc::EACCES));
        block
    }

    fn ioctl_block() -> Vec<libc::sock_filter> {
        let mut block = vec![load(offset_arg_low(1))];
        for request in [libc::TIOCSTI, libc::TIOCLINUX] {
            block.extend(when(request as u32, vec![fail(libc::EPERM)]));
        }
        block.push(allow());
        block
    }

    pub(super) fn build(policy: SocketPolicy) -> Vec<libc::sock_filter> {
        let mut program = vec![load(OFFSET_ARCH)];
        // Any other ABI: its system call numbers mean something else here.
        program.push(insn(BPF_JEQ_K, 1, 0, NATIVE_ARCH));
        program.push(fail(libc::ENOSYS));
        program.push(load(OFFSET_NR));
        #[cfg(target_arch = "x86_64")]
        {
            program.push(insn(BPF_JGE_K, 0, 1, X32_SYSCALL_BIT));
            program.push(fail(libc::ENOSYS));
        }
        for (syscall, errno) in refused() {
            program.extend(when(nr(syscall), vec![fail(errno)]));
        }
        program.extend(when(nr(libc::SYS_socket), socket_block(policy)));
        program.extend(when(nr(libc::SYS_socketpair), socketpair_block(policy)));
        program.extend(when(nr(libc::SYS_ioctl), ioctl_block()));
        program.push(allow());
        program
    }

    /// Install `program` on the calling thread. Runs between `fork` and
    /// `exec`: it only makes the `prctl` system call on memory allocated
    /// before the fork.
    pub(super) fn install(program: &[libc::sock_filter]) -> std::io::Result<()> {
        let fprog = libc::sock_fprog {
            len: program.len() as libc::c_ushort,
            filter: program.as_ptr().cast_mut(),
        };
        // SAFETY: `fprog` points at a live, well-formed program for the
        // duration of the call; the kernel copies it.
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &fprog as *const libc::sock_fprog,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(test)]
    pub(super) mod interpreter {
        //! Runs a program the way the kernel would, for the tests.
        use super::*;

        pub(crate) struct Call {
            pub(crate) arch: u32,
            pub(crate) nr: libc::c_long,
            pub(crate) args: [u64; 6],
        }

        impl Call {
            pub(crate) fn native(nr: libc::c_long, args: &[u64]) -> Self {
                let mut all = [0_u64; 6];
                all[..args.len()].copy_from_slice(args);
                Self {
                    arch: NATIVE_ARCH,
                    nr,
                    args: all,
                }
            }

            fn word(&self, offset: u32) -> u32 {
                match offset {
                    OFFSET_NR => self.nr as u32,
                    OFFSET_ARCH => self.arch,
                    offset if offset >= 16 && (offset - 16) % 8 == 0 => {
                        self.args[((offset - 16) / 8) as usize] as u32
                    }
                    other => panic!("unexpected load offset {other}"),
                }
            }
        }

        /// The action the program returns for `call`.
        pub(crate) fn run(program: &[libc::sock_filter], call: &Call) -> u32 {
            let mut accumulator = 0_u32;
            let mut pc = 0_usize;
            loop {
                let insn = program[pc];
                match insn.code {
                    BPF_LD_W_ABS => accumulator = call.word(insn.k),
                    BPF_AND_K => accumulator &= insn.k,
                    BPF_RET_K => return insn.k,
                    BPF_JEQ_K => {
                        let jump = if accumulator == insn.k {
                            insn.jt
                        } else {
                            insn.jf
                        };
                        pc += usize::from(jump);
                    }
                    #[cfg(target_arch = "x86_64")]
                    BPF_JGE_K => {
                        let jump = if accumulator >= insn.k {
                            insn.jt
                        } else {
                            insn.jf
                        };
                        pc += usize::from(jump);
                    }
                    other => panic!("unexpected instruction {other:#x}"),
                }
                pc += 1;
            }
        }

        pub(crate) const ALLOW: u32 = SECCOMP_RET_ALLOW;

        pub(crate) fn errno(value: i32) -> u32 {
            SECCOMP_RET_ERRNO | value as u32
        }
    }
}

/// A built filter, ready to install in the child.
#[derive(Debug)]
pub struct SeccompFilter {
    #[cfg(all(
        target_os = "linux",
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    program: Vec<libc::sock_filter>,
}

impl SeccompFilter {
    /// Build the filter for `policy`. `None` on an architecture without one,
    /// which [`super::abi::probe`] has already refused.
    pub fn new(policy: SocketPolicy) -> Option<Self> {
        #[cfg(all(
            target_os = "linux",
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            Some(Self {
                program: filter::build(policy),
            })
        }
        #[cfg(not(all(
            target_os = "linux",
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = policy;
            None
        }
    }

    /// Install the filter on the calling thread, which must already have
    /// `no_new_privs`. Async-signal-safe: it allocates nothing.
    pub fn install(&self) -> std::io::Result<()> {
        #[cfg(all(
            target_os = "linux",
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            filter::install(&self.program)
        }
        #[cfg(not(all(
            target_os = "linux",
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::filter::interpreter::{errno, run, Call, ALLOW};
    use super::*;

    const ISOLATED_OLD_KERNEL: SocketPolicy = SocketPolicy {
        host_network: false,
        unix_sockets: false,
    };
    const ISOLATED: SocketPolicy = SocketPolicy {
        host_network: false,
        unix_sockets: true,
    };
    const HOST_NETWORK: SocketPolicy = SocketPolicy {
        host_network: true,
        unix_sockets: true,
    };

    fn verdict(policy: SocketPolicy, call: Call) -> u32 {
        let filter = SeccompFilter::new(policy).expect("filter");
        run(&filter.program, &call)
    }

    fn socket(family: i32, kind: i32) -> Call {
        Call::native(libc::SYS_socket, &[family as u64, kind as u64])
    }

    #[test]
    fn the_isolated_posture_refuses_every_network_socket() {
        for family in [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
            libc::AF_VSOCK,
        ] {
            for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_RAW] {
                assert_eq!(
                    verdict(ISOLATED, socket(family, kind | libc::SOCK_CLOEXEC)),
                    errno(libc::EACCES),
                    "family {family} type {kind}"
                );
            }
        }
    }

    #[test]
    fn the_host_network_posture_allows_inet_but_not_other_families() {
        for family in [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
            assert_eq!(
                verdict(HOST_NETWORK, socket(family, libc::SOCK_DGRAM)),
                ALLOW
            );
        }
        for family in [libc::AF_PACKET, libc::AF_VSOCK, libc::AF_ALG] {
            assert_eq!(
                verdict(HOST_NETWORK, socket(family, libc::SOCK_STREAM)),
                errno(libc::EACCES)
            );
        }
    }

    #[test]
    fn unix_sockets_follow_whether_landlock_confines_them() {
        assert_eq!(
            verdict(ISOLATED, socket(libc::AF_UNIX, libc::SOCK_STREAM)),
            ALLOW
        );
        assert_eq!(
            verdict(
                ISOLATED_OLD_KERNEL,
                socket(libc::AF_UNIX, libc::SOCK_STREAM)
            ),
            errno(libc::EACCES)
        );
    }

    #[test]
    fn only_datagram_socketpairs_are_refused_without_unix_socket_rights() {
        let pair = |kind: i32| {
            Call::native(
                libc::SYS_socketpair,
                &[libc::AF_UNIX as u64, (kind | libc::SOCK_CLOEXEC) as u64],
            )
        };
        assert_eq!(verdict(ISOLATED_OLD_KERNEL, pair(libc::SOCK_STREAM)), ALLOW);
        assert_eq!(
            verdict(ISOLATED_OLD_KERNEL, pair(libc::SOCK_SEQPACKET)),
            ALLOW
        );
        assert_eq!(
            verdict(ISOLATED_OLD_KERNEL, pair(libc::SOCK_DGRAM)),
            errno(libc::EACCES)
        );
        assert_eq!(verdict(ISOLATED, pair(libc::SOCK_DGRAM)), ALLOW);
    }

    #[test]
    fn ipc_keyrings_and_io_uring_are_refused() {
        for (nr, expected) in [
            (libc::SYS_io_uring_setup, libc::ENOSYS),
            (libc::SYS_shmget, libc::EPERM),
            (libc::SYS_msgget, libc::EPERM),
            (libc::SYS_semget, libc::EPERM),
            (libc::SYS_mq_open, libc::EPERM),
            (libc::SYS_keyctl, libc::EPERM),
        ] {
            assert_eq!(
                verdict(HOST_NETWORK, Call::native(nr, &[])),
                errno(expected)
            );
        }
    }

    // The ioctl request is a c_ulong on glibc and a c_int on musl.
    #[allow(clippy::unnecessary_cast)]
    #[test]
    fn terminal_input_injection_is_refused_and_other_ioctls_pass() {
        let ioctl = |request: libc::Ioctl| Call::native(libc::SYS_ioctl, &[0, request as u64]);
        assert_eq!(verdict(ISOLATED, ioctl(libc::TIOCSTI)), errno(libc::EPERM));
        assert_eq!(
            verdict(ISOLATED, ioctl(libc::TIOCLINUX)),
            errno(libc::EPERM)
        );
        assert_eq!(verdict(ISOLATED, ioctl(libc::TIOCGWINSZ)), ALLOW);
    }

    #[test]
    fn ordinary_system_calls_pass() {
        for nr in [
            libc::SYS_read,
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_kill,
        ] {
            assert_eq!(verdict(ISOLATED_OLD_KERNEL, Call::native(nr, &[])), ALLOW);
        }
    }

    #[test]
    fn another_abi_is_refused_whole() {
        let mut compat = socket(libc::AF_UNIX, libc::SOCK_STREAM);
        compat.arch = 0x4000_0003; // AUDIT_ARCH_I386
        compat.nr = 102; // socketcall
        assert_eq!(verdict(HOST_NETWORK, compat), errno(libc::ENOSYS));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_system_calls_are_refused() {
        let x32 = Call::native(libc::SYS_socket | 0x4000_0000, &[libc::AF_INET as u64]);
        assert_eq!(verdict(HOST_NETWORK, x32), errno(libc::ENOSYS));
    }
}
