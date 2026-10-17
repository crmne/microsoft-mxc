// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! What the running kernel's Landlock can enforce.
//!
//! Landlock grows by ABI version, and every version adds restrictions an older
//! kernel silently does not apply. The backend therefore asks the kernel for
//! its ABI once per run, refuses to run below [`MIN_ABI`], and covers what the
//! ABI it found cannot express with its seccomp filter, or reports it. It never
//! assumes a right the kernel did not confirm.

use std::fmt;

/// The oldest Landlock ABI the backend runs on: 3, from Linux 6.2.
///
/// ABI 1 and 2 do not restrict truncation, so a workload could empty any file
/// it can open for reading, or any file it owns through `truncate(2)`, in paths
/// the policy only lets it read. That is a write the policy forbids.
pub const MIN_ABI: i32 = 3;

/// The newest ABI the backend handles rights for. A newer kernel enforces
/// everything this ABI does; the rights it adds are not requested.
pub const KNOWN_ABI: i32 = 9;

/// The kernel's Landlock ABI, at or above [`MIN_ABI`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockAbi {
    kernel: i32,
}

impl LandlockAbi {
    /// The ABI the kernel reports.
    pub fn kernel(self) -> i32 {
        self.kernel
    }

    /// The ABI whose rights the backend requests: the kernel's, capped at the
    /// newest one it knows.
    pub fn effective(self) -> i32 {
        self.kernel.min(KNOWN_ABI)
    }

    /// ABI 4 (Linux 6.7): TCP `bind` and `connect`.
    pub fn restricts_tcp(self) -> bool {
        self.effective() >= 4
    }

    /// ABI 5 (Linux 6.10): `ioctl` on device files.
    pub fn restricts_device_ioctl(self) -> bool {
        self.effective() >= 5
    }

    /// ABI 6 (Linux 6.12): signals and abstract Unix sockets scoped to the
    /// sandbox.
    pub fn scopes_signals_and_abstract_sockets(self) -> bool {
        self.effective() >= 6
    }

    /// ABI 9 (Linux 7.1): `connect` and `sendmsg` to pathname Unix sockets
    /// only beneath granted paths.
    pub fn restricts_unix_sockets(self) -> bool {
        self.effective() >= 9
    }

    /// What a Bubblewrap sandbox would keep from the workload that this ABI
    /// cannot: one sentence each, for warnings and the availability probe.
    pub fn gaps(self) -> Vec<String> {
        let mut gaps = Vec::new();
        if !self.scopes_signals_and_abstract_sockets() {
            gaps.push(format!(
                "Landlock ABI {} cannot keep the workload from signalling the user's other \
                 processes (needs ABI 6, Linux 6.12)",
                self.kernel
            ));
        }
        if !self.restricts_unix_sockets() {
            gaps.push(format!(
                "Landlock ABI {} cannot confine Unix sockets to granted paths, so the workload \
                 gets socketpair(2) only (needs ABI 9, Linux 7.1)",
                self.kernel
            ));
        }
        gaps
    }

    /// One line on what this ABI enforces, for logs and warnings.
    pub fn summary(self) -> String {
        let unix = if self.restricts_unix_sockets() {
            "Unix sockets only beneath granted paths"
        } else {
            "Unix sockets limited to socketpair (pathname socket access needs ABI 9)"
        };
        let signals = if self.scopes_signals_and_abstract_sockets() {
            "signals scoped to the sandbox"
        } else {
            "signals to the user's other processes not blocked (needs ABI 6)"
        };
        format!(
            "Landlock ABI {}: filesystem and network enforced, {unix}, {signals}",
            self.kernel
        )
    }
}

/// Why the Landlock backend cannot run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandlockUnavailable {
    /// The kernel was built without Landlock (`ENOSYS`).
    NotImplemented,
    /// Landlock is built in but not enabled at boot (`EOPNOTSUPP`).
    NotEnabled,
    /// The kernel's ABI is older than [`MIN_ABI`].
    TooOld(i32),
    /// Asking for the ABI failed for another reason.
    ProbeFailed(String),
    /// The backend has no seccomp filter for this CPU architecture.
    UnsupportedArchitecture,
}

impl fmt::Display for LandlockUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => write!(
                f,
                "Landlock is not available: this kernel was built without it (Linux 6.2 or \
                 newer with CONFIG_SECURITY_LANDLOCK is required)."
            ),
            Self::NotEnabled => write!(
                f,
                "Landlock is built into this kernel but not enabled. Add landlock to the lsm= \
                 boot parameter (or CONFIG_LSM) to use the Landlock backend."
            ),
            Self::TooOld(abi) => write!(
                f,
                "Landlock ABI {abi} is too old: the Landlock backend needs ABI {MIN_ABI} \
                 (Linux 6.2) or newer, because older ABIs cannot stop a workload truncating \
                 files it may only read."
            ),
            Self::ProbeFailed(detail) => {
                write!(f, "Could not query the Landlock ABI: {detail}.")
            }
            Self::UnsupportedArchitecture => write!(
                f,
                "The Landlock backend supports x86_64 and aarch64 only: it needs a seccomp \
                 filter for the system calls Landlock does not cover."
            ),
        }
    }
}

impl std::error::Error for LandlockUnavailable {}

/// Interpret the return value and `errno` of
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
/// Split from [`probe`] so every answer is testable on any kernel.
fn interpret(result: i64, errno: i32) -> Result<LandlockAbi, LandlockUnavailable> {
    if !super::seccomp::ARCH_SUPPORTED {
        return Err(LandlockUnavailable::UnsupportedArchitecture);
    }
    if result < 0 {
        return Err(match errno {
            libc::ENOSYS => LandlockUnavailable::NotImplemented,
            libc::EOPNOTSUPP => LandlockUnavailable::NotEnabled,
            other => LandlockUnavailable::ProbeFailed(
                std::io::Error::from_raw_os_error(other).to_string(),
            ),
        });
    }
    let kernel = i32::try_from(result).unwrap_or(i32::MAX);
    if kernel < MIN_ABI {
        return Err(LandlockUnavailable::TooOld(kernel));
    }
    Ok(LandlockAbi { kernel })
}

/// Ask the kernel for its Landlock ABI.
pub fn probe() -> Result<LandlockAbi, LandlockUnavailable> {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with a null attribute pointer, zero size, and the VERSION flag
    // the call only returns the ABI; it reads and writes no memory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    interpret(result, errno)
}

#[cfg(test)]
impl LandlockAbi {
    pub(crate) fn for_tests(kernel: i32) -> Self {
        Self { kernel }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_disabled_landlock_says_which() {
        if !super::super::seccomp::ARCH_SUPPORTED {
            return;
        }
        assert_eq!(
            interpret(-1, libc::ENOSYS),
            Err(LandlockUnavailable::NotImplemented)
        );
        assert_eq!(
            interpret(-1, libc::EOPNOTSUPP),
            Err(LandlockUnavailable::NotEnabled)
        );
        assert!(matches!(
            interpret(-1, libc::EPERM),
            Err(LandlockUnavailable::ProbeFailed(_))
        ));
    }

    #[test]
    fn abis_that_cannot_stop_truncation_are_refused() {
        if !super::super::seccomp::ARCH_SUPPORTED {
            return;
        }
        assert_eq!(interpret(1, 0), Err(LandlockUnavailable::TooOld(1)));
        assert_eq!(interpret(2, 0), Err(LandlockUnavailable::TooOld(2)));
        assert_eq!(interpret(3, 0).map(LandlockAbi::kernel), Ok(3));
        assert!(LandlockUnavailable::TooOld(2).to_string().contains("ABI 3"));
    }

    #[test]
    fn a_kernel_newer_than_the_backend_is_capped_at_the_rights_it_knows() {
        let abi = LandlockAbi::for_tests(12);
        assert_eq!(abi.kernel(), 12);
        assert_eq!(abi.effective(), KNOWN_ABI);
        assert!(abi.restricts_unix_sockets());
    }

    #[test]
    fn each_abi_reports_what_it_enforces() {
        let ubuntu_24_04 = LandlockAbi::for_tests(4);
        assert!(ubuntu_24_04.restricts_tcp());
        assert!(!ubuntu_24_04.restricts_device_ioctl());
        assert!(!ubuntu_24_04.scopes_signals_and_abstract_sockets());
        assert!(!ubuntu_24_04.restricts_unix_sockets());
        let summary = ubuntu_24_04.summary();
        assert!(summary.contains("socketpair"), "{summary}");
        assert!(summary.contains("needs ABI 6"), "{summary}");

        assert_eq!(ubuntu_24_04.gaps().len(), 2);

        let current = LandlockAbi::for_tests(9);
        assert!(current.scopes_signals_and_abstract_sockets());
        assert!(current.summary().contains("signals scoped"));
        assert!(current.gaps().is_empty());
    }
}
