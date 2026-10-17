// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The Landlock ruleset and seccomp filter for one run, built in the parent
//! and applied by the child to itself between `fork` and `exec`.
//!
//! Everything that allocates or can fail for a reason the caller should hear
//! (opening the granted paths, creating the ruleset, compiling the filter)
//! happens before the fork. The child only makes three system calls:
//! `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self`, and
//! `prctl(PR_SET_SECCOMP)`. Any of them failing fails the spawn, so a workload
//! never runs less confined than planned.
//!
//! There is no `PR_SET_PDEATHSIG`: it fires when the *thread* that forked
//! exits, and an SDK caller may well spawn from a thread that ends before the
//! workload does.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use landlock::{
    Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, Scope, ABI,
};

use super::abi::LandlockAbi;
use super::fs_plan::{Access, FsPlan};
use super::network::NetworkPosture;
use super::seccomp::{SeccompFilter, SocketPolicy};

/// A ruleset ready to enforce, with the filter that goes with it.
pub struct Restriction {
    ruleset: OwnedFd,
    filter: SeccompFilter,
}

/// The crate's name for the rights of `abi`. Requests are capped at the newest
/// ABI the backend knows, and below [`super::abi::MIN_ABI`] nothing is built.
fn crate_abi(abi: LandlockAbi) -> ABI {
    match abi.effective() {
        i32::MIN..=3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        7 => ABI::V7,
        8 => ABI::V8,
        _ => ABI::V9,
    }
}

/// The Landlock rights for a grant.
fn rights(access: Access, abi: ABI, is_dir: bool) -> BitFlags<AccessFs> {
    let read = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    // Device nodes need privilege to create anyway; ioctls belong to devices.
    let write = AccessFs::from_write(abi)
        & !(AccessFs::MakeChar | AccessFs::MakeBlock | AccessFs::IoctlDev);
    let all = AccessFs::from_all(abi);
    let device_ioctl = all & AccessFs::IoctlDev;
    let wanted = match access {
        Access::ReadExecute => read,
        Access::ReadWrite => read | write,
        Access::ReadDevice => AccessFs::ReadFile.into(),
        // `> /dev/null` opens with O_TRUNC, which Landlock checks as a
        // truncation.
        Access::ReadWriteDevice => {
            AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate | device_ioctl
        }
    };
    let wanted = wanted & all;
    if is_dir {
        wanted
    } else {
        wanted & AccessFs::from_file(abi)
    }
}

impl Restriction {
    /// Build the ruleset for `plan` and `posture` on `abi`, and the filter.
    pub fn new(plan: &FsPlan, abi: LandlockAbi, posture: NetworkPosture) -> Result<Self, String> {
        let crate_abi = crate_abi(abi);
        let fail = |error: &dyn std::fmt::Display| format!("Landlock: {error}");

        // A hard requirement: every right requested here comes from the ABI
        // the kernel reported, so a refusal means the kernel and the probe
        // disagree, and the run must not start.
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(crate_abi))
            .map_err(|error| fail(&error))?;
        if posture == NetworkPosture::Isolated && abi.restricts_tcp() {
            // No rules follow, so every TCP bind and connect is refused, on
            // top of the filter refusing the sockets themselves.
            ruleset = ruleset
                .handle_access(AccessNet::from_all(ABI::V4))
                .map_err(|error| fail(&error))?;
        }
        if abi.scopes_signals_and_abstract_sockets() {
            ruleset = ruleset
                .scope(Scope::from_all(ABI::V6))
                .map_err(|error| fail(&error))?;
        }
        let mut created = ruleset.create().map_err(|error| fail(&error))?;
        for grant in &plan.grants {
            let is_dir = grant.path.is_dir();
            let fd = PathFd::new(&grant.path).map_err(|error| {
                format!("Landlock: cannot open '{}': {error}", grant.path.display())
            })?;
            created = created
                .add_rule(PathBeneath::new(
                    fd,
                    rights(grant.access, crate_abi, is_dir),
                ))
                .map_err(|error| {
                    format!("Landlock: cannot grant '{}': {error}", grant.path.display())
                })?;
        }
        let ruleset: Option<OwnedFd> = created.into();
        let ruleset =
            ruleset.ok_or_else(|| "Landlock: the kernel did not create the ruleset".to_string())?;

        let filter = SeccompFilter::new(SocketPolicy {
            host_network: posture == NetworkPosture::HostNetwork,
            unix_sockets: abi.restricts_unix_sockets(),
        })
        .ok_or_else(|| {
            "Landlock: no seccomp filter for this architecture; refusing to run".to_string()
        })?;
        Ok(Self { ruleset, filter })
    }

    /// Have the child confine itself before `exec`. Registered last, so it
    /// runs after every other `pre_exec` step (resource limits, the session).
    pub fn apply_to(self, command: &mut Command) {
        let Self { ruleset, filter } = self;
        // SAFETY: the closure runs between fork and exec. It makes only the
        // async-signal-safe `prctl` and `syscall` calls on a descriptor and a
        // program prepared before the fork, and allocates nothing. The
        // ruleset descriptor is close-on-exec, so the workload never holds it.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::syscall(
                    libc::SYS_landlock_restrict_self,
                    ruleset.as_raw_fd(),
                    0 as libc::c_uint,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                filter.install()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_grants_cannot_write_or_truncate() {
        let granted = rights(Access::ReadExecute, ABI::V9, true);
        assert!(granted.contains(AccessFs::ReadFile | AccessFs::Execute | AccessFs::ReadDir));
        assert!(!granted.intersects(AccessFs::from_write(ABI::V9)));
    }

    #[test]
    fn read_write_grants_never_make_devices_or_issue_ioctls() {
        let granted = rights(Access::ReadWrite, ABI::V9, true);
        assert!(granted.contains(AccessFs::WriteFile | AccessFs::Truncate | AccessFs::MakeReg));
        assert!(granted.contains(AccessFs::ResolveUnix));
        assert!(!granted.intersects(AccessFs::MakeChar | AccessFs::MakeBlock | AccessFs::IoctlDev));
    }

    #[test]
    fn rights_never_exceed_what_the_abi_handles() {
        for access in [
            Access::ReadExecute,
            Access::ReadWrite,
            Access::ReadDevice,
            Access::ReadWriteDevice,
        ] {
            let granted = rights(access, ABI::V3, true);
            assert_eq!(granted & !AccessFs::from_all(ABI::V3), BitFlags::empty());
        }
        assert!(!rights(Access::ReadWriteDevice, ABI::V4, false).contains(AccessFs::IoctlDev));
        assert!(rights(Access::ReadWriteDevice, ABI::V5, false).contains(AccessFs::IoctlDev));
    }

    #[test]
    fn file_grants_carry_only_file_rights() {
        let granted = rights(Access::ReadWrite, ABI::V9, false);
        assert_eq!(granted & !AccessFs::from_file(ABI::V9), BitFlags::empty());
        assert!(granted.contains(AccessFs::WriteFile));
    }

    #[test]
    fn abis_map_onto_the_rights_the_backend_knows() {
        assert_eq!(crate_abi(LandlockAbi::for_tests(3)), ABI::V3);
        assert_eq!(crate_abi(LandlockAbi::for_tests(6)), ABI::V6);
        assert_eq!(crate_abi(LandlockAbi::for_tests(10)), ABI::V9);
    }
}
