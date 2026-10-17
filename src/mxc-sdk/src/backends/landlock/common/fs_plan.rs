// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Which paths the workload may use, and how, as Landlock can express it.
//!
//! Landlock allows access to whole file hierarchies and nothing else: a rule
//! on a directory covers everything beneath it, and there is no rule that
//! takes access away. Bubblewrap expresses the same policy with mounts, where
//! a deeper mount can hide or narrow a shallower one. So the plan:
//!
//! - grants each `readonlyPaths` entry read and execute, and each
//!   `readwritePaths` entry read, execute, and write;
//! - grants the same baseline Bubblewrap mounts (`/usr/bin`, `/usr/lib`,
//!   `/etc`, ...), the device files its `--dev` provides, `/proc`, and a
//!   private temporary directory;
//! - honours a `deniedPaths` entry beneath a baseline grant by replacing that
//!   grant with grants on its other entries, since the baseline is MXC's
//!   choice and only reads;
//! - refuses a `deniedPaths` entry beneath a policy grant, and a policy path
//!   that would narrow a broader grant above it (read-only beneath
//!   read-write), because Landlock would grant it anyway.
//!
//! Paths are compared after resolving symlinks, since Landlock rules apply to
//! the file a path reaches.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The access a grant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// Read device files such as `/dev/urandom`.
    ReadDevice,
    /// Read and write device files such as `/dev/null`, with their ioctls.
    ReadWriteDevice,
    /// List, read, and execute.
    ReadExecute,
    /// Also create, write, truncate, rename, and remove.
    ReadWrite,
}

impl Access {
    /// Whether this grant includes everything `other` does, so `other` is no
    /// narrower once Landlock unions the two.
    fn covers(self, other: Access) -> bool {
        matches!(
            (self, other),
            (Access::ReadWrite, _)
                | (
                    Access::ReadExecute,
                    Access::ReadExecute | Access::ReadDevice
                )
                | (
                    Access::ReadWriteDevice,
                    Access::ReadWriteDevice | Access::ReadDevice
                )
                | (Access::ReadDevice, Access::ReadDevice)
        )
    }
}

/// One Landlock rule: `access` to `path` and everything beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Symlink-free path of an existing file or directory.
    pub path: PathBuf,
    pub access: Access,
}

/// The rules for one run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FsPlan {
    pub grants: Vec<Grant>,
}

/// Read-only system paths every sandbox gets: the same list as Bubblewrap's
/// `BASELINE_RO_BIND_PATHS`, for the same reasons. Missing entries are
/// skipped.
pub const BASELINE_READ_EXECUTE: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    "/etc",
    "/run/systemd/resolve",
    "/run/NetworkManager",
    "/run/resolvconf",
    "/mnt/wsl/resolv.conf",
];

/// Device files `bwrap --dev` provides, which the workload may write.
pub const BASELINE_DEVICES_READ_WRITE: &[&str] = &["/dev/null", "/dev/full", "/dev/tty"];

/// Device files `bwrap --dev` provides, which the workload may only read.
pub const BASELINE_DEVICES_READ: &[&str] = &["/dev/zero", "/dev/random", "/dev/urandom"];

/// The policy paths, as the runner hands them over after the shared
/// normalization.
#[derive(Debug, Default, Clone)]
pub struct PolicyPaths<'a> {
    pub readonly: &'a [String],
    pub readwrite: &'a [String],
    pub denied: &'a [String],
}

/// Resolve `path` through every symlink it names, or explain why the plan
/// cannot use it.
fn resolve_existing(list: &str, path: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| {
        format!(
            "Landlock: {list} entry '{path}' cannot be granted ({error}). Landlock grants \
             access to files that exist, so create it first or remove it from the policy."
        )
    })
}

/// Resolve a denied path as far as it exists. A path that does not exist yet
/// is still placed under the grants that would let it be created.
fn resolve_denied(path: &str) -> PathBuf {
    crate::mxc_common::filesystem_symlink::resolve_through_symlinks(Path::new(path))
        .unwrap_or_else(|| PathBuf::from(path))
}

/// Build the plan. `private_tmp`, when given, is granted read-write.
pub fn plan(paths: &PolicyPaths<'_>, private_tmp: Option<&Path>) -> Result<FsPlan, String> {
    let mut policy = Vec::new();
    for (list, entries, access) in [
        ("readonlyPaths", paths.readonly, Access::ReadExecute),
        ("readwritePaths", paths.readwrite, Access::ReadWrite),
    ] {
        for entry in entries {
            policy.push(Grant {
                path: resolve_existing(list, entry)?,
                access,
            });
        }
    }
    reject_narrowing(&policy)?;

    let denied: Vec<(String, PathBuf)> = paths
        .denied
        .iter()
        .map(|entry| (entry.clone(), resolve_denied(entry)))
        .collect();
    for (entry, resolved) in &denied {
        if let Some(grant) = policy
            .iter()
            .find(|grant| resolved.starts_with(&grant.path))
        {
            return Err(format!(
                "Landlock: deniedPaths entry '{entry}' lies inside {} '{}'. Landlock grants \
                 whole directory trees and cannot take part of one away, so it would grant \
                 the denied path too. Grant the paths beside it instead, or use the \
                 Bubblewrap backend.",
                if grant.access == Access::ReadWrite {
                    "readwritePaths entry"
                } else {
                    "readonlyPaths entry"
                },
                grant.path.display()
            ));
        }
    }

    let mut baseline = Vec::new();
    let mut add_baseline = |path: &str, access: Access| {
        if let Ok(resolved) = fs::canonicalize(path) {
            baseline.push(Grant {
                path: resolved,
                access,
            });
        }
    };
    for path in BASELINE_READ_EXECUTE {
        add_baseline(path, Access::ReadExecute);
    }
    for path in BASELINE_DEVICES_READ_WRITE {
        add_baseline(path, Access::ReadWriteDevice);
    }
    for path in BASELINE_DEVICES_READ {
        add_baseline(path, Access::ReadDevice);
    }
    // bwrap mounts a fresh /proc for its PID namespace; Landlock can only
    // let the workload read the host's. Other users' processes stay behind
    // their own permissions, and Landlock keeps the workload from reading
    // another process's memory or environment through ptrace checks.
    add_baseline("/proc", Access::ReadExecute);
    if let Some(tmp) = private_tmp {
        add_baseline(&tmp.to_string_lossy(), Access::ReadWrite);
    }

    for (_, resolved) in &denied {
        baseline = carve(baseline, resolved).map_err(|error| {
            format!(
                "Landlock: could not leave deniedPaths entry '{}' out of the baseline \
                 grants: {error}",
                resolved.display()
            )
        })?;
    }

    let mut grants = policy;
    grants.extend(baseline);
    grants.sort_by(|a, b| a.path.cmp(&b.path).then(a.access.cmp(&b.access)));
    grants.dedup_by(|later, earlier| later.path == earlier.path && later.access == earlier.access);
    Ok(FsPlan { grants })
}

/// Refuse a policy path Landlock would grant more than the policy asks:
/// one beneath another whose access it does not cover.
fn reject_narrowing(policy: &[Grant]) -> Result<(), String> {
    for inner in policy {
        for outer in policy {
            if inner.path != outer.path
                && inner.path.starts_with(&outer.path)
                && !inner.access.covers(outer.access)
            {
                return Err(format!(
                    "Landlock: readonlyPaths entry '{}' lies inside readwritePaths entry \
                     '{}'. Landlock grants whole directory trees and cannot narrow part of \
                     one, so the read-only path would be writable. Grant the paths beside it \
                     instead, or use the Bubblewrap backend.",
                    inner.path.display(),
                    outer.path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Leave `denied` out of the baseline grants: drop grants at or beneath it,
/// and replace a grant above it with grants on the entries beside the way
/// down to it.
fn carve(grants: Vec<Grant>, denied: &Path) -> io::Result<Vec<Grant>> {
    let mut carved = Vec::with_capacity(grants.len());
    for grant in grants {
        if grant.path.starts_with(denied) {
            continue;
        }
        if denied.starts_with(&grant.path) {
            split(&grant, denied, &mut carved)?;
        } else {
            carved.push(grant);
        }
    }
    Ok(carved)
}

/// Grant every entry of `grant.path` except the one leading to `denied`, and
/// split that one in turn. Symlinks get no grant: Landlock judges the file a
/// symlink reaches by that file's own grants, while a grant on the symlink
/// would cover wherever it points.
fn split(grant: &Grant, denied: &Path, out: &mut Vec<Grant>) -> io::Result<()> {
    let Ok(rest) = denied.strip_prefix(&grant.path) else {
        return Ok(());
    };
    let Some(next) = rest.components().next() else {
        return Ok(());
    };
    let toward = grant.path.join(next);
    for entry in fs::read_dir(&grant.path)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_symlink() {
            continue;
        }
        if path == toward {
            if path != denied && entry.file_type()?.is_dir() {
                let inner = Grant {
                    path: path.clone(),
                    ..grant.clone()
                };
                split(&inner, denied, out)?;
            }
            continue;
        }
        out.push(Grant {
            path,
            ..grant.clone()
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(paths: &[&Path]) -> Vec<String> {
        paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    fn grant_for<'a>(plan: &'a FsPlan, path: &Path) -> Option<&'a Grant> {
        let path = fs::canonicalize(path).unwrap();
        plan.grants.iter().find(|grant| grant.path == path)
    }

    #[test]
    fn policy_paths_get_their_access_and_the_baseline_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        let rw = dir.path().join("rw");
        fs::create_dir_all(&ro).unwrap();
        fs::create_dir_all(&rw).unwrap();
        let readonly = strings(&[&ro]);
        let readwrite = strings(&[&rw]);
        let plan = plan(
            &PolicyPaths {
                readonly: &readonly,
                readwrite: &readwrite,
                denied: &[],
            },
            None,
        )
        .unwrap();
        assert_eq!(grant_for(&plan, &ro).unwrap().access, Access::ReadExecute);
        assert_eq!(grant_for(&plan, &rw).unwrap().access, Access::ReadWrite);
        assert_eq!(
            grant_for(&plan, Path::new("/etc")).unwrap().access,
            Access::ReadExecute
        );
        assert_eq!(
            grant_for(&plan, Path::new("/dev/null")).unwrap().access,
            Access::ReadWriteDevice
        );
        assert!(plan
            .grants
            .iter()
            .all(|grant| !grant.path.starts_with("/home") || grant.path.starts_with(dir.path())));
    }

    #[test]
    fn a_missing_policy_path_is_refused() {
        let readwrite = vec!["/definitely/not/here".to_string()];
        let error = plan(
            &PolicyPaths {
                readwrite: &readwrite,
                ..Default::default()
            },
            None,
        )
        .unwrap_err();
        assert!(error.contains("/definitely/not/here"), "{error}");
    }

    #[test]
    fn a_denied_path_inside_a_policy_grant_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join(".env");
        fs::write(&secret, "TOKEN=1").unwrap();
        let readwrite = strings(&[dir.path()]);
        let denied = strings(&[&secret]);
        let error = plan(
            &PolicyPaths {
                readwrite: &readwrite,
                denied: &denied,
                ..Default::default()
            },
            None,
        )
        .unwrap_err();
        assert!(error.contains("deniedPaths"), "{error}");
        assert!(error.contains("Bubblewrap"), "{error}");
    }

    #[test]
    fn a_denied_path_that_does_not_exist_yet_inside_a_policy_grant_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let readwrite = strings(&[dir.path()]);
        let denied = strings(&[&dir.path().join("later/secret")]);
        assert!(plan(
            &PolicyPaths {
                readwrite: &readwrite,
                denied: &denied,
                ..Default::default()
            },
            None,
        )
        .is_err());
    }

    #[test]
    fn a_read_only_path_inside_a_read_write_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("vendor");
        fs::create_dir_all(&inner).unwrap();
        let readwrite = strings(&[dir.path()]);
        let readonly = strings(&[&inner]);
        let error = plan(
            &PolicyPaths {
                readonly: &readonly,
                readwrite: &readwrite,
                denied: &[],
            },
            None,
        )
        .unwrap_err();
        assert!(error.contains("writable"), "{error}");
    }

    #[test]
    fn a_read_write_path_inside_a_read_only_one_widens_it_as_bubblewrap_does() {
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("out");
        fs::create_dir_all(&inner).unwrap();
        let readonly = strings(&[dir.path()]);
        let readwrite = strings(&[&inner]);
        let plan = plan(
            &PolicyPaths {
                readonly: &readonly,
                readwrite: &readwrite,
                denied: &[],
            },
            None,
        )
        .unwrap();
        assert_eq!(grant_for(&plan, &inner).unwrap().access, Access::ReadWrite);
    }

    #[test]
    fn a_denied_baseline_entry_is_dropped_and_one_inside_the_baseline_is_carved_out() {
        // Stand in for the baseline with a temporary tree.
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        for name in ["a/keep", "a/secret/inner", "b"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        fs::write(root.join("a/file"), "x").unwrap();
        std::os::unix::fs::symlink("/home", root.join("a/link")).unwrap();
        let baseline = vec![
            Grant {
                path: root.join("a"),
                access: Access::ReadExecute,
            },
            Grant {
                path: root.join("b"),
                access: Access::ReadExecute,
            },
        ];
        let carved = carve(baseline.clone(), &root.join("a/secret")).unwrap();
        let mut paths: Vec<_> = carved.iter().map(|g| g.path.clone()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![root.join("a/file"), root.join("a/keep"), root.join("b")]
        );

        let dropped = carve(baseline, &root.join("b")).unwrap();
        assert!(dropped.iter().all(|g| g.path != root.join("b")));
        assert!(dropped.iter().any(|g| g.path == root.join("a")));
    }

    #[test]
    fn the_private_temporary_directory_is_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let plan = plan(&PolicyPaths::default(), Some(tmp.path())).unwrap();
        assert_eq!(
            grant_for(&plan, tmp.path()).unwrap().access,
            Access::ReadWrite
        );
    }
}
