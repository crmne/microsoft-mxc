// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `landlock_common`: the Landlock sandbox backend for Linux.
//!
//! Landlock confines a process without privileges and without namespaces, so
//! it works where Bubblewrap cannot create its user namespace: Ubuntu 23.10
//! and later with AppArmor's restriction on, hosts with
//! `user.max_user_namespaces` at zero, and containers whose seccomp profile
//! refuses `unshare`. The engine uses it for `containment: "process"` when
//! Bubblewrap is unavailable, and it can be named as `"landlock"`.
//!
//! - [`abi`] asks the kernel which Landlock ABI it runs and what that ABI
//!   enforces, refusing ABIs that cannot hold a read-only grant.
//! - [`fs_plan`] maps the filesystem policy and Bubblewrap's baseline onto
//!   Landlock grants, refusing what Landlock cannot express.
//! - [`network`] settles the network posture: isolated, the whole host
//!   network, or refused.
//! - [`seccomp`] builds the filter for what Landlock does not cover.
//! - [`restriction`] builds the ruleset and applies both in the child.
//! - [`landlock_runner`] runs and supervises the workload.
//!
//! See docs/backends/landlock/landlock-backend.md.

pub mod abi;
pub mod fs_plan;
pub mod landlock_runner;
pub mod network;
pub mod restriction;
pub mod seccomp;
