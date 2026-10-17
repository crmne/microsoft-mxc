// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The host's process sandbox when the preferred one cannot run here.
//!
//! `containment: "process"` asks for the host's native process sandbox, which
//! on Linux is Bubblewrap. Bubblewrap needs unprivileged user namespaces, and
//! many hosts take them away: Ubuntu 23.10 and later restrict them with
//! AppArmor, `user.max_user_namespaces` can be zero, and container runtimes
//! filter `unshare` with seccomp. Landlock needs none of that, so a request
//! that left the choice to MXC runs on Landlock there instead of failing.
//!
//! A backend the caller named is never substituted: `"bubblewrap"` fails with
//! Bubblewrap's own reason. And the substitute runs the same policy or refuses
//! it; it never runs a weaker one.

use std::borrow::Cow;

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ContainmentBackend, ExecutionRequest};

/// The request to run: `request` itself, or a copy on Landlock when it left
/// the choice to MXC and Bubblewrap cannot run here.
pub(crate) fn select<'a>(
    request: &'a ExecutionRequest,
    logger: &mut Logger,
) -> Cow<'a, ExecutionRequest> {
    select_with(
        request,
        logger,
        crate::bwrap_common::bwrap_version::probe_bwrap,
        crate::landlock_common::abi::probe,
    )
}

/// [`select`] with injectable probes, so both outcomes are testable on any
/// host.
fn select_with<'a, B, L>(
    request: &'a ExecutionRequest,
    logger: &mut Logger,
    bubblewrap: B,
    landlock: L,
) -> Cow<'a, ExecutionRequest>
where
    B: FnOnce() -> Result<
        crate::bwrap_common::bwrap_version::BwrapVersion,
        crate::bwrap_common::bwrap_version::BwrapUnavailable,
    >,
    L: FnOnce() -> Result<
        crate::landlock_common::abi::LandlockAbi,
        crate::landlock_common::abi::LandlockUnavailable,
    >,
{
    if request.containment != ContainmentBackend::Bubblewrap || !request.process_intent {
        return Cow::Borrowed(request);
    }
    let unavailable = match bubblewrap() {
        Ok(_) => return Cow::Borrowed(request),
        Err(error) => error,
    };
    match landlock() {
        Ok(abi) => {
            logger.warning_line(&format!(
                "Bubblewrap cannot run on this host, so containment \"process\" runs on \
                 Landlock instead. {unavailable} {}.",
                abi.summary()
            ));
            Cow::Owned(ExecutionRequest {
                containment: ContainmentBackend::Landlock,
                ..request.clone()
            })
        }
        Err(error) => {
            // Bubblewrap's validation reports why it cannot run; say why the
            // fallback could not either.
            logger.log_line(&format!(
                "Landlock fallback unavailable for containment \"process\": {error}"
            ));
            Cow::Borrowed(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bwrap_common::bwrap_version::{BwrapUnavailable, MIN_BWRAP_VERSION};
    use crate::landlock_common::abi::{LandlockAbi, LandlockUnavailable};
    use crate::mxc_common::logger::Mode;

    fn blocked() -> Result<crate::bwrap_common::bwrap_version::BwrapVersion, BwrapUnavailable> {
        Err(BwrapUnavailable::NamespacesUnavailable {
            status: Some(1),
            detail: "bwrap: No permissions to create a new namespace".to_string(),
        })
    }

    fn process_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "true".to_string(),
            containment: ContainmentBackend::Bubblewrap,
            process_intent: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_working_bubblewrap_is_kept() {
        let request = process_request();
        let mut logger = Logger::new(Mode::Buffer);
        let selected = select_with(
            &request,
            &mut logger,
            || Ok(MIN_BWRAP_VERSION),
            || panic!("Landlock is not probed when Bubblewrap works"),
        );
        assert_eq!(selected.containment, ContainmentBackend::Bubblewrap);
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn process_falls_back_to_landlock_and_says_so() {
        let request = process_request();
        let mut logger = Logger::new(Mode::Buffer);
        let selected = select_with(&request, &mut logger, blocked, || {
            Ok(LandlockAbi::for_tests(4))
        });
        assert_eq!(selected.containment, ContainmentBackend::Landlock);
        assert_eq!(selected.script_code, request.script_code);
        let warning = logger.warnings().join("\n");
        assert!(warning.contains("Landlock ABI 4"), "{warning}");
        assert!(warning.contains("No permissions"), "{warning}");
    }

    #[test]
    fn a_named_bubblewrap_is_never_substituted() {
        let request = ExecutionRequest {
            process_intent: false,
            ..process_request()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let selected = select_with(&request, &mut logger, blocked, || {
            panic!("a named backend is not substituted")
        });
        assert_eq!(selected.containment, ContainmentBackend::Bubblewrap);
    }

    #[test]
    fn without_landlock_bubblewrap_reports_its_own_failure() {
        let request = process_request();
        let mut logger = Logger::new(Mode::Buffer);
        let selected = select_with(&request, &mut logger, blocked, || {
            Err(LandlockUnavailable::TooOld(2))
        });
        assert_eq!(selected.containment, ContainmentBackend::Bubblewrap);
        assert!(logger.get_buffer().contains("ABI 2"));
    }

    #[test]
    fn other_backends_are_left_alone() {
        for containment in [ContainmentBackend::Lxc, ContainmentBackend::Landlock] {
            let request = ExecutionRequest {
                containment: containment.clone(),
                process_intent: true,
                ..Default::default()
            };
            let mut logger = Logger::new(Mode::Buffer);
            let selected = select_with(
                &request,
                &mut logger,
                || panic!("probed"),
                || panic!("probed"),
            );
            assert_eq!(selected.containment, containment);
        }
    }
}
