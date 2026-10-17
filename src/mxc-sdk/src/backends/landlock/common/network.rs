// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The network postures Landlock can enforce, and the ones it refuses.
//!
//! The workload runs in the host's network namespace. Landlock (from ABI 4)
//! restricts TCP `bind` and `connect` by port only, and the seccomp filter
//! decides which socket families may exist at all. Neither can tell one
//! address from another, so the backend has exactly two postures:
//!
//! - **Isolated**: no network socket can be created, and on ABI 4 and newer
//!   Landlock also refuses every TCP `bind` and `connect`. This is the default
//!   deny. It is stricter than Bubblewrap's, which keeps a loopback of its own:
//!   the host's loopback is the only one a Landlock sandbox could use.
//! - **Host network**: no network restriction at all. Only a policy that
//!   allows all of it gets this: outbound by default, inbound by default, and
//!   the host's loopback.
//!
//! Anything in between (address rules, a proxy as the only way out, outbound
//! access with the host's loopback or inbound connections denied) needs an
//! address-aware filter, so it is refused rather than widened.

use crate::mxc_common::models::{ExecutionRequest, NetworkAction};

/// What the workload's sockets may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPosture {
    /// No network sockets.
    Isolated,
    /// The host's network, unrestricted.
    HostNetwork,
}

/// Explains every posture Landlock cannot hold.
const ADDRESS_FILTER_NEEDED: &str = "Landlock runs the workload in the host's network \
     namespace and cannot tell one address from another, so it can either deny the network \
     or allow all of it, the host's loopback included. Use network.egress.default='deny', \
     allow everything (network.egress.default='allow' with network.ingress.default='allow' \
     and network.ingress.hostLoopback='allow'), or use the Bubblewrap backend.";

/// Choose the posture for `request`, or refuse it.
pub fn posture(request: &ExecutionRequest) -> Result<NetworkPosture, String> {
    let policy = &request.policy;
    if policy.network_proxy.is_enabled() {
        return Err(format!(
            "Landlock: runtimeConfig.networkProxy is not supported. Proxy-only egress needs \
             every address but the proxy closed. {ADDRESS_FILTER_NEEDED}"
        ));
    }
    let egress = policy.network_egress.as_ref();
    if egress.is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty()) {
        return Err(format!(
            "Landlock: network.egress allow and deny rules are not supported. \
             {ADDRESS_FILTER_NEEDED}"
        ));
    }
    let egress_allowed = egress.is_some_and(|egress| egress.default == NetworkAction::Allow);
    let (ingress_allowed, loopback_allowed) =
        policy
            .network_ingress
            .as_ref()
            .map_or((false, false), |ingress| {
                (
                    ingress.default == NetworkAction::Allow,
                    ingress.host_loopback == NetworkAction::Allow,
                )
            });

    match (egress_allowed, ingress_allowed, loopback_allowed) {
        (false, false, false) => Ok(NetworkPosture::Isolated),
        (true, true, true) => Ok(NetworkPosture::HostNetwork),
        (true, _, _) => Err(format!(
            "Landlock: network.egress.default='allow' with inbound connections or the host's \
             loopback denied is not supported. {ADDRESS_FILTER_NEEDED}"
        )),
        (false, _, _) => Err(format!(
            "Landlock: inbound connections or the host's loopback cannot be allowed while \
             outbound traffic is denied. {ADDRESS_FILTER_NEEDED}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule, ProxyAddress, ProxyConfig,
    };

    fn request(
        egress: Option<NetworkAction>,
        ingress: Option<(NetworkAction, NetworkAction)>,
    ) -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = egress.map(|default| NetworkEgressPolicy {
            default,
            ..Default::default()
        });
        request.policy.network_ingress =
            ingress.map(|(default, host_loopback)| NetworkIngressPolicy {
                default,
                host_loopback,
            });
        request
    }

    #[test]
    fn no_network_policy_and_an_explicit_deny_are_isolated() {
        assert_eq!(posture(&request(None, None)), Ok(NetworkPosture::Isolated));
        assert_eq!(
            posture(&request(
                Some(NetworkAction::Deny),
                Some((NetworkAction::Deny, NetworkAction::Deny))
            )),
            Ok(NetworkPosture::Isolated)
        );
    }

    #[test]
    fn only_allowing_everything_gets_the_host_network() {
        use NetworkAction::{Allow, Deny};
        assert_eq!(
            posture(&request(Some(Allow), Some((Allow, Allow)))),
            Ok(NetworkPosture::HostNetwork)
        );
        // The default outbound posture keeps the host's loopback denied, which
        // the host's own network namespace cannot.
        for ingress in [
            None,
            Some((Deny, Deny)),
            Some((Allow, Deny)),
            Some((Deny, Allow)),
        ] {
            let error = posture(&request(Some(Allow), ingress)).unwrap_err();
            assert!(error.contains("loopback"), "{error}");
        }
    }

    #[test]
    fn inbound_access_without_outbound_is_refused() {
        use NetworkAction::{Allow, Deny};
        assert!(posture(&request(Some(Deny), Some((Allow, Deny)))).is_err());
        assert!(posture(&request(None, Some((Deny, Allow)))).is_err());
    }

    #[test]
    fn address_rules_and_proxies_are_refused() {
        let mut ruled = request(Some(NetworkAction::Deny), None);
        if let Some(egress) = ruled.policy.network_egress.as_mut() {
            egress.allow.push(NetworkRule::default());
        }
        assert!(posture(&ruled).unwrap_err().contains("rules"));

        let mut proxied = request(Some(NetworkAction::Deny), None);
        proxied.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://127.0.0.1:3128",
                "127.0.0.1".to_string(),
                3128,
            )),
        };
        assert!(proxied.policy.network_proxy.is_enabled());
        assert!(posture(&proxied).unwrap_err().contains("networkProxy"));
    }
}
