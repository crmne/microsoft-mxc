# Issue #1485: PSEC 1.0 direct-egress host-loopback compatibility

> **Audience:** MXC developers
>
> **Status:** Minimal compatibility candidate implemented; Windows host validation pending.

## Reported behavior

[#1485](https://github.com/microsoft/mxc/issues/1485) reports that the same
direct-egress policy works with MXC 0.8 but is rejected before workload launch
with MXC 1.0 on Windows build 26200.9457. The reported host supports PSEC 1.0,
but not PSEC 1.1 or the NetworkIngress support flag. The relevant network
policy excerpt is:

```json
{
  "network": {
    "egress": { "default": "allow" },
    "ingress": {
      "default": "allow",
      "hostLoopback": "allow"
    }
  }
}
```

This excerpt does not configure `runtimeConfig.networkProxy`; it is **not** the
identity-less proxy case. The issue's code fence places the opening brace after
the fence marker; it is restored here for readable JSON.

## What changed

* MXC 0.8 serialized `hostLoopback: "allow"` using the `networkLoopback`
  capability and `MXC-Loopback` peer in a PSEC 1.0 payload. That mapping could
  provide connectivity: [#1080](https://github.com/microsoft/mxc/pull/1080)
  reports live 0.8 tests where container-to-host and host-to-container
  connections worked with `allow` and were blocked with `deny`.
* [#1076](https://github.com/microsoft/mxc/pull/1076) added a native PSEC 1.1
  ingress table with independent `default_action` and `host_loopback` controls.
  [#1080](https://github.com/microsoft/mxc/pull/1080), merged September 10,
  2026, made direct-egress host-loopback allow require both PSEC 1.1 and the
  NetworkIngress support flag. It rejects the policy if either is absent rather
  than silently dropping ingress enforcement or choosing an incapable fallback.
  This change was already present in the September 28 `v0.9.0` tag, before the
  October 6 `v1.0.0` tag. PSEC 1.0 remains usable for compatible policies.
* [#1406](https://github.com/microsoft/mxc/pull/1406) added a **separate,
  narrower** PSEC 1.0-only workaround for an explicitly configured,
  identity-less `runtimeConfig.networkProxy` with `hostLoopback: "allow"`.
  It does not apply to the direct-egress policy above, and its merge commit is
  not in the tagged `v1.0.0` release. The
  [ProcessContainer networking guide](../../backends/process-container/networking.md)
  also documents an unresolved host-to-container limitation for proxy mode;
  switching to a proxy is not an equivalent restoration of direct egress.
* This branch adds a candidate PSEC 1.0-only compatibility path for the
  allow-all direct-egress posture above, without a proxy, proxy peer, or
  egress rules. It selects the 1.0 payload and restores `networkLoopback`
  alongside the existing `MXC-Loopback` peer. It does not change the PSEC 1.1
  ingress path or permit other direct-egress host-loopback policies on 1.0.

For the current selection and serialization paths, see
[`BaseContainerRunner::can_backend_service_request`](../../../src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs),
[`BaseContainerRunner::choose_min_required_psec_version_for_request`](../../../src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs),
[`build_psec_v1_network_policy`](../../../src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs),
and the [PSEC FlatBuffer contract](../../../external/windows-sdk/ProcessSecurityEnvironment.fbs).
The [fallback detector](../../../src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs)
rejects host-loopback allow when BaseContainer cannot service it.

**Interpretation:** This is a deliberate loss of support for *direct-egress
host-loopback allow on PSEC 1.0-only hosts*, not a general retirement of PSEC
1.0 and not a JSON syntax change. The old mapping's reported connectivity
does not, by itself, prove that it enforces the entire requested policy on
the affected Windows host. Conversely, the introduction of an explicit
PSEC 1.1 ingress table does not prove that PSEC 1.0 could never provide
bidirectional loopback connectivity.

## VM validation before deciding on a fix

1. On the affected VM, record the Windows build, the exact MXC binary/version,
   whether the PSEC API is available, the results of the PSEC 1.0 and 1.1
   version queries, and the NetworkIngress support flag. Keep 0.8 and 1.0
   binaries and their request formats separate; do not attribute a request
   parsing failure to the runtime capability gate.
2. Reproduce the original policy on that same host: check whether 0.8 actually
   launches and connects in **both** directions, whether tagged 1.0.0
   rejects before launch, and whether a build from this branch connects in
   **both** directions with a PSEC 1.0 payload. Test
   explicit `hostLoopback: "deny"` and omitted host loopback as negative
   controls; a timeout or unrelated launch failure is not evidence of
   enforcement.
3. Exercise the PSEC 1.0 capability/peer mapping with direct egress on the
   affected build, including allowed and denied destination rules, both
   loopback directions, and unrelated private/public endpoints. Verify the
   intended isolation boundary, not merely one successful HTTP request.
   Compare with a host advertising PSEC 1.1 **and** NetworkIngress where
   possible. Do not infer support from PSEC 1.1 version availability alone.
4. The existing
   [`run_processcontainer_network_loopback_test.ps1`](../../../tests/scripts/run_processcontainer_network_loopback_test.ps1)
   can be run with `-RequireTier base-container` as documented in
   [`tests/scripts/README.md`](../../../tests/scripts/README.md). On a PSEC 1.0
   host, it requires a successful fetch when the host probe identifies
   PSEC 1.0-only proxy compatibility. It checks the container-to-host
   loopback path; add or perform a separate host-to-container check before
   claiming the bidirectional contract is met.
5. Verify that a build from this branch still rejects other direct-egress
   host-loopback postures on PSEC 1.0-only hosts and rejects all such requests
   on PSEC 1.1+ hosts without NetworkIngress. Failed version/support queries
   and AppContainer fallback must remain fail-closed. If the old mapping
   cannot enforce the complete policy, do not ship this compatibility path.

**Recommendation:** Treat this implementation as a candidate for VM validation,
not evidence of enforcement on the affected host. Tagged 1.0.0 is already
published; if full enforcement is verified, ship a subsequent 1.0.x release
rather than changing the released artifact. No VM validation is claimed here.
