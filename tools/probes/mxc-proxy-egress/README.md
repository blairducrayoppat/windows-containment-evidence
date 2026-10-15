# MXC loopback-proxy egress probe

What it measures: with `runtimeConfig.networkProxy` set to a loopback proxy the run controls (no `allowedProxyPeer`,
`ingress.default` allow, `ingress.hostLoopback` allow, `egress.default` deny, no egress rules), whether each launcher
accepts the policy, and if so whether non-proxy egress from inside the container is blocked. Launchers: arm A the
signed v1.0.0, arm B a main build (refused unless its `--probe` reports `baseContainerSupportsIdentitylessLoopbackProxy`
true), optional arm B0 an older main build.

Per run (separate launcher invocation, preceded by `--dry-run`): B2 three HTTP requests through a stdlib forwarding
proxy to a second loopback listener (instrument control); B3 a direct connect to that listener; B4(i) a connect-only
attempt to the default gateway on a port an unfenced pre-check reached; B4(ii) a connect-only attempt to 1.1.1.1:443.
B5: the same connects from an unconfined process on the same account, once per batch and again immediately before and
after every launch. B2 and B3 are judged from host-side listener logs (run tag required); B4 from the container's error
code, where only WinError 10013 counts as a refusal. No listener is bound on a non-loopback address.

Verdicts: HOLD, FAIL, REFUSED, REFUSED-AT-LAUNCH, INSTRUMENT-BLIND (rules in `summarise.py`). A B4(i) with no reachable
LAN-peer port is recorded NOT-MEASURABLE and is never a HOLD. On any FAIL the harness prints `STOP: FAIL condition met`
and runs nothing further. Any change in the before/after state snapshot (ACLs, registry mappings, firewall rules for the
two interpreters, firewall profiles, loopback exemptions, WinHTTP proxy, MXC-named WFP filter count when readable) also
stops the batch.

Reading a reach: the policy document states that an identity-less loopback proxy "opens both host-loopback
directions", so a B3 reach is to be read against that text. For B4(i) the networking document says: "Private-network
traffic remains available in both directions when `ingress.default` is `"allow"`", while also saying that on an
enforcing BaseContainer path per-container WFP "blocks direct public and private destinations". The two sentences
disagree about exactly the B4(i) destination. The harness still STOPs on any B3 or B4 reach; the operator reads the
reach against both document sentences before any routing decision.

Elevation: live runs are launched elevated (`launch.ps1` refuses otherwise; `--dry-run-only` may run without it). The
run's elevation is recorded in the batch header and every run record. Each batch needs a fresh output folder. Arm B
needs `--arm-b-commit` (arm B0 `--arm-b0-commit`) unless the launcher's sha256 is in the known-build table.

How to run: `launch.cmd` (or `pwsh -File launch.ps1 [probe args]`); it refuses to start unless the four probe files
match `<sha256>  <filename>` lines in `APPROVED_SHA256.txt` under the research-data folder. `python -I self_test.py`
runs the self-test (no MXC, non-elevated).

Writes: raw records only under the output folder (default `<home>/blarai-research-data/mxc-proxy-egress/run-<date>-<n>`);
a folder inside a git working tree is refused.

Not measured: any build other than the one(s) run; behaviour on a host whose `--probe` reports host-loopback ingress
unsupported (the earlier 26200.9457 condition); an identity-scoped proxy (`allowedProxyPeer`); the session-isolation
backend; UDP, ICMP or DNS egress under the proxy policy; host-to-container ingress (the doc's own open limitation);
nono under MXC; anything about the fork or any other sandbox; IPv6; HTTPS or CONNECT through the proxy.
