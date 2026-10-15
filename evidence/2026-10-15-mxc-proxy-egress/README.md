# MXC with `runtimeConfig.networkProxy` pointing at a loopback proxy: accepted or refused, and is non-proxy egress blocked? 2026-10-15

Two launchers, Windows 26200.9711, three runs per state per arm, one elevated batch of about 30 seconds.

## Question

With a policy whose `runtimeConfig.networkProxy` is `http://127.0.0.1:<port>`, no `allowedProxyPeer`, `network.ingress.default` allow, `network.ingress.hostLoopback` allow, `network.egress.default` deny and no egress rules: does the launcher accept the policy, and if it does, is every direct (non-proxy) connect from inside the container refused while a request through the proxy works?

## Result in one paragraph

Both launchers accepted the policy at `--dry-run` 3 of 3 and launched it 3 of 3 (exit code 0). Inside the container a request through the configured proxy to a second loopback listener succeeded in every case (the control: 9 of 9 requests per arm, seen by the container, by the proxy log and by the listener log). A direct connect to that second loopback listener, a connect to the default gateway (port 80) and a connect to 1.1.1.1:443 were each refused with Windows error 10013 in 3 of 3 runs per arm, and the second listener logged no direct hit. From an unconfined process on the same account the same three destinations connected every time (once per batch, and again immediately before and after every launch). The harness's own verdict, from fixed rules written before the run, is HOLD for both arms. This is a finding about these two launchers, with this policy, on this build and this security-software state, three runs each. It is not a claim that MXC is secure.

## Conditions

| Item | Value |
|---|---|
| When | 2026-10-15, 16:07:21 to 16:07:53 local (UTC-4); one batch, arm A runs 1 to 3 then arm B runs 1 to 3 |
| Machine | Intel Core Ultra 7 258V laptop, 31.3 GB; AC power, battery 80 %; no GPU or model work |
| Windows | build 26200.9711 (UBR read from the registry; ProductName reads "Windows 10 Pro" as Windows writes it) |
| Elevation | elevated (administrator console); live runs are launched elevated by the launcher script |
| Priority | harness at BelowNormal |
| Arm A | Microsoft-signed `wxc-exec` v1.0.0, sha256 `aa444c0fc4b7f155fd8631068ffafb453d71d8b47fc47d417a74c9545a344031`, Authenticode Valid (CN=Microsoft Corporation); the launcher prints no version, so the tag is the operator's designation |
| Arm B | `wxc-exec` built from microsoft/mxc commit `525d0f25763b2edaab56e29651fb7c12c4cbbd93` (Rust 1.93, `cargo build --release`, not `--locked`), sha256 `e951922beec5ad5f0ba967e398763640c3b24c96cbf97f2d198174a949e5f8cc`, not signed |
| `--probe` | both: tier `base-container`, `baseContainerSupportsIngressHostLoopbackAllow` true; arm B also `baseContainerSupportsIdentitylessLoopbackProxy` true. Neither prints a version for the ingress contract (the full output is in `runs/run-20261015-1/batch-header.json`). Arm B is only run if that last flag reads true |
| Container interpreter | Python 3.14 from a throwaway toolchain copy, sha256 `cce21c0e8710e304273e98ac4b2b0f5aceb639acbcd2343cbaa5c4e81619c45b` (the same file hash as the host interpreter) |
| Host preparation | `wxc-host-prep` not invoked |
| Security software | Per the operator, Bitdefender was uninstalled on 2026-10-14. During the run Windows Defender real-time protection was on, the Windows firewall was in force (all three profiles enabled), Security Center still listed a stale McAfee entry as the firewall product (`McAfee|266240`), and one Bitdefender remnant service (`bdredline_agent`; the process scan reads `bdredline.exe`) was running. The run was not under a third-party firewall and Bitdefender was not present as a product. |
| Harness | `tools/probes/mxc-proxy-egress/` as it ran (commit `25210ef3` of the private repository; `run_probe.py` sha256 `979c21d546af264702ea9df8ca1f2b9f25ad038d9f1425019c85a1e4aa945879`, recorded in the batch header), started through a launcher that refuses to run unless each probe file matches an approved hash written by an independent non-elevated reviewer after three review rounds |

## Method

Every run is a separate launcher invocation preceded by `--dry-run`. State A1 (arm A, policy fixture `fx-a`) and B1 (arm B, fixture `fx-b`) have identical measured content (the policy is in each run record). Inside the container, per run:

| Probe | What | Judged from |
|---|---|---|
| B2 (instrument control) | three HTTP requests through a stdlib forwarding proxy on `127.0.0.1:18110` to a second loopback listener on `127.0.0.1:18111`; passes only if the container, the proxy log and the listener log all show all three | container report, proxy log, listener log (run tag required) |
| B3 | one direct TCP connect to the second loopback listener, not through the proxy | host-side listener log (run tag required) and the container's error |
| B4(i) | one connect-only attempt to the default gateway on port 80 (a port an unfenced connect reached) | the container's error code |
| B4(ii) | one connect-only attempt to 1.1.1.1:443 | the container's error code |
| B5 (controls) | the same connects from an unconfined process on the same account, once per batch (`control-b5.json`), and the 1.1.1.1:443 and gateway connects again immediately before and after every launch (`unfenced_pre`, `unfenced_post`) | the connect succeeded |

Only Windows error 10013 counts as a refusal; a timeout or any other error blinds the run. No listener is bound on a non-loopback address. Before and after every run the harness snapshots ACL hashes of the granted folders, the sandbox registry mappings, the firewall rules whose program is either interpreter, the firewall profiles, the loopback-exemption list, the WinHTTP proxy and a count of MXC-named WFP filters; any difference stops the batch. The rules for HOLD, FAIL, REFUSED, REFUSED-AT-LAUNCH and INSTRUMENT-BLIND are in `tools/probes/mxc-proxy-egress/summarise.py`.

## Results (n = 3 per state per arm)

| | Arm A, v1.0.0 (A1) | Arm B, main 525d0f25 (B1) |
|---|---|---|
| `--dry-run` accepts the policy ("Dry run completed. Result: validation passed", empty stderr) | 3 of 3 | 3 of 3 |
| Launch exit code 0 | 3 of 3 | 3 of 3 |
| B2: requests through the proxy, container saw 200 / proxy log forwarded 200 / listener logged with run tag | 9 of 9 / 9 of 9 / 9 of 9 | 9 of 9 / 9 of 9 / 9 of 9 |
| B3: direct connect to the second loopback listener refused (10013) / direct hits on that listener | 3 of 3 / 0 | 3 of 3 / 0 |
| B4(i): connect to the default gateway refused (10013) | 3 of 3 | 3 of 3 |
| B4(ii): connect to 1.1.1.1:443 refused (10013) | 3 of 3 | 3 of 3 |
| Unfenced 1.1.1.1:443 connected before and after the launch / unfenced gateway connected before and after | 3 of 3 / 3 of 3 | 3 of 3 / 3 of 3 |
| Runs where the host state snapshot changed | 0 of 3 | 0 of 3 |
| Run verdict HOLD / batch verdict | 3 of 3 / HOLD | 3 of 3 / HOLD |
| Launch wall time | 0.698, 0.453, 0.404 s | 0.387, 0.454, 0.425 s |

B5, once per batch: the second loopback listener, the gateway on port 80 and 1.1.1.1:443 were each reached from the unconfined process (`control-b5.json`, judgement `ok` true). The MXC-named WFP filter count read 0 before and after every run; per review, such a count may read 0 whatever is enforced, so it is recorded and not relied on. In the container `HTTP_PROXY` and `HTTPS_PROXY` (upper case) were set to the proxy endpoint.

**Re-count.** Every figure above was recomputed from the sanitised files in `runs/run-20261015-1/` by a script that reads the run records (not the summary) and compared with the same recount over the raw records: 47 figures, 0 differences (listed in `PROVENANCE.md`).

## Against the earlier record

On 2026-10-11, Windows 26200.9457, elevated, with Bitdefender present, the same signed v1.0.0 launcher rejected the same network and proxy settings at `--dry-run` 3 of 3 (`network.ingress.hostLoopback='allow' is not supported by this version of Windows; host-loopback ingress requires native ProcessContainer support`), and an older main build (`70fc7d52`) accepted a proxy policy and refused direct connects (10013). The earlier probe's records are in the private project's public mirror, in its comparison study folder `docs/research/windows-containment-comparison-2026-10/` (the MXC proxy probe sub-folder). Today `--probe` for v1.0.0 reports `baseContainerSupportsIngressHostLoopbackAllow` true. Between the two records the Windows build (9457 to 9711), the security software (Bitdefender present, then removed), the harness and the proxy port (18099 to 18110) changed. This record does not isolate which change moved the acceptance. All earlier arms of this repository's studies (2026-10-05 to 2026-10-14) ran with Bitdefender present; this one did not.

## Not measured

Any build other than the two run; a non-elevated live run; a host whose `--probe` reports host-loopback ingress unsupported (the 26200.9457 condition); an identity-scoped proxy (`allowedProxyPeer`); the session-isolation backend; UDP, ICMP or DNS egress under the proxy policy; host-to-container ingress (the vendor documentation's own open limitation); nono under MXC; anything about any other sandbox; IPv6; HTTPS or CONNECT through the proxy; destination ports other than those named; the WFP filter list of the container's session; variance beyond three runs per state per arm (a repeat on one machine within half a minute, not a distribution). The vendor documentation says an identity-less proxy "opens both host-loopback directions" and that private-network traffic "remains available in both directions when `ingress.default` is `allow`"; this run did not observe either (B3 and B4(i) were refused), and the documentation was not re-read for this record: re-read it live before quoting this.

## What is in the folder

| Path | What |
|---|---|
| `runs/run-20261015-1/batch-header.json` | launchers (sha256, signature, full `--probe` output), harness file hashes, interpreters, arm B commit, firewall product and profiles, machine conditions |
| `runs/run-20261015-1/run-<arm>-<state>-r<n>-<time>.json` | six run records: policy as submitted, dry-run output and exit code, launch exit code and stdout/stderr tails, payload report, proxy log, listener log, unfenced pre and post, machine conditions, before and after state snapshots, verdict |
| `runs/run-20261015-1/control-b5.json`, `batch-summary.json` | the batch controls and the verdicts |
| `runs/run-20261015-1/staging/logs/*.log` | the launcher's own log for each of the six launches. Kept because it is the launcher's account of the run. |
| `runs/run-20261015-1/.sanitized` | replacement counts per file and rule (never an original value) |
| `tools/probes/mxc-proxy-egress/` | the harness as it ran, sanitised |

Not included from the raw folder: `staging/cfg/` (each policy file is byte-for-byte the `policy_as_submitted` in its run record), `staging/payload/` (a copy of `net_payload.py`, which is in `tools/probes/`), and the empty `staging/state/` and `staging/work/`.

## How to re-run

Needs Windows with the two `wxc-exec` launchers, a Python for the container, and an elevated console. The paths in the probe (`MXC_ROOT`, `TOOLCHAIN`) are constants at the top of `run_probe.py`; edit them for your machine, which changes the file's hash (the launcher script checks hashes against an approved list you write yourself: `<sha256>  <filename>` per line in `APPROVED_SHA256.txt`). `python -I -B self_test.py` runs the self-test without MXC and without elevation; `run_probe.py --dry-run-only` runs `--probe` and `--dry-run` only and changes nothing. A live run is `launch.ps1` from an elevated console (arm B needs `--arm-b-commit <40-hex>` unless its launcher hash is in the harness's table). Each batch needs a fresh output folder. A live run creates and removes per-container ACL grants and may leave the state described in the harness header if interrupted; the snapshot compares before and after. Run it on a machine you can afford to change.

The harness copy here is the one that ran (commit `25210ef3`). Later review fixes made in the private repository (a refusal at launch is only reported when MXC's own log shows no process was created; compiled Python files in the probe folder refuse the start; the override flag for the self-test is honoured only with its environment variable; the commit arguments must be 40 hex; the batch header records the token privileges; single-run batches agree between the harness and the standalone summariser) are not in this copy.
