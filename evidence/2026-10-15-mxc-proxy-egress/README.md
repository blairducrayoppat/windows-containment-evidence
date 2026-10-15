# MXC with `runtimeConfig.networkProxy` pointing at a loopback proxy: accepted or refused, and is non-proxy egress blocked? 2026-10-15

Two launchers, Windows 26200.9711, three runs per state per arm, two elevated batches under two security-software conditions (condition 1: no third-party suite; condition 2: Bitdefender reinstalled and present). One further attempt is a named non-result.

## Question

With a policy whose `runtimeConfig.networkProxy` is `http://127.0.0.1:<port>`, no `allowedProxyPeer`, `network.ingress.default` allow, `network.ingress.hostLoopback` allow, `network.egress.default` deny and no egress rules: does the launcher accept the policy, and if it does, is every direct (non-proxy) connect from inside the container refused while a request through the proxy works?

## Result in one paragraph

In both conditions the results were identical, run for run. Both launchers accepted the policy at `--dry-run` 3 of 3 and launched it 3 of 3 (exit code 0). Inside the container a request through the configured proxy to a second loopback listener succeeded in every case (the control: 9 of 9 requests per arm, seen by the container, by the proxy log and by the listener log). A direct connect to that second loopback listener, a connect to the default gateway (port 80) and a connect to 1.1.1.1:443 were each refused with Windows error 10013 in 3 of 3 runs per arm, and the second listener logged no direct hit. From an unconfined process on the same account the same three destinations connected every time (once per batch, and again immediately before and after every launch). The harness's own verdict, from fixed rules written before the runs, is HOLD for both arms in both conditions. The proxy policy launched under PSEC 1.1 in all 12 launches (MXC's launch log; both arms, both conditions), so arm B's HOLD says nothing about the PSEC 1.0-only path that main's identity-less proxy support was written for (see Not measured). Only the launch wall times differ visibly (0.387 to 0.698 s in condition 1; 0.566 to 1.864 s in condition 2). This is a finding about these two launchers, with this policy, on this build, in these two security-software states, three runs each per condition. It is not a claim that MXC is secure.

## Conditions

Shared by both batches:

| Item | Value |
|---|---|
| Machine | Intel Core Ultra 7 258V laptop, 31.3 GB; AC power, battery 80 %; no GPU or model work |
| Windows | build 26200.9711 (UBR read from the registry; ProductName reads "Windows 10 Pro" as Windows writes it) |
| Elevation | elevated (administrator console); live runs are launched elevated by the launcher script |
| Priority | harness at BelowNormal |
| Arm A | Microsoft-signed `wxc-exec` v1.0.0, sha256 `aa444c0fc4b7f155fd8631068ffafb453d71d8b47fc47d417a74c9545a344031`, Authenticode Valid (CN=Microsoft Corporation); the launcher prints no version, so the tag is the operator's designation |
| Arm B | `wxc-exec` built from microsoft/mxc commit `525d0f25763b2edaab56e29651fb7c12c4cbbd93` (Rust 1.93, `cargo build --release`, not `--locked`), sha256 `e951922beec5ad5f0ba967e398763640c3b24c96cbf97f2d198174a949e5f8cc`, not signed |
| `--probe` | both: tier `base-container`, `baseContainerSupportsIngressHostLoopbackAllow` true; arm B also `baseContainerSupportsIdentitylessLoopbackProxy` true. Neither prints a PSEC version (full output in each `batch-header.json`); the version a launch used is in the launcher's own log: every one of the 12 launches (both arms, both conditions) logged `process security environment spec built (PSEC 1.1, 432 bytes)` in the launcher's own log (the raw log lines carry interleaved timestamp prefixes; strip them to read it). Arm B is only run if that last flag reads true |
| Container interpreter | Python 3.14 from a throwaway toolchain copy, sha256 `cce21c0e8710e304273e98ac4b2b0f5aceb639acbcd2343cbaa5c4e81619c45b` (the same file hash as the host interpreter) |
| Host preparation | `wxc-host-prep` not invoked |
| Harness | `tools/probes/mxc-proxy-egress/` as it ran in both batches (commit `25210ef3` of the private repository; `run_probe.py` sha256 `979c21d546af264702ea9df8ca1f2b9f25ad038d9f1425019c85a1e4aa945879` and `launch.ps1` sha256 `d94e93d8bb53065c11bc54423802dd10dd311748d80e0a944c02e11c7e635a03` recorded in both batch headers), started through a launcher that refuses to run unless each probe file matches an approved hash written by an independent non-elevated reviewer after three review rounds. Condition 2 was started from a clean detached worktree of that commit; the hash check passed |

The two conditions:

| Item | Condition 1: `runs/run-20261015-1/` | Condition 2: `runs/run-20261015-3/` |
|---|---|---|
| When (UTC-4) | 2026-10-15, 16:07:21 to 16:07:53 | 2026-10-15, 16:43:14 to 16:44:41 |
| Third-party security suite | none. Per the operator: Bitdefender was uninstalled on 2026-10-14, Windows Defender real-time protection was on, and the remnant service was `bdredline_agent`. From the raw record: the Windows firewall profiles were all enabled, Security Center listed a stale McAfee entry as the firewall product (`McAfee|266240`) and the process scan found `bdredline.exe`. Not under a third-party firewall; Bitdefender was not present as a product. | Bitdefender reinstalled and present, its firewall in the default automatic mode (per the operator). Security Center listed `Bitdefender Firewall|266240` (and the stale `McAfee|266240` entry); 14 Bitdefender-named processes ran during the batch (`bdagent`, `bdntwrk`, `bdredline` x2, `bdservicehost` x5, `bduserhost` x4, `updatesrv`). Windows firewall profiles enabled as before. |
| Bitdefender firewall activity | none | per the operator, shortly before the batch the Bitdefender firewall logged "Application allowed to access network" for the host Python to 1.1.1.1:443 TCP and granted it automatically (the unfenced control of the aborted attempt below). That auto-allow is part of this condition. The product was still changing state: the aborted attempt's header (16:30) lists 17 Bitdefender-named processes (the 14 plus `bdvpnapp`, `bdvpnservice` and `bdtrackersnmh`), the batch's (16:43) lists 14. |
| Windows firewall rules for either interpreter | two disabled inbound allow rules for the host Python, unchanged by every run | the same two rules, unchanged by every run |

## Named non-result: `run-20261015-2` (aborted, not evidence)

An earlier attempt at condition 2 (started 16:30:27) passed its hash check and its unfenced control, then stopped on binding 127.0.0.1:18111 (Windows error 10048, address already in use; this error text is from the console output the operator pasted, no raw file records it) because an unrelated self-test of the harness on the same machine held the harness's two loopback ports. No container was launched and no run record exists. It is not in this folder; it is named here so that the sequence is complete. Times in this record are the raw records' timestamps; the status notes kept beside the raw folders give approximate times for the same events. An earlier start from the wrong folder was refused by the hash check before anything ran. After this the harness gained a pre-flight that refuses to start, naming the holder, when its ports are busy (not in the copy here).

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

## Results (n = 3 per state per arm, per condition)

| | Cond. 1, arm A (v1.0.0, A1) | Cond. 1, arm B (main 525d0f25, B1) | Cond. 2, arm A | Cond. 2, arm B |
|---|---|---|---|---|
| `--dry-run` accepts the policy ("Dry run completed. Result: validation passed", empty stderr) | 3 of 3 | 3 of 3 | 3 of 3 | 3 of 3 |
| Launch exit code 0 | 3 of 3 | 3 of 3 | 3 of 3 | 3 of 3 |
| B2: requests through the proxy, container saw 200 / proxy log forwarded 200 / listener logged with run tag | 9/9, 9/9, 9/9 | 9/9, 9/9, 9/9 | 9/9, 9/9, 9/9 | 9/9, 9/9, 9/9 |
| B3: direct connect to the second loopback listener refused (10013) / direct hits on that listener | 3 of 3 / 0 | 3 of 3 / 0 | 3 of 3 / 0 | 3 of 3 / 0 |
| B4(i): connect to the default gateway refused (10013) | 3 of 3 | 3 of 3 | 3 of 3 | 3 of 3 |
| B4(ii): connect to 1.1.1.1:443 refused (10013) | 3 of 3 | 3 of 3 | 3 of 3 | 3 of 3 |
| Unfenced 1.1.1.1:443 connected before and after the launch / unfenced gateway connected before and after | 3/3, 3/3 | 3/3, 3/3 | 3/3, 3/3 | 3/3, 3/3 |
| Runs where the host state snapshot changed | 0 of 3 | 0 of 3 | 0 of 3 | 0 of 3 |
| Run verdict HOLD / batch verdict | 3 of 3 / HOLD | 3 of 3 / HOLD | 3 of 3 / HOLD | 3 of 3 / HOLD |
| Launch wall time | 0.698, 0.453, 0.404 s | 0.387, 0.454, 0.425 s | 1.801, 1.308, 0.566 s | 1.864, 1.260, 0.813 s |

B5, once per batch, in each condition: the second loopback listener, the gateway on port 80 and 1.1.1.1:443 were each reached from the unconfined process (`control-b5.json`, judgement `ok` true). The MXC-named WFP filter count read 0 before and after every run in both conditions; per review, such a count may read 0 whatever is enforced, so it is recorded and not relied on. Observed in the launcher's own log of every launch: `mxc.NetworkPolicyApplied` with `enforcement_mode` `capabilities`, `firewall_rules_created` 0, `firewall_applied` false and `status` success (the same fields as in the 2026-10-11 launches). That is MXC's account of how it enforced; the container's WFP filters were not read here. The snapshot does not include Bitdefender's own firewall rule store, so a change there between runs would not have been seen. In the container `HTTP_PROXY` and `HTTPS_PROXY` (upper case) were set to the proxy endpoint.

**Re-count.** Every figure above was recomputed from the sanitised files of each batch by a script that reads the run records (not the summary) and compared with the same recount over the raw records: 47 figures per batch, 0 differences in both (tabulated in `PROVENANCE.md`).

## Against the earlier record

On 2026-10-11, Windows 26200.9457, elevated, with Bitdefender present, the same signed v1.0.0 launcher rejected the same network and proxy settings at `--dry-run` 3 of 3 (`network.ingress.hostLoopback='allow' is not supported by this version of Windows; host-loopback ingress requires native ProcessContainer support`), and an older main build (`70fc7d52`) accepted a proxy policy and refused direct connects (10013). The earlier probe's records are in the private project's public mirror, in its comparison study folder `docs/research/windows-containment-comparison-2026-10/` (the MXC proxy probe sub-folder). Today `--probe` for v1.0.0 reports `baseContainerSupportsIngressHostLoopbackAllow` true. On the launcher's own logs, every launched run of the 2026-10-11 probe (the older main build `70fc7d52`; 9 launches: 3 with the baseline policy, 232 bytes, and 6 with the proxy policy, 344 bytes) logged `PSEC 1.0` (field `mxc_log_tail` of the raw run records in the public record's `raw/` and `raw-p18100/`); the v1.0.0 launcher was rejected at `--dry-run` then and did not launch; today every one of the 12 launches (both arms, both conditions) logged `process security environment spec built (PSEC 1.1, 432 bytes)` in the launcher's own log (the raw log lines carry interleaved timestamp prefixes; strip them to read it). `--probe` on 26200.9711 reports host-loopback ingress support (`baseContainerSupportsIngressHostLoopbackAllow` true); the proxy policy launched under PSEC 1.1 in all 12 launches (MXC's launch log); the six 2026-10-11 proxy-policy launches on 26200.9457 logged PSEC 1.0 (nine launches in all, three of them the no-proxy baseline); the logged version follows the policy launched, not only the host. A different policy on the same 26200.9711 host logged PSEC 1.0 (312 bytes) in three launches in a separate probe, which is not part of this record. The vendor networking document (microsoft/mxc `docs/backends/process-container/networking.md` lines 125 to 128 at commit `068a78d8392a7e8a4d8df14ba24f3f11cfbc6b76`) says "Direct-egress host-loopback allow requires PSEC 1.1 and the ingress support flag" and that for an identity-less `runtimeConfig.networkProxy` with explicit `hostLoopback: "allow"`, "MXC also supports a compatibility workaround on hosts that support PSEC 1.0 but not 1.1"; the 2026-10-11 v1.0.0 rejection text and the main build's acceptance on that PSEC 1.0 host are consistent with that reading. What caused the change in acceptance is not isolated: the Windows build (9457 to 9711), the harness and the proxy port (18099 to 18110) all changed; Bitdefender (one product, its default mode, one reinstall) is unlikely to be the cause, because acceptance was the same here with it absent and present; its version was not recorded. All earlier arms of this repository's studies (2026-10-05 to 2026-10-14) ran with Bitdefender present. Condition 1 of this record did not; condition 2 did, and the results did not differ.

## Not measured

Any build other than the two run; the PSEC 1.0-only path (the identity-less proxy workaround from microsoft/mxc#1406): the host supports PSEC 1.1 and the proxy policy launched under it, so the workaround path was not taken and arm B did not exercise it, and arm B's HOLD is not evidence about that path; a non-elevated live run; a host whose `--probe` reports host-loopback ingress unsupported (the 26200.9457 condition); an identity-scoped proxy (`allowedProxyPeer`); the session-isolation backend; UDP, ICMP or DNS egress under the proxy policy; host-to-container ingress (the vendor documentation's own open limitation); nono under MXC; anything about any other sandbox; IPv6; HTTPS or CONNECT through the proxy; destination ports other than those named; the container's WFP filters (they were not read; only an MXC-named count and MXC's own log line were taken); variance beyond three runs per state per arm (each batch is a repeat on one machine within about one minute, not a distribution); Bitdefender's own firewall rules and logs (only the operator's statement of one auto-allow event is recorded); any Bitdefender mode other than the default automatic one. The vendor documentation says an identity-less proxy "opens both host-loopback directions" and that private-network traffic "remains available in both directions when `ingress.default` is `allow`"; this run did not observe either (B3 and B4(i) were refused), and the documentation was not re-read for this record: re-read it live before quoting this.

## What is in the folder

| Path | What |
|---|---|
| `runs/run-20261015-1/` (condition 1) and `runs/run-20261015-3/` (condition 2): `batch-header.json` | launchers (sha256, signature, full `--probe` output), harness file hashes, interpreters, arm B commit, firewall product and profiles, machine conditions |
| `run-<arm>-<state>-r<n>-<time>.json` (each folder) | six run records each: policy as submitted, dry-run output and exit code, launch exit code and stdout/stderr tails, payload report, proxy log, listener log, unfenced pre and post, machine conditions, before and after state snapshots, verdict |
| `control-b5.json`, `batch-summary.json` (each folder) | the batch controls and the verdicts |
| `staging/logs/*.log` (each folder) | the launcher's own log for each of the six launches. Kept because it is the launcher's account of the run. |
| `.sanitized` (each folder) | replacement counts per file and rule (never an original value) |
| `tools/probes/mxc-proxy-egress/` | the harness as it ran, sanitised |

Not included from either raw folder: `staging/cfg/` (each policy file is byte-for-byte the `policy_as_submitted` in its run record), `staging/payload/` (a copy of `net_payload.py`, which is in `tools/probes/`), and the empty `staging/state/` and `staging/work/`.

## How to re-run

Needs Windows with the two `wxc-exec` launchers, a Python for the container, and an elevated console. The paths in the probe (`MXC_ROOT`, `TOOLCHAIN`) are constants at the top of `run_probe.py`; edit them for your machine, which changes the file's hash (the launcher script checks hashes against an approved list you write yourself: `<sha256>  <filename>` per line in `APPROVED_SHA256.txt`). `python -I -B self_test.py` runs the self-test without MXC and without elevation, but it binds the live probe ports 127.0.0.1:18110, 18111 and 18113: never run it while a live run may be in progress or pending (it aborted one); `run_probe.py --dry-run-only` runs `--probe` and `--dry-run` only and changes nothing. A live run is `launch.ps1` from an elevated console (arm B needs `--arm-b-commit <40-hex>` unless its launcher hash is in the harness's table). Each batch needs a fresh output folder. A live run creates and removes per-container ACL grants and may leave the state described in the harness header if interrupted; the snapshot compares before and after. Run it on a machine you can afford to change.

The harness copy here is the one that ran (commit `25210ef3`). Later review fixes made in the private repository (a refusal at launch is only reported when MXC's own log shows no process was created; compiled Python files in the probe folder refuse the start; the override flag for the self-test is honoured only with its environment variable; the commit arguments must be 40 hex; the batch header records the token privileges; single-run batches agree between the harness and the standalone summariser) are not in this copy.
