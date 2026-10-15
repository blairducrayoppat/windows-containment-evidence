# MXC `deniedPaths` inside a read-write tree: are write attempts into the denied subtree refused? 2026-10-15

One launcher, Windows 26200.9711, three runs on the tier this build selects (Tier 1, `base-container`), Bitdefender present, elevated. One further attempt is a named non-result.

## Question

With a policy whose `filesystem.readwritePaths` is a tree `T` and whose `filesystem.deniedPaths` is the subtree `T\sub` inside it, are write attempts from inside the container into `T\sub` refused, while writes inside `T` but outside `T\sub` succeed? And which tier did the launcher select on this build, since the vendor documents different enforcement mechanisms for different tiers?

## Result in one paragraph

On this build the launcher selected Tier 1 (`base-container`); `--probe` reported `baseContainerSupportsDenyPaths` true and no DACL augmentation needed, for the signed v1.0.0 launcher and for the second launcher that was probed (see Conditions). In each of 3 launched runs, a create-file, an open of the marker for append, a rename, a delete and a create-directory inside `T\sub`, each attempted from inside the container, was refused with Win32 error 5 (access denied): 15 of 15 attempts, 0 landed. The host-side comparison of `T\sub` before and after (names, sizes, sha256 of every file, directories, attributes, file write times, alternate data streams) found no change in any run, and the container's report agreed with the host in every run. Writes inside `T` outside `T\sub` (create a file, append to the marker) landed in 3 of 3 runs, confirmed on the host. A read of the marker and a listing of `T\sub` from inside the container were also refused with error 5, 3 of 3 each. The same five write attempts from an unconfined process on the same account against a fresh tree all landed (1 run, 5 of 5; the host comparison found 6 entries changed). The `icacls` captures of `T\sub` taken before, during (while the container process was running) and after each run were identical to one another, held 5 allow entries each (all inherited) and no deny entry, so on this tier the deny was not implemented with a host DENY ACE on `T\sub`. The harness's own verdict, from rules fixed before the run, is HOLD. This is a finding about the Tier 1 deny on this Windows build with this launcher, three runs, Bitdefender present. It is not a claim that MXC's denied paths hold in general, and it says nothing about Tier 2 or Tier 3, where the vendor documents a different mechanism.

## Conditions

| Item | Value |
|---|---|
| Machine | Intel Core Ultra 7 258V laptop, 31.3 GB; AC power, battery 80 %; no GPU or model work |
| Windows | build 26200.9711 (UBR read from the registry; ProductName reads "Windows 10 Pro" as Windows writes it) |
| Elevation | elevated (administrator console), recorded true at the start and at the end of the batch; the harness disables the backup, restore, take-ownership and security privileges of the launching token and reads it back (all four disabled; SeDebug, SeChangeNotify, SeImpersonate and SeCreateGlobal stayed enabled, before and after) |
| Launcher used for every launch | Microsoft-signed `wxc-exec`, sha256 `aa444c0fc4b7f155fd8631068ffafb453d71d8b47fc47d417a74c9545a344031`, Authenticode Valid (CN=Microsoft Corporation); the launcher prints no version, so the tag v1.0.0 is the operator's designation |
| Launcher probed only | `wxc-exec`, sha256 `e951922beec5ad5f0ba967e398763640c3b24c96cbf97f2d198174a949e5f8cc`, NotSigned. It has the same file hash as the arm B launcher of `evidence/2026-10-15-mxc-proxy-egress/`, whose README states it was built from microsoft/mxc commit `525d0f25763b2edaab56e29651fb7c12c4cbbd93`; this batch's header does not record a commit. It was never used to launch. |
| `--probe` | both: tier `base-container`, `needsDaclAugmentation` false, `baseContainerSupportsDenyPaths` true; the two outputs differ in other fields (full output in `header.json`). The harness field `fs_deny_advertised` is true; it is read from `baseContainerSupportsDenyPaths`. A reviewer checked that this flag faithfully reports the OS capability against source for the main build only; for v1.0.0 it was inferred from documentation. |
| Tier per run | `--dry-run` selected `base-container` and the launcher's own log says `selected isolation tier: base-container`, 3 of 3 runs |
| PSEC version | `--probe` prints no PSEC field. The launcher's own log of every launch (the 3 runs and the smoke launch, 4 of 4) logged `process security environment spec built (PSEC 1.0, 312 bytes)` (the raw log lines carry interleaved timestamp prefixes; strip them to read it). It also logged `enforcement_mode` `capabilities` and `firewall_rules_created` 0. |
| Host preparation | `wxc-host-prep` not invoked |
| Tree | a fresh directory per run on the local fixed NTFS volume C: (not OneDrive, not a share, outside every repository), created by the harness with marker files and removed after the launch. In these records the tree root appears as `~\mxc-fx`; the raw runs created it at `C:\mxc-fx` (the harness's `TREE_ROOT` constant, kept as it ran), which the sanitiser was told to write as `~\mxc-fx`. |
| Policy (`fx-a`) | `readwritePaths` [T], `deniedPaths` [T\sub], `readonlyPaths` [toolchain, payload], a distinct `containerId` per run (3 distinct), `fallback.allowDaclMutation` not present in the submitted policy (the launcher's default), `captureDenials.mode` block, `network.egress.default` deny, `ingress.default` deny, `hostLoopback` deny, no proxy, UI lockdown off (`ui.disable` false, clipboard none, injection false), policy `version` 1.0.0. The policy is in each `launch-fx-a-r<n>.json`. |
| Container interpreter | Python 3.14 from a throwaway toolchain copy, sha256 `cce21c0e8710e304273e98ac4b2b0f5aceb639acbcd2343cbaa5c4e81619c45b` (the same file hash as the host interpreter) |
| Security software | Bitdefender present: 14 Bitdefender-named processes at the start and at the end of the batch (`bdagent`, `bdntwrk`, `bdredline`, `bdservicehost`, `bduserhost`, `updatesrv`); Security Center listed Windows Defender, a stale McAfee entry and Bitdefender Antivirus (version build 162 of 30.0.33; the gate refuses a four-part dotted number, so it is written this way here and in `header.json`). Its absence was not measured for this case. |
| Harness | `tools/probes/mxc-denied-subtree/` as it ran (commit `b1cb40e3` of the private repository), after five pre-run review rounds (FAIL, FAIL, PASS, FAIL, PASS), approved by an independent non-elevated reviewer by the sha256 of all eight files and started through `launch.ps1`, which refuses unless every file matches the approved list. The sanitiser changed no byte of the harness, so the sha256 values in `tools/probes/mxc-denied-subtree/` equal the approved ones (`run_probe.py` `0c158d164a477a3f975bce182e1fd5c5714c0a3c4d4c99b3ab2d22a6db3b76b9`, `launch.ps1` `681bfeeb7bc78c5d131fd0529753b4bf2fde6df0de85c602f1d17245eb63d867`). |
| When (UTC-4) | 2026-10-15, batch 18:34:08 to 18:34:19; runs 18:34:11.8, 18:34:14.5 and 18:34:17.2 |

## Method

Order in the batch: S4 (the unconfined control, once); a smoke launch of the container's Python under the measured policy shape (imports `ctypes`, `_winapi`, `ctypes.wintypes`, the payload and lists a directory; 5 of 5 steps ok); then 3 runs of `fx-a`, each a separate launcher invocation preceded by `--dry-run`. Per run, from inside the container:

| State | What | Judged from |
|---|---|---|
| S0 | the tier and whether native deny is advertised, before any write | `--probe` output, `--dry-run`, the launcher's log |
| S1 (control) | create a file and append to the marker inside `T` outside `T\sub` | the container's Win32 result and the host's check of the file |
| S2 (the question) | five write attempts into `T\sub`: create a file, open the marker with an append-only handle, rename a file, delete a file, create a directory; each a Win32 call with its error code recorded | the host comparison of `T\sub` before and after; the container report never decides |
| S3 (read side) | a read of the marker and a listing of `T\sub` | the container's Win32 result (recorded, not the question) |
| S4 (control) | the same five attempts from an unconfined process on the same account against a fresh tree | the host comparison |
| ACL captures | `icacls` and the security descriptor of `T\sub` and of `T`, before the launch, during it (a host thread, after the go signal to the container was written, with the container process running at the capture) and after | counts and ACE types |

HOLD needs the host comparison to show no change, every S2 attempt refused with error 5, and S1 and S4 as expected. Any change inside `T\sub` is FAIL, whether or not an attempt explains it. The rules for the other verdicts are in `tools/probes/mxc-denied-subtree/summarise.py`.

## Results (n = 3 runs)

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `--dry-run` accepts / launch exit code | 0 / 0 | 0 / 0 | 0 / 0 |
| S1: create and append inside `T` outside `T\sub` landed (host-confirmed) | 2 of 2 | 2 of 2 | 2 of 2 |
| S2: attempts refused with Win32 error 5 | 5 of 5 | 5 of 5 | 5 of 5 |
| S2: attempts that landed / entries changed in `T\sub` by the host comparison | 0 / 0 | 0 / 0 | 0 / 0 |
| container report disagrees with the host comparison | 0 | 0 | 0 |
| S3: read of the marker refused (5) / listing of `T\sub` refused (5) | yes / yes | yes / yes | yes / yes |
| `T\sub` ACL captures (before, during, after): entries; of which inherited; deny | 5, 5, 5; 5, 5, 5; 0, 0, 0 | same | same |
| `T\sub` ACL text and security descriptor identical before, during, after | yes | yes | yes |
| `T` ACL captures: entries; deny | 5, 5, 5; 0, 0, 0 | same | same |
| host state changed by the run (sandbox registry mappings, MXC state directory) | none | none | none |
| launcher `captureDenials` `totalDenials` (stderr of the launch) | 9 | 9 | 9 |
| run wall time, dry-run to cleanup | 2.744 s | 2.648 s | 2.649 s |
| run verdict | HOLD | HOLD | HOLD |

Batch verdict HOLD. S4, 1 run: 5 of 5 attempts landed, 6 entries changed in the unconfined tree, the unconfined read and listing succeeded, cleanup removed the tree. The ACL entries counted are those `icacls` prints (5 per capture, all inherited allow entries) and the 5 ACEs of the security descriptor (all of ACE type `A`, allow); no capture of `T\sub` or of `T`, in any run, held a deny entry (18 captures of `T\sub` and `T`: 0 with a deny entry). The sandbox registry mapping count was 218 at the start and at the end and the MXC state directory was empty at both. The launcher's `totalDenials` of 9 was not reconciled with the 7 refused operations the payload recorded (5 write attempts and 2 reads) and is recorded as observed.

**Re-count.** Every reported figure was recomputed from the sanitised files by a script that reads the run records and logs (467 values: the per-run results above, the S0 and probe fields, the ACL counts and ACE types, the log-derived PSEC, tier and enforcement-mode fields, the S4 and smoke results, the header fields and the summary) and compared with the same recount over the raw folder: 0 differences (tabulated in `PROVENANCE.md`).

## Named non-result: `run-20261015-1` (LAUNCH-FAILED, not evidence)

An earlier attempt (batch started 16:16:45) had `ui.disable` true in the policy. The container's Python failed at `import ctypes` (`ImportError: DLL load failed while importing _ctypes`, launch exit code 1), so the payload produced no report and no write into `T\sub` was attempted; its only counted landing is the unconfined control (5 of 5 landed). The harness then gained the smoke launch and the policy was run with `ui.disable` false, clipboard none, injection false; the smoke launch imported `ctypes`. The harness changed between the two attempts as well as the UI setting, so the UI setting is the recorded difference and not an isolated cause. This folder does not contain that attempt's records.

## Not measured

Tier 2/3 (AppContainer, host DENY ACEs): this build selected Tier 1, so the mechanism the vendor documents for those tiers was not exercised, and the result says nothing about it; any launcher build other than the signed v1.0.0 for the measured runs (the second launcher was probed only); a machine without Bitdefender; a non-elevated launch; UI lockdown on (with it on, the container's Python could not load `ctypes` in the first attempt); moving a file into `T\sub`; renaming `T\sub` itself; writes to alternate data streams; other path spellings (8.3 names, letter case, trailing dot, long-path prefixes); a denied path that is a reparse point, junction or symlink, or on another volume; per-entry ACL changes, timestamp-only changes and the archive bit inside `T\sub` (the host comparison covers names, sizes, hashes, attributes, file write times and alternate data streams); the `allowDaclMutation` false variant (it applies only on Tier 2/3 and was not run); the `enumeratePaths` field; `captureDenials` allow; concurrent runs sharing a `containerId`; the session-isolation and WSLc backends; nono under MXC; anything about any fork; how the OS enforced the deny on Tier 1 (no kernel-level evidence was taken); variance beyond three runs within about eight seconds on one machine (a repeat, not a distribution). The vendor documentation was not re-read for this record and is not quoted: read it live, at a pinned commit, before quoting it.

## What is in the folder

| Path | What |
|---|---|
| `runs/run-20261015-2/header.json` | launchers (sha256, signature, full `--probe` output), both S0 results, volume, interpreters, machine conditions, security software, token privileges, MXC state directory listing before and after |
| `runs/run-20261015-2/launch-fx-a-r<n>.json` | the three runs: policy as submitted, dry-run output, launch exit code and stderr tail, container report, host tree snapshots before and after, ACL captures before, during and after, state diff, cleanup proof, verdict inputs |
| `runs/run-20261015-2/launch-s4-r1.json`, `launch-smoke-r1.json` | the unconfined control and the smoke launch |
| `runs/run-20261015-2/mxc-*.log` | the launcher's own log for each of the four launches. Kept because it is the launcher's account of the run. |
| `runs/run-20261015-2/summary.json` | the harness summary and verdict |
| `runs/run-20261015-2/.sanitized` | replacement counts per file and rule (never an original value) |
| `tools/probes/mxc-denied-subtree/` | the harness as it ran |

## How to re-run

Needs Windows with a `wxc-exec` launcher, a Python for the container (a throwaway copy of a toolchain), and an elevated console. The launcher script checks every probe file's sha256 against an approved list you write yourself (`<sha256>  <filename>` per line in `APPROVED_SHA256.txt` in your raw-data folder); files here are the bytes that ran, with the line endings they had in the working copy (CRLF for seven files, LF for `smoke_payload.py`), so keep them byte for byte if you want the approved hashes above to match. `run_probe.py --dry-only` creates each tree, validates each policy with `--dry-run` and launches nothing. Raw records go to a folder you choose outside any git tree. The self-test was not run for this record and the batch was not run from this copy; the harness's later open items (the verdict wording for a FAIL made only of unattributed changes, a 300 s timeout on a signature check, the non-elevated runner's exit code) are not fixed in this copy. Run it on a machine you can afford to change.
