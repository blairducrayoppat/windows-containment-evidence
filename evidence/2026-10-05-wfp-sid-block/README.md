# Containment evidence bundle (2026-10-05)

Required Notice: Copyright (c) 2026 blairducrayoppat. Licence of this bundle: the run data, records, claims and write-ups in it are licensed under CC BY 4.0 (LICENSE-DATA at the repository root); the measurement scripts, harness, driver and the srt-win patches are licensed under Apache-2.0 (LICENSE at the repository root), the licence of anthropics/sandbox-runtime, so the patches can be contributed to it. The Apache-2.0 files are the code: the scripts in `wfp-spike/`, `arm1-permit/scripts/`, `arm2-hold/scripts/`, `arm3-persist/scripts/`, `confined-model-spike/as-run/` and `confined-model-spike/post-run-hardened/` and `../2026-10-13-nep0005-halfset/scripts/`, the harness in `../2026-10-13-nep0005-halfset/harness/`, the code in `../2026-10-13-nep0005-halfset/srtcli/` (the driver, its deploy and export scripts, the `fix/*.mjs` test scripts and the srt-win patches `srtcli/fix/*.patch` and `srtcli/fix/pr/*.patch`). Everything else in this bundle is CC BY 4.0. The srt-win patches modify Apache-2.0 code from anthropics/sandbox-runtime (Copyright 2025 Anthropic) and keep its licence.
Companion to
`evidence/2026-10-05-wfp-sid-block/account-level-containment-evidence.md` (read that first: it states what each file does and
does not show).

## What is here

| Folder | Content |
|---|---|
| `wfp-spike/` | the raw Windows Filtering Platform (WFP) block spike: script, its README, console output, 3 result files |
| `confined-model-spike/` | the confined-model spike. `as-run/` = the scripts as they stood after the runs (the results come from these); `post-run-hardened/` = the same scripts after later hardening; `runs/` = Test A (2 runs), Test B (1 run), in-process control |
| `arm1-permit/` | arm 1 (the permit filter's role; the confined account as CLIENT of a real local server over loopback while blocked): `scripts/` = the changed scripts (`README.md` there lists the changes and the run order), `runs/` = the result files |
| `arm2-hold/` | arm 2 (the long hold: does the SID-keyed block stay enforced for up to two hours while Bitdefender runs): `scripts/` = the changed scripts plus the elevated-once wrapper and the sanitised-to-live converter (`README.md` there), `selftest/` = the saved self-test results, `runs/` = the result files (run 2026-10-11) |
| `arm3-persist/` | arm 3 (a persistent filter set, a restart, fail-closed on absence): `DESIGN.md` (written first), `scripts/` (arm 3a, the 3b arming / post-reboot / veto scripts, the rollback proof gate; `README.md` there has the manual rollback), `selftest/`, `runs/` (arm 3a run 2026-10-11, arm 3b 2026-10-12) |
| `preflight/` | read-only pre-flight (account, task, ACL listing, offline suites), 2026-10-05; not included in this repository |
| `reviews/` | review reports behind the negative results; not included in this repository |
| `CHANGES.md`, `make_changes.py` | generated table of what was changed in each file, and the generator (`make_changes.py` is not included in this repository); `as-run/MANIFEST.sha256` pins the as-run set |

## The scripts were changed after the runs

The runs were 15:57 to 16:03 on 2026-10-05; the confined-model scripts were hardened at about 16:44 to 16:50. Use `as-run/` to read what
produced the results (Test A run 1 used an even earlier `spike-run-test.ps1`, now lost; see `CHANGES.md`). `post-run-hardened/` is what to run today. `as-run/MANIFEST.sha256` proves those files are unchanged since it was generated, not their provenance (provenance: first bundle commit `9adcafc4` and the research-data file times in `CHANGES.md`). Text files are stored LF (the originals were CRLF); hashes use LF-normalised bytes, so a CRLF checkout verifies too.

## Sanitising: see `CHANGES.md` for the per-file counts

Only these changes were made: the user name and machine name became `_OPERATOR_` and `_MACHINE_`; the two real machine SID
domains became shape-valid placeholder domains (relative ids kept); JSON files were re-serialised and model text cut to 100
characters. Fabricated test SIDs in the scripts were left alone, so the scripts' own `-SelfTest` runs. Anything else would be
a defect. No password or credential is in any file (the spike password was generated at run time and held only in the
scheduled-task vault).

### NEP-0005 code files: SID constants rewritten after the run (2026-10-13)

Four NEP-0005 code files carry the test account's SID (and, in the harness, one mock SID on the same domain) as recorded constants that their guards compare against. They ran with the real machine domain in those constants; on 2026-10-13 the domain was rewritten to the placeholder `S-1-5-21-X-X-X` in place (relative ids 1271 and 1272 kept), by a script of the private project's repository (not included) over the whole repository. Nothing else in them changed. Because the constants changed, the files no longer hash-equal the reviewed bytes; `../2026-10-13-nep0005-halfset/runs/AS_RUN.md` records both hashes (reviewed and rewritten) for each, and the per-file occurrence counts are in a private review record (not included):
- `../2026-10-13-nep0005-halfset/harness/halfset.rs` (3 occurrences; `harness/tests/refusals.ps1` matches the SID compiled into it, 1)
- `../2026-10-13-nep0005-halfset/scripts/spike-nep5-connect-probe.ps1` (1)
- `../2026-10-13-nep0005-halfset/scripts/spike-nep5-lib.ps1` (2)

The private project's integrity test (not included in this repository) has no per-file exemption: it fails on any machine domain other than the placeholder and fabricated ones, written in the usual text form (`S-1-5-21-` and three numbers, any letter case), in any bundle file. It does not see SIDs written another way (without the prefix, split across lines, or in UTF-16 files); a second private test (not included) catches the bare-digit form of this machine's domain across every tracked file.

## Known gaps in the raw data (read before relying on it)

- `outbound_blocked` in the WFP results is defined by private-helpers `scripts/coder-containment-probe.ps1` (not bundled): it is
  true when the connect does not complete in 5000 ms OR throws, so ANY failure counts as blocked. The in-run baseline and
  post-removal arms are what attribute the block to the filters.
- `secret_reads_denied: true` in the WFP results is vacuous: the probe was sent an empty secret-path list.
- `hold_seconds: 100` is the requested cap; the filters stood for seconds (see the evidence document).

## Run order (elevated, 64-bit; operator present; only on a machine you can reboot)

1. `-SelfTest` of every script (both sets) changes nothing and is run by the bundle test (PowerShell 7 and Windows PowerShell 5.1).
   `spike-wfp.ps1` and `spike-verify-cleanup.ps1` (either set) need `-WfpScript <path to wfp-spike\wfp-coder-egress-spike.ps1>` because their
   defaults name the operator's original folder.
2. WFP spike: `wfp-spike\wfp-coder-egress-spike.ps1 -DryRun`, then `-Live -HoldSeconds 100`. It needs the account `blarai-coder`,
   the task `\BlarAI\BlarAI-Coder-Leg`, and private-helpers `coder-leg-queue.ps1`, `coder-provisioning-lib.ps1`,
   `coder-leg-run.ps1`, `coder-containment-probe.ps1`. None of those are in this bundle.
3. Confined-model spike (needs an OpenVINO GenAI 2026.4 venv and a model directory; set the paths in `spike-lib.ps1`):
   `Run-Spike-AsAdmin.cmd` (provision), `spike-wfp.ps1 -DryRun`, `-TestA`, `-TestB`, then `spike-cleanup.ps1 -DryRun`, `-Apply`,
   `spike-verify-cleanup.ps1` (exit 0 = clean). The operator paths inside the scripts are now `_OPERATOR_` placeholders.
4. Arm 1 (needs the provisioned account and the same venv and model): `arm1-permit\scripts\spike-wfp.ps1 -DryRun [-NoLoopbackPermit]`,
   then `Run-Arm1-AsAdmin.cmd` there (six `-TestC` runs, conditions interleaved), then the cleanup of step 3. See `arm1-permit\scripts\README.md`.

5. Arm 2 (needs the same provisioned account; the task needs the probe-mode `spike-run-test.ps1`): `arm2-hold\scripts\spike-wfp.ps1 -DryRun -HoldSeconds 3600`, then
   `-LongHold` through `Start-ElevatedOnce.ps1` or `Run-Arm2-AsAdmin.cmd`. See `arm2-hold\scripts\README.md`.
6. Arm 3 (machine-wide state; read `arm3-persist\DESIGN.md` first): `arm3-persist\scripts\spike-wfp-persist.ps1 -SelfTest -WriteProof`, `-DryRun`, `-Arm3a`; then, only after
   3a is clean, `spike-arm3b-arm.ps1`. See `arm3-persist\scripts\README.md` for the order, the exit codes and the manual rollback.

Every WFP object of the spikes, arm 1 and arm 2 lives in a dynamic session: closing the engine, killing the operator process or rebooting removes it. Arm 3's objects are
PERSISTENT by design and are removed by key (`spike-wfp-persist.ps1 -Remove`, the 3b post-reboot and veto tasks, the manual snippet in the arm 3 README).

## Integrity gate

The private project's integrity test (not included in this repository) fails if the user or machine name or a real SID domain reappears, if model
text exceeds 100 characters, if `CHANGES.md` disagrees with the files, if the evidence document cites a missing file, has an
incomplete claim row or loses its limits section, or if any bundled script's `-SelfTest` fails.
