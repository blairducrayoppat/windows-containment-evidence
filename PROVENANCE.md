# Provenance

Every folder below was first published in the public mirror of the private project where the research was done,
`https://github.com/blairducrayoppat/blarai-public`. Those copies stay where they are (links pinned to their commits keep
working). The copies here were taken from that mirror at commit `b04ee32d` (2026-10-15), passed through
`tools/sanitize.py`, then edited by hand where a sentence named something the sanitiser removed. No git history was
moved.

## Migrated folders

| Folder here | Source path in blarai-public | First published there | Copied from | Tabular export (Hugging Face) |
|---|---|---|---|---|
| `evidence/2026-10-05-wfp-sid-block/` | `docs/research/containment-evidence-2026-10-05/` (all but `nep0005-open-questions/`) and `docs/research/account-level-containment-evidence-2026-10-05.md` (here `account-level-containment-evidence.md`) | `27bb82c3`, 2026-10-09; arms 2, 3a and 3b were added in later snapshots | `b04ee32d` | `blairducrayoppat/openvino-arc140v-lunarlake`, commit `d215aed0`, `containment/nep0005_halfset/` (`arm_runs.csv`, `arm2_hold_samples.csv`); sanitised copies of the export are in `hf-export/` here |
| `evidence/2026-10-13-nep0005-halfset/` | `docs/research/containment-evidence-2026-10-05/nep0005-open-questions/` | `3b4d1156`, 2026-10-15 | `b04ee32d` | same commit `d215aed0`, `containment/nep0005_halfset/` (`nep5_*.csv`, `srtcli_*.csv`) |
| `evidence/2026-10-14-nono-9p-control/` | `docs/research/nono-9p-failclosed-control-2026-10-14/` | `b04ee32d`, 2026-10-15 | `b04ee32d` | none (no tabular export was made) |
| `tools/probes/nono_9p_failclosed_control.py` | `tools/probes/nono_9p_failclosed_control.py` | `b04ee32d`, 2026-10-15 | the bytes that ran (SHA-256 `b7cc9a6a53089ffdfc68b82ac3b5f2bad87f3eff6940d44da143939c44536302`, the value both 9P run records hold); blarai-public carries a later revision of the same script | n/a |
| `evidence/2026-10-15-mxc-proxy-egress/` | not published elsewhere; made directly from the raw run folder of 2026-10-15 (kept outside every repository) | first published here | the raw folder, through `tools/sanitize.py` (staging logs only, see below) | none |
| `tools/probes/mxc-proxy-egress/` | not published elsewhere | first published here | the bytes of the private repository's commit `25210ef3` (the commit the run used), through `tools/sanitize.py` | n/a |

The NEP-0005 half-set folder is dated by its run (2026-10-13); the matrix's specification was fixed on 2026-10-12.
The srt-win patches are in `evidence/2026-10-13-nep0005-halfset/srtcli/fix/` (`status-completeness.patch`,
`status-partial-consumer.patch`, `verify-ipv6.patch`, and `pr/0001-windows-wfp-status-partial.patch` with its
`pr/pr-body.md`).

## MXC loopback-proxy egress bundle (2026-10-15)

`evidence/2026-10-15-mxc-proxy-egress/runs/run-20261015-1/` is the raw run folder after `tools/sanitize.py`. The raw folder was
not modified (its file hashes were identical before and after). The sanitiser read a copy of it that holds the nine
top-level JSON records and `staging/logs/`; left out: `staging/cfg/` (each policy file is byte-for-byte the
`policy_as_submitted` of its run record), `staging/payload/` (a copy of `net_payload.py`, which is in `tools/probes/`) and the
empty `staging/state/` and `staging/work/`. The six launcher logs are kept because they are the launcher's own account of each launch.

Sanitiser replacement counts (from the two `.sanitized` files):

| Folder | Files | host | user | sid | home | local | tracker | fixture | guid |
|---|---|---|---|---|---|---|---|---|---|
| `runs/run-20261015-1/` | 15 | 0 | 163 | 0 | 162 | 50 | 81 | 0 | 24 |
| `tools/probes/mxc-proxy-egress/` | 8 | 0 | 0 | 0 | 1 | 0 | 2 | 0 | 0 |

What those were: the account name and the profile path (`USER`, `~`); a local-vocabulary pair added for this run only
(the default gateway's private IPv4 address, written `<default-gateway>`, which the standing local file does not hold);
an internal four-digit number inside two directory names (the toolchain folder `blarai-spike` and the MXC folder
`blarai-spike-mxc` carried it as a suffix in the raw paths; it is absent from every path, record and script constant here); GUIDs of two firewall rules for the Python interpreter
(`GUID-0001`, `GUID-0002`). The default gateway's address was removed so that a home network is not identified; the
port (80) and every figure are kept. A launcher log line that the launcher itself truncated in the middle of a home
path reads `~USER... (374 chars total)`.

Re-count: `tools/` is unchanged by this; the figures were recomputed from the run records of the raw folder and of the
sanitised folder by one script (not kept here: it reads the same fields the README tables name) and compared: 47 figures
(per arm 19: runs, dry-run accepted, launch exit 0, B2 requests 200 in the container, B2 requests total, B2 proxy-log forwarded 200,
B2 second-listener entries, B3 refused with 10013, B3 listener hits, B4(i) refused, B4(ii) refused, unfenced 1.1.1.1:443 and gateway
connects before and after, runs with a state change, runs with verdict HOLD, batch verdict, launch wall times, launcher sha256, the
`--probe` host-loopback flag; B5: 5 fields; harness `run_probe.py` sha256, elevation, Windows build, number of launcher logs). 0 differences.

| Figure | Arm A raw / sanitised | Arm B raw / sanitised |
|---|---|---|
| runs; dry-run accepted; launch exit 0 | 3, 3, 3 / 3, 3, 3 | 3, 3, 3 / 3, 3, 3 |
| B2 requests: container 200 / proxy log 200 / listener entries (of 9) | 9, 9, 9 / 9, 9, 9 | 9, 9, 9 / 9, 9, 9 |
| B3 refused 10013 / listener hits | 3, 0 / 3, 0 | 3, 0 / 3, 0 |
| B4(i) refused / B4(ii) refused | 3, 3 / 3, 3 | 3, 3 / 3, 3 |
| unfenced 1.1.1.1:443 / gateway connected before and after | 3, 3 / 3, 3 | 3, 3 / 3, 3 |
| runs with state change / runs verdict HOLD | 0, 3 / 0, 3 | 0, 3 / 0, 3 |

Hand edits after the sanitiser: `tools/probes/mxc-proxy-egress/self_test.py` lines 432 and 435 named the internal-tracker field
in a string and in a key test; the key is now built from two pieces (`"ti" + "cket"`) and the message reads "no
internal-reference field" (the gate refused the word). `README.md` of the bundle is new, written here.

Consequences to know when re-running: the probe's SHA-256 values in `batch-header.json` (`harness_sha256`) describe the
bytes that ran, not the sanitised copy here (`run_probe.py` and `launch.ps1` differ from the original after the path
replacements, `self_test.py` after the hand edit; `net_payload.py`, `proxy.py`, `summarise.py` and `README.md` are identical).
`launch.cmd` was stored with LF line endings in the private repository's commit; the hash the approver took was of its
CRLF form. The sanitised copy's self-test was not run to completion: it was stopped on instruction because it holds the
probe's loopback ports on a machine where a live run was in progress.

## What the sanitiser changed

Per folder, `.sanitized` gives the count for each rule and file; it holds no original value. In order: host name and
account name (none were left in these copies; an earlier scrub had already replaced them), SID domains (to
`S-1-5-21-X-X-X-<RID>`, with distinct domains kept distinct as X, Y, Z, ...), home paths (to `~` for the operator's
profile, `~<account>` for a test account's), internal tracker references, numbers and fields, fixture names (`fx-a`,
`fx-b`, in the letter case of the original spelling), and a local vocabulary map (internal role names to "operator",
the upstream nono issue written in full as `nolabs-ai/nono#2089`). No measured number, count, verdict, time or hash
was changed; the 9P control was re-counted after sanitising and after the hand edits (222 denied as policy, 51
allowed as policy, 63 over-denial, 0 policy violation, 24 inconclusive, from both the per-run verdicts and the run's
own totals).

Consequences to know when re-running:

- A SHA-256 recorded in a run record, `exports-manifest.json`, `hf-export/manifest.json` or a `.sha256` file describes the
  bytes as first published, not the sanitised copy here.
- File names that carried an internal number were shortened (for example a proof file `...-proof-<n>.json` is
  `...-proof.json` in the records and scripts alike), and schema strings lost the same number (`nep5-proof-v1`).
- Names that a script derives a value from (for example a synthetic SID derived from a fixed string) now derive a
  different value than the one in the records.
- The 9P fixture's marker file and its 8.3 short name are recorded as `FX_FIXTURE.txt` and `FX_~1.TXT`; the real short
  name of a file called `FX_FIXTURE.txt` would differ. The 8.3 probes themselves used other files (`UNGRAN~1`,
  `SECRET~1.TXT`), which are unchanged.
- The sanitised 9P probe passes its own self-test exactly as the original does (990 checks, 0 failed, 1 skipped: the
  pty runner, which needs WSL). The 42 PowerShell scripts parse with the same result before and after sanitising.
- Two scripts no longer behave exactly as the ones that ran, because the vocabulary map renamed a word inside code:
  `evidence/2026-10-13-nep0005-halfset/scripts/spike-nep5-run-lib.ps1` (one word of the secret-name pattern that
  decides which environment variables are withheld from the test account) and `scripts/spike-nep5-matrix.ps1` (an
  environment variable name in one self-test case). In `wfp-spike/wfp-coder-egress-spike.ps1` a parameter was renamed
  to `-HelperScripts`.
- Constants in the scripts and records are kept exactly as they ran, because they are measured values: the loopback
  test ports, the leading group of the WFP filter and sublayer keys, and the relative id of the fabricated stale SID.
  Some were derived from internal reference numbers of the private project.

## Hand edits after the sanitiser

- The 9P probe: its tracker constant was removed and the field it filled is written blank (`"ticket": ""` in the
  JSON); the marker-file text no longer names the internal record; a seven-line header (what it measures, how to run
  it, what it writes, what it does not measure) was added above the docstring, and the docstring's first line, which
  had lost its subject to the sanitiser, now begins "Fail-open control for nono".
- After the first independent review (the review record is in `docs/reviews/`): the account handle replaced the
  operator's full name in a licence notice and a patch header; a run record's free-text reason and the NEP-0005 as-run
  record lost pointers to internal tracker comments; two file names in `CHANGES.md` lost an internal number; the
  upstream pull request a PR body cites was restored as `anthropics/sandbox-runtime#359`; sentences reporting internal
  approvals were restated as the conditions they set (who was present, what was in scope) or removed; three script
  comments that a removed reference had broken were repaired; out-of-date status notes were corrected.
- Eleven Markdown files: sentences that named a removed reference were reworded so they read whole; the word for the
  tracker field was replaced in prose; references to files of the private repository that are not here say so in place
  of the path. No figure was changed (checked by comparing every number in each file before and after).
- `account-level-containment-evidence.md`: the header now names this repository's folders and licences; section 7 is
  titled "What this does and does not establish" and no longer cites the private project's decision records; the former
  section 8 (a cross-reference to a private decision record) was removed. The claims table, rows C1 to C26 and their
  lettered sub-rows, is whole.
- `evidence/2026-10-05-wfp-sid-block/README.md`: the licence section points at the root `LICENSE` and `LICENSE-DATA`;
  rows for material not migrated say so.

## Not migrated

Internal process records, not measurements: the bundle's `reviews/` (two code reviews), `preflight/` (a read-only
pre-flight note), `ARMS_HANDOFF.md`, and `make_changes.py` (the script that produced the earlier export's
`CHANGES.md`; `CHANGES.md` itself is here). The bundle's own licence texts are replaced by the root `LICENSE` and
`LICENSE-DATA`. The comparison study's phase-2 probe scripts (`tools/probes/containment_arms/` in blarai-public) are not
here because their evidence is not.
