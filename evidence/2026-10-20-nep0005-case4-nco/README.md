# Network Configuration Operators and the WFP engine: does membership let an account add and delete a filter? 2026-10-20

Subject: the Windows Filtering Platform (WFP) engine's access list, as it applies to a member of the local group Network
Configuration Operators (well-known SID `S-1-5-32-556`). This is question Q2 of the NEP-0005 matrix, asked of a delegated
non-administrator. One physical machine (Windows 11 Pro, OS build 26200.9711), two sittings on 2026-10-20.

## Question

Can a member of Network Configuration Operators add a WFP filter to a test sublayer (S2) and delete it again, and does the
answer depend on which token the member's process holds: the filtered token of an ordinary launch, or the full token?

## Result in one paragraph

The outcome differed between the two token states. A member launched the ordinary way (`runas`, a secondary logon) holds a filtered token in which
the group is present but marked use-for-deny-only (elevation type 3, attributes `0x00000010`), and its `FwpmFilterAdd0`
was refused with `0x00000005` (access denied) 4 of 4 times. The first sitting also tried to reach the member's full token
through Windows' elevation prompt, raised from inside the member's own console: no elevated record from that route exists. What happened at the prompt rests only on the operator's typed note in the
first sitting's `-Collect` record (`elevation_refused`), which reads: "Windows elevation prompt from the nco-probe console
offered only the administrator accounts of this machine, with no field to name nco-probe; the operator cancelled it, four
times". No instrument recorded the prompt or the four cancellations. The second sitting reached a token with the group enabled by a different route: a scheduled task
that an administrator created, running as the member whether logged on or not (a batch logon; the record shows no linked
token: elevation type 1, group attributes `0x00000007`, Administrators absent, integrity S-1-16-8448, session 0). On that
token the same `FwpmFilterAdd0` returned `0x00000000` and `FwpmFilterDeleteByKey0` returned `0x00000000`, 3 of 3 times
(filter ids 537392, 537393, 537394, each read back present after the add and absent after the delete), with nothing left
behind. Controls: the operator's own elevated administrator token added and deleted the filter 3 of 3; the operator's
non-elevated token was refused 3 of 3; a separate standard non-administrator account was refused on both calls 3 of 3. The
first sitting alone could not say whether the group-enabled token would succeed ("not established"); the second sitting
measured it, and that reading is replaced here. The records show a difference between two token states; they do not show its cause. The group-enabled token differs
from the filtered token in more than the group's attribute, and these differences moved together in the records:

| In the records | F (filtered, 4 runs) | E route 2 (batch logon, 3 runs) |
|---|---|---|
| Group `S-1-5-32-556` attributes | `0x00000010` (use-for-deny-only) | `0x00000007` (enabled) |
| `elevation.elevated` | false | true |
| Logon type, from the token's groups | `NT AUTHORITY\INTERACTIVE` | `NT AUTHORITY\BATCH` |
| Integrity level | S-1-16-8192 (medium) | S-1-16-8448 (medium-plus) |
| Session | 1 | 0 |
| Elevation type, linked token | 3 (limited), linked token present | 1 (default), none (error 1312) |
| Account | `nco-probe`, relative id 2250 | re-created, relative id 2251 |
| Sitting | first (00:48 to 01:43) | second (09:28 to 11:12); whether the machine restarted in between is not recorded |
| Probe command line | exe path unquoted, with `--wait` | exe path quoted, no `--wait`; launched by a scheduled task |
| Probe-proof instance | sha256 `77f7b126...`, `written_utc` 2026-10-20T04:48:52Z (the first `-Prepare`; also used by S and A) | sha256 `55cf04d2...`, `written_utc` 2026-10-20T13:28:27Z (the second `-Prepare`) |
| Console | a console window (`cmd /k`) | none opened (`RUN_SHEET.md` step 4b) |
| Token privileges | not recorded | not recorded |

No run varied one of these alone, so the records do not say which of them the engine's decision followed. The engine's
access list, read before and after each sitting, carries an entry for the group (`(A;;0x307ff;;;NO)`); that is
consistent with the result, and no run removed it, so it is not shown to be the cause.

The author reads this as not a vulnerability finding; that is a reading, not a result of the runs. The reason: in these
runs the account became a member only because an administrator added it, and could run as a batch job only because an
administrator granted the batch-logon right and created the task, so no step crossed a boundary without administrator
action. One machine, one build.

## Conditions

| Item | Value |
|---|---|
| Machine | one physical Windows 11 Pro laptop, OS build 26200.9711 (`runs/AS_RUN.md`). No other machine or build |
| Security product | Bitdefender present, with two file-level scan exceptions for the driver script (see "Bitdefender" below) |
| Clock | 2026-10-20, -04:00 local. First sitting 00:48 to 01:43; second sitting 09:28 to 11:12. The control records are from 2026-10-19, 16:49 to 16:51 |
| Test account | `nco-probe`, a local account, member of Network Configuration Operators only (plus Users). Relative id 2250 in the first sitting; deleted, then re-created in the second sitting as 2251 |
| Who did what | the operator, at the keyboard, typed every launch line and every password; the account lifecycle (create, enable, add to and remove from the group, delete, delete the profile), and in the second sitting the batch-logon right and the scheduled task (create, run, delete, remove), were his, in Windows' own tools. No script created, enabled, logged on or deleted an account (`SPEC.md`, "What the scripts and their author may and may not do") |
| Filter | one persistent BLOCK filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, weight `0x1000`, in the test sublayer S2 under a test provider, keyed to a stale SID (`S-1-5-21-Y-Y-Y-91763`: a fabricated domain, resolves to no account, so the filter matches no real account and blocks nothing) |
| Engine access list | read with `netsh wfp show security type=engine` at each `-Prepare` and each `-Finish`: identical both times in both sittings; the group's entry `(A;;0x307ff;;;NO)` present |
| Probe | `ncoprobe.exe`, sha256 `4fde1ad6db744fa289b65eb6f639628cd1f04ead6f3b5e6db247fcdc3a0e14d4`, built from `NcoProbe.cs` (LF sha256 `28bc05d5...`), one build for both sittings |
| Driver | `spike-nep5-c4-driver.ps1`, two versions ran (table below) |

## Method

A C# probe (`probe/NcoProbe.cs`, compiled with the .NET Framework compiler already on the machine) reads its own token
(user SID, every group and its attributes, integrity level, elevation type, whether a linked token exists, session), then
makes ONE `FwpmFilterAdd0` into S2, reads the filter back, makes ONE `FwpmFilterDeleteByKey0` on the same key, reads it
back again, and writes one record. It opens the engine in a non-dynamic session, so a filter that a failed delete left
behind would persist and be measured; the administrator driver sweeps by key afterwards. It makes no other WFP call, no
network call and no account, group, task or registry write. It refuses to run without a proof file that the driver writes
for it (hash of the exe and of the source, the constants, a fresh timestamp), and refuses when the stale SID resolves to
an account or when the running account is not the one the condition names.

Conditions, three launches each unless stated:

| Cond | Process | How launched |
|---|---|---|
| F | the member, filtered token | `runas /user:nco-probe`, from the operator's normal console (4 runs) |
| E, route 1 | the member, full token | an elevation request raised from inside the member's own console (4 attempts) |
| E, route 2 | the member, full token | a scheduled task running as the member, whether logged on or not, with highest privileges, after the batch-logon right was granted to the member (3 runs) |
| S | the operator, non-elevated (control) | the operator's normal console |
| A | the operator, elevated (control) | the operator's administrator console |
| N1 | a standard non-administrator account (control) | the half-set matrix's `n1` phase, re-run 2026-10-19 at 16:49 under its approved password design |

The driver's modes ran in this order in each sitting: `-Prepare` (creates S2 and its provider with no filter in them,
reads the engine access list, builds the public folder with its access list and writes the probe proof), the operator's
launches, `-Collect` (validates every record: schema, the probe's hash, the condition, the principal, the clock window,
no duplicates; reads S2 for a filter left behind; invalid records are listed and never counted), `-Finish` (removes the
probe key, the library keys, S2 and the provider by key, then requires a direct sweep to read clean, re-reads the engine
access list, removes the public folder), the operator's part C (remove the member from the group, delete the account, and
in the second sitting delete the task and remove the batch-logon right), then `-PartD` (read-only: the account is
absent, the group is empty, the profile list entry and the profile folder are absent).

### Scripts as they ran

The driver was revised between and during the sittings. Two versions of it ran. Two later revisions (commits `e4383096` and `4ebad95c`, the second of them the copy on the project's main line) never
ran a live mode, so neither is published here; their hashes are in `runs/AS_RUN.md`.

| Published as | Git commit in the private project | Ran | sha256 of the bytes that ran (LF) |
|---|---|---|---|
| `scripts/driver-first-sitting/spike-nep5-c4-driver.ps1` | `1ed25f50` | the whole first sitting (`-Prepare`, `-Collect`, `-Finish`, `-PartD`: `runs/case4-prepare-20261020-004848.json`, the two `-collect-2026102001*` records, `case4-final-20261020-012312.json`, `case4-partd-20261020-014216.json`), and the second sitting's `-Prepare` (`runs/case4-prepare-20261020-092824.json`) | `47fcd179b28f15b6deb9d9bfeb41ee501f7e43ee8824364c2bc757707f6c031a` |
| `scripts/driver-second-sitting-collect/spike-nep5-c4-driver.ps1` | `1881f15d` | the second sitting's `-Collect`, `-Finish` and `-PartD` (the three `-collect-` records, `runs/case4-final-20261020-102928.json`, `runs/case4-partd-20261020-110756.json`); this version accepts a type-1 token with the group enabled as condition E | `4c0b559eb47014c6b69d43573d29cf6af8d5bc0784c9a402ad5a273c7c9e3fdd` |

Both hashes equal the ones `runs/AS_RUN.md` records for the live copies (lines 14 and 81 to 84), checked against the
recovered commits. The probe source (`28bc05d5...`, commit `21cb384d`) and the lock-pattern corpus
(`case4-lock-corpus.json`, `f9830409...`) are the same bytes on the main line and in the sittings. `probe/build-probe.ps1`,
`probe/run-probe-selftest.ps1` and `scripts/run-limited.ps1` have each been changed in one commit only, `fa96f8e7`, and
no run record holds a hash of them; the driver's own proof records them, and that proof is kept in the admin-only folder
and is not published. The two documents `SPEC.md` and `RUN_SHEET.md` and the two `README.md` files are the main line's
text after the sittings (the scripts' README describes the later driver, not the two that ran).

Sanitised copies are not the bytes that ran: see "What was changed in these copies".

## Results

### Per condition

| Cond | n | Elevation type | Group `S-1-5-32-556` | Administrators | Add | Delete | Left behind |
|---|---|---|---|---|---|---|---|
| F (member, filtered) | 4 | 3 (limited), linked token present, integrity medium, session 1 | present, `0x00000010` (use-for-deny-only) | absent | `0x00000005`, 4 of 4 | `0x80320003` (not found: nothing was added), 4 of 4 | none |
| E route 1 (member, prompt) | 4 attempts | no record; the operator's note says the prompt offered only the machine's administrator accounts and no field to name the account, and that he "cancelled" it four times | n/a | n/a | n/a | n/a | n/a |
| E route 2 (member, batch logon) | 3 | 1 (default), no linked token (error 1312), integrity S-1-16-8448, session 0 | present, `0x00000007` (enabled, enabled by default, mandatory) | absent | `0x00000000`, 3 of 3; filter ids 537392, 537393, 537394; each present after the add | `0x00000000`, 3 of 3; each absent after the delete | none |
| S (operator, non-elevated) | 3 | 3 (limited) | absent | present, `0x00000010` | `0x00000005`, 3 of 3 | `0x80320003`, 3 of 3 | none |
| A (operator, elevated) | 3 | 2 (full) | absent | present, `0x0000000F` | `0x00000000`, 3 of 3 | `0x00000000`, 3 of 3 | none |
| N1 (standard account) | 3 | n/a (a matrix phase; its record holds the calls) | n/a | n/a | `0x00000005`, 3 of 3 | `0x00000005`, 3 of 3 | none |

For F and E, `is_expected_account` reads true in every record; for S and A it reads false (the operator's account). Every
record carries the token facts the probe read for itself. The `-Collect` passes list 10 valid and 0 invalid records for
the first sitting (F 4, S 3, A 3) and 3 valid and 0 invalid for the second sitting (E 3). `runs/results-summary.json`
holds the per-record fields in one file.

### What went wrong on the way, and what it changed

- **First sitting, condition E.** The elevation request from the member's own console could not reach the member's full
  token (route 1 above). The operator cancelled four times; the driver counts no record for it. The first sitting
  therefore ended with the group-enabled token unmeasured.
- **First sitting, `-Finish`.** The engine part verified; the removal of the public folder was refused (exit 7: "being
  used by another process") because the operator's consoles were still open in it. The folder was removed by hand at
  01:43 once empty (`runs/case4-final-20261020-012312.json` reads `verified: false`, `code: 7`). `-PartD` at 01:42:16
  read all four items absent (exit 20).
- **Second sitting, `-Collect`.** The first `-Collect` (10:28:24, `runs/case4-collect-20261020-102824.json`) validated the 3
  E records but exited 21 and skipped the engine enumeration, because it read the out dir as not admin-only: a file in it
  was owned by the writing token's user SID (which file is unrecorded). The owner was corrected by hand and `-Collect` was
  run again (10:29:13, exit 0, residue readable, nothing left behind). The driver's record-writing and copy-writing were
  then fixed to give Administrators as owner; those later versions did not run live, and are not what produced any record
  here.
- **Second sitting, part C.** The account's profile could not be deleted while its registry hive stayed loaded from the
  batch logon; the operator restarted the machine at 10:52 and deleted the orphaned profile afterwards. `-PartD` at
  11:07:56 read all four items absent (exit 20).
- **After part C**, by hand and outside the driver (11:12:31, read-only): of 327 scheduled tasks (a figure from `runs/AS_RUN.md`'s prose, not recomputable from any record) none is named with `nco`,
  `probe` or `case4` and none runs as the account; an exported copy of the user-rights policy names neither the account nor
  its relative ids; the machine's registry holds no hive for the account (`runs/AS_RUN.md`).
- **Control records.** The sweep before each published control phase (taskcheck, n1) read clean: the `pre_cleanup` of
  `runs/controls/nep5-results-taskcheck-20261019-164908.json` and of `runs/controls/nep5-results-n1-20261019-164952.json`
  reads "nothing to remove: the machine reads clean", and each pass of the `n1` phase records `sweep_before` clean. One record named in
  `runs/AS_RUN.md`, `runs/controls/remove-20261019-164737.json`, is not published; `runs/AS_RUN.md` still lists it in its
  file table.

## What the counts are

Repeats on one machine, minutes or seconds apart, in two sittings: 4 F runs between 01:05 and 01:15, 3 S runs and 3 A
runs each within 3 seconds (01:21:45 to 01:22:43), 3 E runs over 9 minutes (09:33:12, 09:37:10, 09:42:29). They show that the outcome was the same on every repeat in each
condition. They are not a distribution and not an independent replication. The A and S controls show
that the probe's add and delete succeed under a full administrator token and that its add is refused under that same
operator's filtered token, so the add refusals in F are not an artefact of the probe or of the sublayer. N1 shows a
standard account refused on the add (`0x00000005`) and on the delete (`0x00000005`). Every F and S delete ran against a
key that was not present (`0x80320003`), so those deletes say nothing about delete permission, and N1's delete is not
like for like with them.

## Not measured

- Whether the access-list entry for the group is what permitted the add, or which of the differences listed under "Result"
  the engine's decision followed. The entry is present in the records and the result is consistent with it, but no run
  removed it, no token with the group enabled and the entry absent was tried, and no token varied one difference alone.
- An interactive logon by the member at the lock screen (the operator's own sheet forbade it), and a logon from code (none
  was made).
- Whether the elevation prompt would list the member if raised inside the member's own interactive session; this run
  raised it from a `runas` console only.
- Other Windows builds, a second physical machine, a domain-joined machine.
- The machine without Bitdefender.
- The group's other documented rights (network configuration).
- Delete permission under the filtered member token: every F delete ran against a key that was not present.
- Any effect of the filter: it is keyed to a stale SID, so it matches no account and no traffic was blocked or permitted
  by it. Filters of other providers, and other layers, sublayers or filter types, were not touched or tried; the probe
  adds into S2 only.
- Variance beyond the repeats listed. No independent replication.

## Claim C27

This folder carries the claim row for this measurement; it is not in the claims table of
`evidence/2026-10-05-wfp-sid-block/account-level-containment-evidence.md`, which holds C1 to C26.

**C27.** The effect of membership of the local group Network Configuration Operators on the filtering engine, as observed,
differs between the tokens the same account holds. Launched the ordinary way (a secondary logon, `runas`), the member holds a filtered token
in which the group is present but use-for-deny-only (elevation type limited, integrity medium, a linked full token
present), and a single `FwpmFilterAdd0` into the test sublayer S2 returned `0x00000005` (access denied), as it does for a
standard non-administrator token (claim C17) and for the operator's own filtered administrator token. Launched by a
scheduled task running as the member (a batch logon), the token holds the group enabled
(attributes `0x7`, elevation type 1, no linked token, integrity medium-plus, session 0, Administrators absent), and the
same `FwpmFilterAdd0` and `FwpmFilterDeleteByKey0` succeeded, nothing left behind. According to the operator's note, the elevation prompt
raised from inside the member's own console offered only this machine's administrator accounts, and no record reached the
engine by that route.

*Counts.* F: 4 of 4 denied. E route 1: 0 runs reached the engine; the operator's note records the prompt cancelled 4 of 4 attempts. E route 2: 3 of 3 add
and delete succeeded (filter ids 537392 to 537394). S: 3 of 3 denied. A: 3 of 3 add and delete succeeded. N1: 3 of 3 add
and delete denied.

*Status.* OBSERVED: filtered token denied 4 of 4; the group-enabled token (batch logon) adds and deletes 3 of 3;
the elevation-prompt route cancelled by the operator in 4 of 4 attempts (his note only). The cause of the difference is not
shown (see "Result"). Not a vulnerability finding, in the author's reading: an administrator
must add the account to the group and grant the batch-logon right. The first sitting's "not established" for the
group-enabled token is superseded by the second sitting. The not-measured list is above.

## Bitdefender

Endpoint protection interfered with the scripts' history, in three separate ways. A heuristic detection
(`CMD:Heur.BZC.PZQ.Boxter`) quarantined the first test runner, `selftest-probe.ps1`, and then blocked that path whatever its
content. Bitdefender's static signature family `Generic.PWSH.CoinStealer` quarantined three revisions of the driver while
the account-lifecycle patterns and planted fixtures were written inline in it: two quarantine records name
`Generic.PWSH.CoinStealer.B.900C832E`, and the third revision's record was cleared when the operator restored the file. The
patterns and fixtures were then moved into `scripts/case4-lock-corpus.json`, read as data, and the driver was renamed
twice. Files the operator restored from quarantine stayed held against write, rename and delete, even for him. The
measurement machine had two file-level scan exceptions for the driver script (the working copy and the live copy; Antivirus
and Advanced Threat Defense, as `SPEC.md` records). The quarantine and bisection records are not published. A reader who
downloads this folder and runs or scans the scripts may see a detection.

## What was changed in these copies

The files in this folder went through `tools/sanitize.py` (counts per file and rule in `.sanitized`, never an original
value), then hand edits and one file rename, all listed in the repository-root `PROVENANCE.md`, in the section for this folder. Consequences a reader needs:

- **No published file has the bytes that ran.** Every sha256 in `runs/AS_RUN.md`'s file tables and in the collect
  records (`sha256` of each copied record) belongs to the source copies, before the sanitiser; none of them matches the
  published bytes. The hashes of the two drivers and of the probe source in this README likewise belong to the bytes that
  ran. The sanitiser rewrote the machine's account domain to `X` (the stale SID's fabricated domain to `Y`), removed
  internal-tracker references, rewrote some paths, and replaced the operator's two-word role title with `operator` (4
  places in `runs/AS_RUN.md`, and in the specification, run sheet, driver sources and READMEs).
  `runs/results-summary.json` as sanitised disagrees with the run records in six fields this README does not use: the
  `clock_start_utc` of the 3 E runs (the summary holds each record's `clock.utc`, for example `13:33:12.484Z`, where the
  record's `clock_start.utc` reads `.471Z`, `.240Z` and `.769Z`) and the `add.filter_id` of the 3 A runs (absent from the
  summary; 537361 to 537363 in the records). The records are authoritative; the summary is published as it was and is not
  edited. The summary's `reading` field (a causal statement, that the engine's entry "applies to that token as Microsoft
  documents", and that the effect is "a property of the token") is not adopted either: it is not a record, and the records
  do not show a cause. The tools `rewrite_sid_domain.py` and `scrub_public_identifiers.py` that `SPEC.md`,
  `runs/AS_RUN.md` and the `sanitisation` field of `runs/results-summary.json` (line 602) name, and the logs
  `docs/reviews/case4-sid-rewrite-log-*.md`, are not in this repository; nor are the helper files and libraries that
  `SPEC.md` and the READMEs name (`Convert-ToLive.ps1`, the half-set matrix with its `spike-*-lib.ps1` libraries and its
  harness, the `build-record-*.json` files a build writes). Those texts are published as sanitised. Inside the scripts these edits also reach test fixtures and file
  name constants (for example a fixture account SID, a fixture profile path and the names of two proof files), so a
  published script is for reading and comparison and may not reproduce its own self-test unchanged. The table at the end
  of this README gives the sha256 (LF) of every published file.
- **One file renamed.** `runs/case4-F-20261020-051400-5880.json` is published as `runs/case4-F-20261020-051400-05880.json`
  (the process id in the name zero-padded, because the leak gate reads a four-digit number in a path as a reference). Its
  content is unchanged. `runs/AS_RUN.md`, `runs/results-summary.json`, the two first-sitting `-collect-` records and the
  record's own `record_file_name` field name it with the original spelling.
- **Placeholders.** Account-domain SIDs read `S-1-5-21-X-X-X-<relative id>`; the stale SID reads `S-1-5-21-Y-Y-Y-91763`
  (as in the half-set folder). The
  probe's filter key (`c4a0e001-0000-4d8e-9a31-2b6d4c8e0041`) is a constant of the script and stays as written.
- **`text` renamed.** In the prepare, final and part-D records the key `text` of each `netsh` output was renamed
  `netsh_text` before sanitising; the values are unchanged.
- **Not included.** The admin-only originals of the records, the driver's self-test proof, the probe proof, the compiled
  `ncoprobe.exe`, the main line's later driver versions, and the one control record named under "Control records".

## What is in the folder

| Path | What |
|---|---|
| `SPEC.md` | the build specification: constants, the probe's refusals, the driver's modes, the standing rules for the account lifecycle |
| `RUN_SHEET.md` | the launch lines the operator typed, in order, including step 4b (the scheduled-task route) |
| `probe/` | `NcoProbe.cs` (the probe), `build-probe.ps1`, `run-probe-selftest.ps1` and the probe's README |
| `scripts/driver-first-sitting/`, `scripts/driver-second-sitting-collect/` | the two driver versions that ran, each in its own folder under the file name it ran as |
| `scripts/case4-lock-corpus.json`, `scripts/run-limited.ps1`, `scripts/README.md` | the driver's pattern corpus (data), the non-elevated launcher, and the driver's README |
| `runs/case4-{F,S,A,E}-*.json` | the 13 probe records (F 4, S 3, A 3, E 3) |
| `runs/case4-prepare-*.json`, `-collect-*.json`, `-final-*.json`, `-partd-*.json` | the driver's records for each mode: 2 prepare, 5 collect, 2 final, 2 part D |
| `runs/results-summary.json` | the results of both sittings and the control in one file |
| `runs/AS_RUN.md` | provenance of the records: times, hashes of the bytes that ran, the by-hand checks after part C |
| `runs/controls/` | the standard-token control (`nep5-results-n1-*`) and its pre-flight phase (`nep5-results-taskcheck-*`) |
| `recount.py`, `RECOUNT.md` | the script that recomputes the figures of this README from the records, and its output |
| `.sanitized` | replacement counts per file and rule (the entry of the unpublished control record is removed) |

## How to re-run

Run only on a machine you can afford to change, from an elevated shell, and only the hand steps of `RUN_SHEET.md` create
accounts, rights and tasks: no script here does. The driver's `-SelfTest`, `-DryRun` and `-Check` change nothing. The
modes run in the order of "Method"; `-Prepare` needs the live folder the specification describes (the half-set matrix's
libraries beside the driver). The published scripts carry the placeholders listed above, so restore a stale-SID domain
that resolves to no account in `NcoProbe.cs` and in the driver before building or proving anything, and expect the
scripts' README to describe a later driver than either that ran.

## Published file hashes

sha256 of the LF-normalised bytes of each published file. `README.md`, `.sanitized` and `RECOUNT.md` are not in the table:
`RECOUNT.md` prints the check of this table, so a row for it would be circular; `recount.py` is in it.

| File | sha256 (LF) |
|---|---|
| `RUN_SHEET.md` | `8a5ef74d59561bbdc58a69ff59e0ec36d6d4a92ca84d4c2d4ac11c52f0356ee6` |
| `SPEC.md` | `493a1ad034a46833bd342af3f0d428bbc4f762497d6bb78472a0cf7ec7a74905` |
| `probe/NcoProbe.cs` | `d5a6b6400d31cbc5be2c25b7923695b293eb27a3296433a90533fff25b792a1e` |
| `probe/README.md` | `03f648d7d42ac43f1f2b3259ca909bb3400c7b9024e4abdb8773f005ad36f823` |
| `probe/build-probe.ps1` | `182d7ca17258adf27c5636d3ebaa969053ea17492361e7fb62d8c3eae9cbf944` |
| `probe/run-probe-selftest.ps1` | `d1c10b4201b6017f0f9049dfd4d19e5cdbee40064f3068183ae4b73ad1779b3b` |
| `recount.py` | `46368245764696a30491556c45b0137c979fc3b0e5b1fd70e5f537be6990e73e` |
| `runs/AS_RUN.md` | `a64e0802bf980317d8a7f68f62b9e90b4b2930223708c976172bb6f6302f9103` |
| `runs/case4-A-20261020-052240-21428.json` | `555a707f61c04ee82a77500ce3759b4962b4cd4c125328fd504c1f9959fa5f21` |
| `runs/case4-A-20261020-052241-23964.json` | `852fdf511fd6444cc46dd8c908bc383eeedd896b4763257cdeabde460b5fba1c` |
| `runs/case4-A-20261020-052242-13572.json` | `21219b85be3f602eb9135b43bb2da15e9a621fd2fff092f2fb36b3aa783ce84f` |
| `runs/case4-E-20261020-133312-14960.json` | `260dd759dc0a05f24108b34f497e15f22ab9f3a340fca320ce398056415f91b8` |
| `runs/case4-E-20261020-133710-25944.json` | `a3703e8390f49659eb70a0528b30138dc3fe4286e5417e512502c9baa0eca706` |
| `runs/case4-E-20261020-134229-11468.json` | `de0ff90f5c3feb4878375a46fe79e16127f6eb890fd76155992c114b69e64dd6` |
| `runs/case4-F-20261020-050515-23756.json` | `efb5f891401e6958f7cb96f1927eb3072aa9402327a949323de62776e6884238` |
| `runs/case4-F-20261020-051400-05880.json` | `a8898db5922b8b8635c875023320d2085c54b485948ad5e8327cd51a6d74a318` |
| `runs/case4-F-20261020-051424-25640.json` | `3d05b9389b0ba3d9ca966b46cf2748401b09c9cf55cdb61c8dfd760e7f6a7955` |
| `runs/case4-F-20261020-051440-28652.json` | `4f2b2c996c3012ab606a6da638b6ed64e5f322fb88ea43c63b9a1608f28a5d29` |
| `runs/case4-S-20261020-052145-19624.json` | `487f2906f422d9e26490fbc6c8642d33d4ef41cb115f298e15f9f03568e8c00d` |
| `runs/case4-S-20261020-052147-18812.json` | `dc1bb1a75ae5623d657d9c3c714d3bd5380d1b972dcc1512f5f862fba314ab5a` |
| `runs/case4-S-20261020-052148-15020.json` | `d0c25bb815fdf517095510f2868dc8e023c8b0e96e04167372c46d0c49b7c5fc` |
| `runs/case4-collect-20261020-012258.json` | `5df9a3e2e024d9098482bdce3dc7144fd0bee07508f8ddedcc97118973ef0a89` |
| `runs/case4-collect-20261020-012313.json` | `3b9b097855001ae6007c52a76d81d6f5a19eb0bb22a27cfb098a2965cb56f618` |
| `runs/case4-collect-20261020-102824.json` | `32adc3b66de5382d05c09eb4ce5b80c60a431d0d8850167eaea3f85b80d46ce4` |
| `runs/case4-collect-20261020-102913.json` | `22c2443631a105f827746f2fb4ee098fac1b354a51dcfaf2b5ca1969a81b5a4c` |
| `runs/case4-collect-20261020-102929.json` | `644b0c463105da8b8beb652fe5676ea633cb4fe8d8d054de664884962d125a5e` |
| `runs/case4-final-20261020-012312.json` | `d304ed67cf66a1169c1ea61bb10f4b18ddeb0f88ebc8c81c2d246601f8df5e7b` |
| `runs/case4-final-20261020-102928.json` | `70269e7e9db2df219a7c240ba6bd05599622e98ac7a319a2668c955d11c234cc` |
| `runs/case4-partd-20261020-014216.json` | `674ed9560f98f9624ae56e8d2a5b3f93844cdb9d5aa404a7689dfed5fccc7625` |
| `runs/case4-partd-20261020-110756.json` | `5b0435909460365099a7f2b9180c58edb6370845c9d0040791bbaf1a94ca2dca` |
| `runs/case4-prepare-20261020-004848.json` | `de15a267a90cd7777e0b99383536efb8a52fb1c1dc7097a67ba96e0e2c9e7048` |
| `runs/case4-prepare-20261020-092824.json` | `4fa24408ea3423f55d8c8917adf38d7485d994f951d4eef7feb94d0c376ddc9d` |
| `runs/controls/nep5-results-n1-20261019-164952.json` | `e515fa904a74d0c659b4b2de36cfb24f1b3867aab888c573ce7eb2e07815e938` |
| `runs/controls/nep5-results-taskcheck-20261019-164908.json` | `9b730e6793d932996503d54b646f3255342e05f44ae6386f1b72c686fa35be7a` |
| `runs/results-summary.json` | `c63c01d135b059c2d7f15656a31a09bcd55de1eeb3a11e669dd100096ec1fec9` |
| `scripts/README.md` | `87bdb230c1a124319e5878996a9ec0b79670623c7960ab6d3b46b4563df3a64a` |
| `scripts/case4-lock-corpus.json` | `f98304092c2e4ac06feba76cbcc5f9c0bb86fea4f8d0aed7c9a8c4b70b3f97bc` |
| `scripts/driver-first-sitting/spike-nep5-c4-driver.ps1` | `6e67ee92ffdad77cb0f624ecc91f9bca86b1df99d1e06527ba1ac25bdde058b5` |
| `scripts/driver-second-sitting-collect/spike-nep5-c4-driver.ps1` | `eaaaec3cda5db4763d54554d8357f726f0a1ce974459f14d7420f58ff10a30b5` |
| `scripts/run-limited.ps1` | `621af5bca418bef06e2f87d3836d62c04d676847a2743c9e6c04dbbdecc773df` |
