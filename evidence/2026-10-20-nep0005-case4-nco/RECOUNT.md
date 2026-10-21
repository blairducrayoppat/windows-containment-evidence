# Re-count of the figures in README.md

`recount.py` reads the run records of this folder and prints every figure the README states as `name = value`. It was written
from the records. Standard library only.

    python recount.py <folder>                                   # print the figures; exit 1 while the 6 documented differences below remain
    python recount.py <folder> --raw <originals> [--repo <git>] [--local <file>]  # also compare with the originals and recompute hashes

`--local` names the sanitiser's private local-vocabulary file; its `replacements` pairs are applied to the originals before
comparing, and without it the lines those pairs changed show as residue.

What it reads, and for which figures:

- the 13 probe records `runs/case4-{F,S,A,E}-*.json`: every per-condition count, return code, token fact (elevation type,
  group attributes, integrity level, session, linked token), filter id, read-back and clock time. A count is made by the
  script from each record's own fields; the records' summary fields (`results-summary.json`, the collect records' `valid`
  list) are compared with the records they summarise and are never used in place of them.
- the driver records (`prepare`, `collect`, `final`, `partd`): exit codes, valid and invalid counts, the first sitting's
  `verified: false`, `code: 7`, the engine access-list comparison between `-Prepare` and `-Finish`, the part-D checks.
- `runs/controls/`: the standard-token control (3 passes) and its pre-flight phase.
- `runs/AS_RUN.md`: its file table (size and sha256 per file) against the originals; the hash lines the README cites.
- the README itself: its published-file hash table (40 rows, every file but `README.md`, `.sanitized` and `RECOUNT.md`) against the files, the paths it names, and the claims table
  (`claim` lines), where each value the README states is set against the value computed from the records. `ok` means equal,
  `DIFFERS` means a stated count differs, `READ` means the stated text is prose and the computed text is printed beside it.
- `--raw`: each of the 28 files under `runs/` against its original after the recorded replacements (domain SIDs to `X` and
  `Y`, the internal-tracker reference removed, home paths, one name, the local-vocabulary pairs, the one renamed
  record); anything left over is printed. One original that is not published is left out of the
  comparison, and the 6 lines of `runs/AS_RUN.md` that were edited by hand (listed in `PROVENANCE.md`) are skipped. `--repo`: `git show` of the driver, probe source and lock corpus at the commits the
  README names.

Result of the run below: the 28 originals equal the published files after the recorded replacements (0 residue); the 167
figures equal the originals' figures after the same replacements (0 differ); the README's 40 hashes match the files; the
hashes of the bytes that ran match `git show` at the named commits. The differences the run does report (6, all inside `results-summary.json`) are listed after the
output.

```
files.probe_records = 13
files.probe_records.by_cond = A (x3), E (x3), F (x4), S (x3)
files.prepare = 2
files.collect = 5
files.final = 2
files.partd = 2
files.controls = 2
probe.exe_sha256 = 4fde1ad6db744fa289b65eb6f639628cd1f04ead6f3b5e6db247fcdc3a0e14d4 (x13)
probe.cs_sha256 = 28bc05d583135c446ae5dff073907b42c855e522123ba7106c76ff185a42f794 (x13)
probe.version/toggle_build = ncoprobe 1.0.0/False (x13)
probe.proof_sha256 by cond = F: 77f7b126 (x4); S: 77f7b126 (x3); A: 77f7b126 (x3); E: 55cf04d2 (x3)
probe.filter = key=c4a0e001-0000-4d8e-9a31-2b6d4c8e0041 action=0x00001001 weight=0x1000 flags=0x00000001 layer=c38d57d1-05a7-4c33-904f-7fbceee60e82 stale=S-1-5-21-Y-Y-Y-91763 (x13)
probe.stale_sid.mapped/lookup_error = False/1332 (x13)
probe.engine_session_flags/open_rc = 0/0x00000000/closed=True (x13)
cond.F.n = 4
cond.F.user_rid = 2250 (x4)
cond.F.is_expected_account = True (x4)
cond.F.elevation_type = 3 limited (x4)
cond.F.integrity = S-1-16-8192 medium (x4)
cond.F.linked_token = present=True err=0 (x4)
cond.F.session = 1 (x4)
cond.F.nco_group = present=True attr=0x00000010 enabled=False deny_only=True (x4)
cond.F.administrators = present=False attr=None (x4)
cond.F.add.rc/class = 0x00000005 denied (x4)
cond.F.add.filter_id = None, None, None, None
cond.F.add.present_after = False (x4)
cond.F.delete.rc/class = 0x80320003 not_found (x4)
cond.F.delete.present_after = False (x4)
cond.F.residue/overall/exit = absent/ok/0 (x4)
cond.F.sequence_complete = True (x4)
cond.F.clock_start_local = 01:05:15 / 01:14:00 / 01:14:24 / 01:14:40
cond.F.zone = -04:00 (x4)
cond.F.pids = 23756, 5880, 25640, 28652
cond.E.n = 3
cond.E.user_rid = 2251 (x3)
cond.E.is_expected_account = True (x3)
cond.E.elevation_type = 1 default (x3)
cond.E.integrity = S-1-16-8448 medium_plus (x3)
cond.E.linked_token = present=False err=1312 (x3)
cond.E.session = 0 (x3)
cond.E.nco_group = present=True attr=0x00000007 enabled=True deny_only=False (x3)
cond.E.administrators = present=False attr=None (x3)
cond.E.add.rc/class = 0x00000000 succeeded (x3)
cond.E.add.filter_id = 537392, 537393, 537394
cond.E.add.present_after = True (x3)
cond.E.delete.rc/class = 0x00000000 succeeded (x3)
cond.E.delete.present_after = False (x3)
cond.E.residue/overall/exit = absent/ok/0 (x3)
cond.E.sequence_complete = True (x3)
cond.E.clock_start_local = 09:33:12 / 09:37:10 / 09:42:29
cond.E.zone = -04:00 (x3)
cond.E.pids = 14960, 25944, 11468
cond.S.n = 3
cond.S.user_rid = 1001 (x3)
cond.S.is_expected_account = False (x3)
cond.S.elevation_type = 3 limited (x3)
cond.S.integrity = S-1-16-8192 medium (x3)
cond.S.linked_token = present=True err=0 (x3)
cond.S.session = 1 (x3)
cond.S.nco_group = present=False attr=None enabled=None deny_only=None (x3)
cond.S.administrators = present=True attr=0x00000010 (x3)
cond.S.add.rc/class = 0x00000005 denied (x3)
cond.S.add.filter_id = None, None, None
cond.S.add.present_after = False (x3)
cond.S.delete.rc/class = 0x80320003 not_found (x3)
cond.S.delete.present_after = False (x3)
cond.S.residue/overall/exit = absent/ok/0 (x3)
cond.S.sequence_complete = True (x3)
cond.S.clock_start_local = 01:21:45 / 01:21:47 / 01:21:48
cond.S.zone = -04:00 (x3)
cond.S.pids = 19624, 18812, 15020
cond.A.n = 3
cond.A.user_rid = 1001 (x3)
cond.A.is_expected_account = False (x3)
cond.A.elevation_type = 2 full (x3)
cond.A.integrity = S-1-16-12288 high (x3)
cond.A.linked_token = present=True err=0 (x3)
cond.A.session = 1 (x3)
cond.A.nco_group = present=False attr=None enabled=None deny_only=None (x3)
cond.A.administrators = present=True attr=0x0000000F (x3)
cond.A.add.rc/class = 0x00000000 succeeded (x3)
cond.A.add.filter_id = 537361, 537362, 537363
cond.A.add.present_after = True (x3)
cond.A.delete.rc/class = 0x00000000 succeeded (x3)
cond.A.delete.present_after = False (x3)
cond.A.residue/overall/exit = absent/ok/0 (x3)
cond.A.sequence_complete = True (x3)
cond.A.clock_start_local = 01:22:40 / 01:22:41 / 01:22:42
cond.A.zone = -04:00 (x3)
cond.A.pids = 21428, 23964, 13572
cond.N1.n = 3
cond.N1.add.rc/class = 0x00000005 denied (x3)
cond.N1.delete.rc/class = 0x00000005 denied (x3)
cond.N1.sweep_before/after_clean = True/True (x3)
cond.N1.started = 2026-10-19T16:49:52 .. 2026-10-19T16:51:17 exit=0
control.taskcheck.passes/classes = 3 / ok (x1)
control.taskcheck.sweep_before_clean = no sweep_before key
control.taskcheck.started = 2026-10-19T16:49:08 .. 2026-10-19T16:49:35 exit=0
control.n1+taskcheck.pre_cleanup = n1: nothing to remove: the machine reads clean; taskcheck: nothing to remove: the machine reads clean
collect.case4-collect-20261020-012258.json.at/code = 2026-10-20T01:22:58 / 0
collect.case4-collect-20261020-012258.json.valid/invalid = 10 ({'A': 3, 'F': 4, 'S': 3}) / 0
collect.case4-collect-20261020-012258.json.refused given/counted/note = True/True/Windows elevation prompt from the nco-probe console offered only the administrator accounts of this machine, with no field to name nco-probe; the operator cancelled it, four times
collect.case4-collect-20261020-012258.json.left_behind/foreign/wrong_account = 0/0/0
collect.case4-collect-20261020-012258.json.residue.readable/enum_skipped = True/False
collect.case4-collect-20261020-012258.json.copies.status = written (x10)
collect.case4-collect-20261020-012313.json.at/code = 2026-10-20T01:23:13 / 0
collect.case4-collect-20261020-012313.json.valid/invalid = 10 ({'A': 3, 'F': 4, 'S': 3}) / 0
collect.case4-collect-20261020-012313.json.refused given/counted/note = True/True/Windows elevation prompt from the nco-probe console offered only the administrator accounts of this machine, with no field to name nco-probe; the operator cancelled it, four times
collect.case4-collect-20261020-012313.json.left_behind/foreign/wrong_account = 0/0/0
collect.case4-collect-20261020-012313.json.residue.readable/enum_skipped = True/False
collect.case4-collect-20261020-012313.json.copies.status = exists-same (x10)
collect.case4-collect-20261020-102824.json.at/code = 2026-10-20T10:28:24 / 21
collect.case4-collect-20261020-102824.json.valid/invalid = 3 ({'E': 3}) / 0
collect.case4-collect-20261020-102824.json.refused given/counted/note = False/False/None
collect.case4-collect-20261020-102824.json.left_behind/foreign/wrong_account = 0/0/0
collect.case4-collect-20261020-102824.json.residue.readable/enum_skipped = True/True
collect.case4-collect-20261020-102824.json.copies.status = written (x3)
collect.case4-collect-20261020-102913.json.at/code = 2026-10-20T10:29:13 / 0
collect.case4-collect-20261020-102913.json.valid/invalid = 3 ({'E': 3}) / 0
collect.case4-collect-20261020-102913.json.refused given/counted/note = False/False/None
collect.case4-collect-20261020-102913.json.left_behind/foreign/wrong_account = 0/0/0
collect.case4-collect-20261020-102913.json.residue.readable/enum_skipped = True/False
collect.case4-collect-20261020-102913.json.copies.status = exists-same (x3)
collect.case4-collect-20261020-102929.json.at/code = 2026-10-20T10:29:29 / 0
collect.case4-collect-20261020-102929.json.valid/invalid = 3 ({'E': 3}) / 0
collect.case4-collect-20261020-102929.json.refused given/counted/note = False/False/None
collect.case4-collect-20261020-102929.json.left_behind/foreign/wrong_account = 0/0/0
collect.case4-collect-20261020-102929.json.residue.readable/enum_skipped = True/False
collect.case4-collect-20261020-102929.json.copies.status = exists-same (x3)
final.case4-final-20261020-012312.json.at = 2026-10-20T01:23:12
final.case4-final-20261020-012312.json.verified/code/error = False/7/Exception calling "RemoveTree" with "1" argument(s): "Exception calling "Delete" with "2" argument(s): "The process cannot access the file 'C:\ProgramData\BlarAI\case4-pub' because it is being used by another process.""
final.case4-final-20261020-012312.json.collect.code/valid/invalid = 0/10/0
final.case4-final-20261020-012312.json.probe_key_delete/after = not_found/False
final.case4-final-20261020-012312.json.removal.ok/steps/errors = True/13/0
final.case4-final-20261020-012312.json.removal.steps = filter:not_found (x9), provider:deleted (x1), sublayer:deleted (x3)
final.case4-final-20261020-012312.json.sweep.clean/export_hits = True/0
final.case4-final-20261020-012312.json.engine_sd.same/removed/added = True/0/0
final.case4-final-20261020-012312.json.folder.removed/uncopied = key absent/0
final.case4-final-20261020-102928.json.at = 2026-10-20T10:29:28
final.case4-final-20261020-102928.json.verified/code/error = True/0/None
final.case4-final-20261020-102928.json.collect.code/valid/invalid = 0/3/0
final.case4-final-20261020-102928.json.probe_key_delete/after = not_found/False
final.case4-final-20261020-102928.json.removal.ok/steps/errors = True/13/0
final.case4-final-20261020-102928.json.removal.steps = filter:not_found (x9), provider:deleted (x1), sublayer:deleted (x3)
final.case4-final-20261020-102928.json.sweep.clean/export_hits = True/0
final.case4-final-20261020-102928.json.engine_sd.same/removed/added = True/0/0
final.case4-final-20261020-102928.json.folder.removed/uncopied = True/0
partd.case4-partd-20261020-014216.json.at/code = 2026-10-20T01:42:16 / 20
partd.case4-partd-20261020-014216.json.net_user/lookup_err/members/profile_present/list_entry_present/profile_folders = absent/1332/0/False/False/0
partd.case4-partd-20261020-014216.json.account_sid = S-1-5-21-X-X-X-2250
partd.case4-partd-20261020-110756.json.at/code = 2026-10-20T11:07:56 / 20
partd.case4-partd-20261020-110756.json.net_user/lookup_err/members/profile_present/list_entry_present/profile_folders = absent/1332/0/False/False/0
partd.case4-partd-20261020-110756.json.account_sid = S-1-5-21-X-X-X-2251
prepare.case4-prepare-20261020-004848.json.at = 2026-10-20T00:48:48
prepare.case4-prepare-20261020-004848.json.nco_ace_in_engine_sd = True
prepare.case4-prepare-20261020-004848.json.sweep.clean = True
prepare.case4-prepare-20261020-004848.json.probe_proof.sha256/written_utc = 77F7B126 / 2026-10-20T04:48:52Z
prepare.case4-prepare-20261020-004848.json.nco_sid = S-1-5-21-X-X-X-2250
prepare.case4-prepare-20261020-092824.json.at = 2026-10-20T09:28:24
prepare.case4-prepare-20261020-092824.json.nco_ace_in_engine_sd = True
prepare.case4-prepare-20261020-092824.json.sweep.clean = True
prepare.case4-prepare-20261020-092824.json.probe_proof.sha256/written_utc = 55CF04D2 / 2026-10-20T13:28:27Z
prepare.case4-prepare-20261020-092824.json.nco_sid = S-1-5-21-X-X-X-2251
engine_sd.prepare 0261020-004848 == finish 0261020-012312 = True
engine_sd.prepare 0261020-092824 == finish 0261020-102928 = True
record.results-summary.counts = {"A": 3, "E": 3, "E_prompt_route_refusals": 4, "F": 4, "N1": 3, "S": 3}
record.results-summary.records = 13

# cross-checks (summary against its records)
DIFF results-summary case4-A-20261020-052240-21428.json add.filter_id: summary=None record=537361
DIFF results-summary case4-A-20261020-052241-23964.json add.filter_id: summary=None record=537362
DIFF results-summary case4-A-20261020-052242-13572.json add.filter_id: summary=None record=537363
DIFF results-summary case4-E-20261020-133312-14960.json clock_start_utc: summary='2026-10-20T13:33:12.484Z' record='2026-10-20T13:33:12.471Z'
DIFF results-summary case4-E-20261020-133710-25944.json clock_start_utc: summary='2026-10-20T13:37:10.256Z' record='2026-10-20T13:37:10.240Z'
DIFF results-summary case4-E-20261020-134229-11468.json clock_start_utc: summary='2026-10-20T13:42:29.785Z' record='2026-10-20T13:42:29.769Z'
cross_check.differences = 6

# claims (README statement | computed from records)
claim F.n stated='4' computed='4' -> ok
claim F.add_denied_0x5 stated='4 of 4' computed='4 of 4' -> ok
claim F.delete_0x80320003 stated='4 of 4' computed='4 of 4' -> ok
claim F.elevation_type_3 stated='4 of 4' computed='4 of 4' -> ok
claim F.group_attr_0x10 stated='4 of 4' computed='4 of 4' -> ok
claim F.linked_token_present,medium,session1 stated='4 of 4' computed='4 of 4' -> ok
claim F.admins_absent,none_left stated='4 of 4' computed='4 of 4' -> ok
claim E.n stated='3' computed='3' -> ok
claim E.add_0x0 stated='3 of 3' computed='3 of 3' -> ok
claim E.delete_0x0 stated='3 of 3' computed='3 of 3' -> ok
claim E.filter_ids stated='537392, 537393, 537394' computed='537392, 537393, 537394' -> ok
claim E.present_after_add_absent_after_delete stated='3 of 3' computed='3 of 3' -> ok
claim E.elevation_type_1_no_linked_token_error stated='3 of 3' computed='3 of 3' -> ok
claim E.group_attr_0x7 stated='3 of 3' computed='3 of 3' -> ok
claim E.integrity_8448_session0 stated='3 of 3' computed='3 of 3' -> ok
claim E.admins_absent,none_left stated='3 of 3' computed='3 of 3' -> ok
claim S.n/add_denied/delete_0x80320003 stated='3; 3 of 3; 3 of 3' computed='3; 3 of 3; 3 of 3' -> ok
claim S.elev3,admins_0x10,nco_absent stated='3 of 3' computed='3 of 3' -> ok
claim A.n/add_ok/delete_ok stated='3; 3 of 3; 3 of 3' computed='3; 3 of 3; 3 of 3' -> ok
claim A.elev2,admins_0xF,nco_absent,none_left stated='3 of 3' computed='3 of 3' -> ok
claim F,E.is_expected_account_true stated='7 of 7' computed='7 of 7' -> ok
claim S,A.is_expected_account_false stated='6 of 6' computed='6 of 6' -> ok
claim N1.n/add/delete_0x5 stated='3; 3 of 3; 3 of 3' computed='3; 3 of 3; 3 of 3' -> ok
claim probe_records_total stated='13 (F 4, S 3, A 3, E 3)' computed='13 (F 4, S 3, A 3, E 3)' -> ok
claim driver_record_files stated='2 prepare, 5 collect, 2 final, 2 part D' computed='2 prepare, 5 collect, 2 final, 2 part D' -> ok
claim collect1.valid/invalid stated='10 valid, 0 invalid (F 4, S 3, A 3)' computed='10 valid, 0 invalid (A 3, F 4, S 3)' -> READ
claim collect2.valid/invalid stated='3 valid, 0 invalid (E 3)' computed='3 valid, 0 invalid (E 3)' -> ok
claim E_route1.refusals stated='4 (cancelled four times)' computed="four; counted=True; no E record in first sitting's collect: 0" -> READ
claim E_route1.in_summary stated='4 attempts, 0 runs' computed='4 refusals; prompt_route.n=0' -> READ
claim second_collect.first.exit_21_enum_skipped stated='exit 21, enumeration skipped, 3 valid' computed='exit 21, enum_skipped=True, 3 valid' -> READ
claim second_collect.rerun.exit_0 stated='10:29:13, exit 0, residue readable, nothing left behind' computed='10:29:13, exit 0, readable=True, left_behind=0' -> READ
claim first_collect.time stated='10:28:24' computed='10:28:24' -> ok
claim final1.verified_false_code7 stated='verified false, code 7' computed='verified False, code 7' -> ok
claim partd1.time/exit stated='01:42:16, exit 20' computed='01:42:16, exit 20' -> ok
claim partd2.time/exit stated='11:07:56, exit 20' computed='11:07:56, exit 20' -> ok
claim partd.four_items_absent stated='all four absent (both)' computed='True' -> READ
claim rids stated='2250 then 2251' computed='2250 (x4) then 2251 (x3)' -> READ
claim F_times stated='4 F runs between 01:05 and 01:15' computed='01:05:15 01:14:00 01:14:24 01:14:40' -> READ
claim S_A_times stated='S and A runs each within 3 seconds (01:21:45 to 01:22:43)' computed='S 01:21:45..01:21:48; A 01:22:40..01:22:42' -> READ
claim E_times stated='09:33:12, 09:37:10, 09:42:29 over 9 minutes' computed='09:33:12 09:37:10 09:42:29' -> READ
claim sitting1.span stated='00:48 to 01:43' computed='prepare 00:48:48; partd 01:42:16 (01:43 is the by-hand folder removal, AS_RUN)' -> READ
claim sitting2.span stated='09:28 to 11:12' computed='prepare 09:28:24; partd 11:07:56 (11:12 is the by-hand check, AS_RUN)' -> READ
claim control_records.window stated='2026-10-19, 16:49 to 16:51' computed='2026-10-19T16:49:08 2026-10-19T16:49:35 2026-10-19T16:49:52 2026-10-19T16:51:17' -> READ
claim engine_acl_identical_before_after stated='identical both times in both sittings' computed='True' -> READ
claim engine_acl_group_entry stated='(A;;0x307ff;;;NO) present' computed='True' -> READ
claim probe_sha256 stated='4fde1ad6...3a0e14d4 in every probe record' computed='4fde1ad6db744fa289b65eb6f639628cd1f04ead6f3b5e6db247fcdc3a0e14d4 (x13)' -> READ
claim probe_cs_sha256_prefix stated='28bc05d5...' computed='28bc05d5 (x13)' -> READ
claim probe_proof_hash_first stated='77f7b126...' computed='77f7b126 (x10)' -> READ
claim filter_BLOCK_weight_stale stated='BLOCK (0x1001), weight 0x1000, stale SID ...-91763, layer ALE_AUTH_CONNECT_V4 (c38d57d1-...)' computed='0x00001001 0x1000 S-1-5-21-Y-Y-Y-91763 c38d57d1-05a7-4c33-904f-7fbceee60e82 (x13)' -> READ
claim filter_persistent_nondynamic_session stated='persistent filter; non-dynamic session' computed='flags=0x00000001 session_flags=0 (x13)' -> READ
claim sweep_before_each_control_phase_clean stated='read clean' computed='taskcheck pre_cleanup.sweep_before.clean=True; n1 pre_cleanup.sweep_before.clean=True; n1 per-pass sweep_before=True (x3); taskcheck per-pass sweep_before=no key (x1)' -> READ
claim N1_phase_time stated='n1 phase re-run 2026-10-19 at 16:49' computed='2026-10-19T16:49' -> READ
claim scheduled_tasks_327 stated='327 scheduled tasks (by-hand check)' computed='327' -> READ

# README hash table, structure and statements about other files
readme.hash_table_rows = 40; published files (excluding README.md, .sanitized, RECOUNT.md) = 40
readme.hash_table_rows_matching = 40
readme.states 47fcd179 = True
readme.states 4c0b559e = True
readme.states 4fde1ad6 = True
git 1ed25f50:scripts/spike-nep5-c4-driver.ps1 sha256(LF) = 47fcd179b28f15b6deb9d9bfeb41ee501f7e43ee8824364c2bc757707f6c031a
git 1881f15d:scripts/spike-nep5-c4-driver.ps1 sha256(LF) = 4c0b559eb47014c6b69d43573d29cf6af8d5bc0784c9a402ad5a273c7c9e3fdd
git 21cb384d:probe/NcoProbe.cs sha256(LF) = 28bc05d583135c446ae5dff073907b42c855e522123ba7106c76ff185a42f794
git e4383096:scripts/spike-nep5-c4-driver.ps1 sha256(LF) = c48019a31aab0f1a3a49297fc5d39bc272b53eac0bcc3023e0ad16a2bad92be2
git 4ebad95c:scripts/spike-nep5-c4-driver.ps1 sha256(LF) = 06d63d9764846df0b5038e17d674ed60b84daf8cb3235f1e653308bd050102c1
git 1ed25f50:scripts/case4-lock-corpus.json sha256(LF) = f98304092c2e4ac06feba76cbcc5f9c0bb86fea4f8d0aed7c9a8c4b70b3f97bc
git 1881f15d:scripts/case4-lock-corpus.json sha256(LF) = f98304092c2e4ac06feba76cbcc5f9c0bb86fea4f8d0aed7c9a8c4b70b3f97bc
git 4ebad95c:scripts/case4-lock-corpus.json sha256(LF) = f98304092c2e4ac06feba76cbcc5f9c0bb86fea4f8d0aed7c9a8c4b70b3f97bc
readme.paths_named = 46; not in this folder = ['PROVENANCE.md', 'runs/case4-F-20261020-051400-5880.json', 'runs/controls/remove-20261019-164737.json'] (PROVENANCE.md is read at the repository root)
as_run.line14 has 47fcd179 = True; line81 has 47fcd179 = True; line82 has 4c0b559e = True; lines 83-84 have [True, True]
renamed.file_name_spelling old-only: runs/AS_RUN.md, runs/case4-F-20261020-051400-05880.json, runs/case4-collect-20261020-012258.json, runs/case4-collect-20261020-012313.json, runs/results-summary.json
renamed.file_name_spelling new:  (none)
case4-prepare-20261020-004848.json: has key 'text' = False; has 'netsh_text' = True
case4-prepare-20261020-092824.json: has key 'text' = False; has 'netsh_text' = True
case4-final-20261020-012312.json: has key 'text' = False; has 'netsh_text' = True
case4-final-20261020-102928.json: has key 'text' = False; has 'netsh_text' = True
case4-partd-20261020-014216.json: has key 'text' = False; has 'netsh_text' = True
case4-partd-20261020-110756.json: has key 'text' = False; has 'netsh_text' = True
sid.domains = S-1-5-21-X-X-X (x115), S-1-5-21-Y-Y-Y (x49)
git log main --format=%h -- probe/build-probe.ps1: ['fa96f8e7']
git log main --format=%h -- probe/run-probe-selftest.ps1: ['fa96f8e7']
git log main --format=%h -- scripts/run-limited.ps1: ['fa96f8e7']
git: e4383096 is ancestor of main = True
git: 4ebad95c is ancestor of main = True
git: 1ed25f50 is ancestor of main = True
git: 1881f15d is ancestor of main = True
git: 21cb384d is ancestor of main = True
main-line driver sha256(LF) = 06d63d9764846df0b5038e17d674ed60b84daf8cb3235f1e653308bd050102c1
main-line NcoProbe.cs sha256(LF) = 28bc05d583135c446ae5dff073907b42c855e522123ba7106c76ff185a42f794
main-line case4-lock-corpus.json sha256(LF) = f98304092c2e4ac06feba76cbcc5f9c0bb86fea4f8d0aed7c9a8c4b70b3f97bc

# originals
raw.files = 28; published.files = 28
raw.only_in_published = []
raw.only_in_raw = []
raw.compare.identical after recorded replacements, 6 hand-edited lines skipped = 1
raw.compare.identical after recorded replacements = 27
as_run.file_table_rows = 28
as_run.file_table_rows_matching_originals = 28 of 28
collect.sha256 values stated = 13; equal to a hash of an original in nco/runs = 0; equal to a hash of a published file = 0
AS_RUN table hashes equal to a hash of a published file = 1 of 39
  AS_RUN table: f98304092c2e is also the hash of a published file
results-summary sha256_lf hashes equal to a hash of a published file = 0 of 13
summary.sha256_lf vs originals = compared (13 records)
figure_names.published = 167; figure_names.original = 167; figures differing as written = 5; still differing after the recorded replacements are applied to the original = 0

total.differences = 6
```

Differences reported (each is a line `DIFF` above; the README states none of these figures):

- `results-summary.json`, E records: `clock_start_utc` holds the record's `clock.utc` (13:33:12.484Z, 13:37:10.256Z,
  13:42:29.785Z), which is 13 to 16 ms after the record's own `clock_start.utc` (.471Z, .240Z, .769Z).
- `results-summary.json`, A records: `add.filter_id` is absent from the summary; the records hold 537361, 537362, 537363.
