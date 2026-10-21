#!/usr/bin/env python3
"""Recount every figure the README of this folder states, from the run records, and print them as `name = value`
lines. Standard library only.

  python recount.py <folder>                              print the figures
  python recount.py <folder> --raw <raw-folder>           also compare against the unsanitised originals
  python recount.py <folder> --raw <raw> --repo <repo>    also recompute the hashes of the bytes that ran from git
  ... --local <file>                                      the sanitiser's local-vocabulary file (its "replacements" pairs), applied when
                                                          comparing; without it, lines those pairs changed show as residue

Sources read for the figures, and nothing else: `runs/case4-{F,S,A,E}-*.json` (the probe records),
`runs/case4-{prepare,collect,final,partd}-*.json` (the driver's records), `runs/controls/*.json`,
`runs/results-summary.json` and `runs/AS_RUN.md`. Per-condition figures are recomputed from each probe record's own
fields (`cond`, `elevation_type`, `nco_group`, `administrators`, `add`, `delete`, `residue`, ...). The records' own
summary fields (the collect records' `valid`, `results-summary.json`) are printed beside under a `record.` name and never
used in their place. The claims table holds each value the README states, typed in; it is compared
with the value computed here (`claim` lines: ok when equal, DIFFERS when a stated count differs, READ when the stated text is
prose and is read against the computed text). The README's hash table, the files it names and the hashes it quotes are
parsed from the README and checked against the folder.

With `--raw`, every record is compared with its original: the original's text is passed through the sanitiser's
recorded replacements (listed in RULES below, plus the local pairs given with --local) and must then equal the published text byte for byte; any residue is a
difference and is printed. With `--repo`, the sha256 (LF) of the driver, probe source and lock corpus at the commits
the README names is computed from git and compared with the README's table.

Exit status: 1 on any difference, any claim that disagrees with its record, or any residue; else 0. Run on this folder it
exits 1 on the 6 differences inside results-summary.json that RECOUNT.md lists; any other difference is new.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

JsonObj = dict[str, Any]
CRLF, LF = bytes([13, 10]), bytes([10])

PROBE_GLOB = "case4-[FSAE]-*.json"
STALE_RID = "91763"  # relative id of the fabricated stale SID: its domain reads Y, every other domain SID reads X
_BS = chr(92)
RULES: list[tuple[str, object]] = [
    # (pattern, replacement) in the order the sanitiser applies them; each is a recorded replacement
    (r"S-1-5-21-\d+-\d+-\d+-(\d+)", lambda m: f"S-1-5-21-{'Y' if m.group(1) == STALE_RID else 'X'}-{'Y' if m.group(1) == STALE_RID else 'X'}-"
        f"{'Y' if m.group(1) == STALE_RID else 'X'}-{m.group(1)}"),
    (r"#\d{4} ", ""),                                         # the internal-tracker reference before a title
    (r"harness-live-proof-\d{4}\.json", "harness-live-proof.json"),
    ("C:" + _BS * 4 + "Users" + _BS * 4 + "_+[A-Z]+_+" + _BS * 4, lambda m: "~" + _BS * 2),   # the operator's home folder, JSON-escaped
    ("C:" + _BS * 4 + "Users" + _BS * 4 + "nco-probe", "~nco-probe"),
]
UNPUBLISHED = {"runs/controls/remove-20261019-164737.json"}   # an original that is not part of this folder
LOCAL_PAIRS: list[tuple[str, str]] = []   # the sanitiser's local-vocabulary pairs, read from the file given with --local
HAND_EDITED = {"runs/AS_RUN.md": {13, 14, 76, 77, 84, 108}}   # lines of a published file edited by hand (listed in PROVENANCE.md); skipped when comparing
RENAMED = {"runs/case4-F-20261020-051400-5880.json": "runs/case4-F-20261020-051400-05880.json"}


def _load(p: Path) -> JsonObj:
    obj: JsonObj = json.loads(p.read_text(encoding="utf-8-sig"))
    return obj


def _lf_sha(b: bytes) -> str:
    return hashlib.sha256(b.replace(b"\r\n", b"\n")).hexdigest()


def _hms(s: str) -> str:
    return s[11:19]


class Folder:
    def __init__(self, root: Path, skip: set[str] = frozenset()) -> None:  # type: ignore[assignment]
        self.root = root
        runs = root / "runs"
        self.probe = {p.name: _load(p) for p in sorted(runs.glob(PROBE_GLOB))}
        self.kind = {k: {p.name: _load(p) for p in sorted(runs.glob(f"case4-{k}-*.json"))}
                     for k in ("prepare", "collect", "final", "partd")}
        self.controls = {p.name: _load(p) for p in sorted((runs / "controls").glob("*.json"))
                         if "runs/controls/" + p.name not in skip}
        self.summary = _load(runs / "results-summary.json")
        self.as_run = (runs / "AS_RUN.md").read_text(encoding="utf-8")

    def cond(self, c: str) -> list[JsonObj]:
        return [r for r in self.probe.values() if r["cond"] == c]


def _vals(rs: list[JsonObj], f: Any) -> str:
    return ", ".join(f"{k} (x{v})" for k, v in sorted(Counter(str(f(r)) for r in rs).items()))


def figures(fo: Folder) -> dict[str, object]:
    fig: dict[str, object] = {}
    fig["files.probe_records"] = len(fo.probe)
    fig["files.probe_records.by_cond"] = _vals(list(fo.probe.values()), lambda r: r["cond"])
    for k, d in fo.kind.items():
        fig[f"files.{k}"] = len(d)
    fig["files.controls"] = len(fo.controls)
    fig["probe.exe_sha256"] = _vals(list(fo.probe.values()), lambda r: r["probe_exe_sha256"])
    fig["probe.cs_sha256"] = _vals(list(fo.probe.values()), lambda r: r["probe_cs_sha256"])
    fig["probe.version/toggle_build"] = _vals(list(fo.probe.values()), lambda r: f"{r['probe_version']}/{r['toggle_build']}")
    fig["probe.proof_sha256 by cond"] = "; ".join(
        f"{c}: {_vals(fo.cond(c), lambda r: r['proof']['sha256'][:8])}" for c in "FSAE")
    fig["probe.filter"] = _vals(list(fo.probe.values()), lambda r: (
        f"key={r['filter']['key']} action={r['filter']['action']} weight={r['filter']['weight']} "
        f"flags={r['filter']['flags']} layer={r['filter']['layer']} stale={r['filter']['user_sid']}"))
    fig["probe.stale_sid.mapped/lookup_error"] = _vals(list(fo.probe.values()),
                                                       lambda r: f"{r['stale_sid']['mapped']}/{r['stale_sid']['lookup_error']}")
    fig["probe.engine_session_flags/open_rc"] = _vals(list(fo.probe.values()), lambda r: (
        f"{r['engine']['open']['session_flags']}/{r['engine']['open']['rc']}/closed={r['engine']['closed']}"))
    for c in "FESA":
        rs = fo.cond(c)
        p = f"cond.{c}."
        fig[p + "n"] = len(rs)
        fig[p + "user_rid"] = _vals(rs, lambda r: r["user_sid"].rsplit("-", 1)[1])
        fig[p + "is_expected_account"] = _vals(rs, lambda r: r["is_expected_account"])
        fig[p + "elevation_type"] = _vals(rs, lambda r: f"{r['elevation_type']['value']} {r['elevation_type']['label']}")
        fig[p + "integrity"] = _vals(rs, lambda r: f"{r['integrity']['sid']} {r['integrity']['label']}")
        fig[p + "linked_token"] = _vals(rs, lambda r: f"present={r['linked_token']['present']} err={r['linked_token']['error']}")
        fig[p + "session"] = _vals(rs, lambda r: r["session_id"]["value"])
        fig[p + "nco_group"] = _vals(rs, lambda r: (
            f"present={r['nco_group']['present']} attr={r['nco_group'].get('attributes')} "
            f"enabled={r['nco_group'].get('enabled')} deny_only={r['nco_group'].get('use_for_deny_only')}"))
        fig[p + "administrators"] = _vals(rs, lambda r: (
            f"present={r['administrators']['present']} attr={r['administrators'].get('attributes')}"))
        fig[p + "add.rc/class"] = _vals(rs, lambda r: f"{r['add']['rc']} {r['add']['class']}")
        fig[p + "add.filter_id"] = ", ".join(str(r["add"]["filter_id"]) for r in rs)
        fig[p + "add.present_after"] = _vals(rs, lambda r: r["add"]["present_after"])
        fig[p + "delete.rc/class"] = _vals(rs, lambda r: f"{r['delete']['rc']} {r['delete']['class']}")
        fig[p + "delete.present_after"] = _vals(rs, lambda r: r["delete"]["present_after"])
        fig[p + "residue/overall/exit"] = _vals(rs, lambda r: f"{r['residue']}/{r['overall']}/{r['exit']}")
        fig[p + "sequence_complete"] = _vals(rs, lambda r: r["sequence_complete"])
        fig[p + "clock_start_local"] = " / ".join(_hms(r["clock_start"]["local"]) for r in rs)
        fig[p + "zone"] = _vals(rs, lambda r: r["clock_start"]["local"][-6:])
        fig[p + "pids"] = ", ".join(str(r["pid"]) for r in rs)
    # N1: the standard-token control
    n1 = next(v for k, v in fo.controls.items() if "-n1-" in k)
    fig["cond.N1.n"] = len(n1["records"])
    fig["cond.N1.add.rc/class"] = _vals(n1["records"], lambda r: f"{r['steps']['n1_add']['direct']['rc_hex']} {r['steps']['n1_add']['class']}")
    fig["cond.N1.delete.rc/class"] = _vals(n1["records"], lambda r: f"{r['steps']['n1_delete']['direct']['rc_hex']} {r['steps']['n1_delete']['class']}")
    fig["cond.N1.sweep_before/after_clean"] = _vals(n1["records"], lambda r: f"{r['steps']['sweep_before']['clean']}/{r['steps']['sweep_after']['clean']}")
    fig["cond.N1.started"] = f"{n1['started'][:19]} .. {n1['finished'][:19]} exit={n1['exit_code']}"
    tc = next(v for k, v in fo.controls.items() if "taskcheck" in k)
    fig["control.taskcheck.passes/classes"] = f"{tc['passes']} / {_vals(tc['records'], lambda r: r['class'])}"
    fig["control.taskcheck.sweep_before_clean"] = _vals(tc["records"], lambda r: r["steps"]["sweep_before"]["clean"]) \
        if "sweep_before" in tc["records"][0].get("steps", {}) else "no sweep_before key"
    fig["control.taskcheck.started"] = f"{tc['started'][:19]} .. {tc['finished'][:19]} exit={tc['exit_code']}"
    fig["control.n1+taskcheck.pre_cleanup"] = f"n1: {n1['pre_cleanup']['Reason']}; taskcheck: {tc['pre_cleanup']['Reason']}"
    # driver records
    for name, c in sorted(fo.kind["collect"].items()):
        fig[f"collect.{name}.at/code"] = f"{c['at'][:19]} / {c['code']}"
        by = Counter(v["file"].split("-")[1] for v in c["valid"])
        fig[f"collect.{name}.valid/invalid"] = f"{len(c['valid'])} ({dict(sorted(by.items()))}) / {len(c['invalid'])}"
        fig[f"collect.{name}.refused given/counted/note"] = (
            f"{c['elevation_refused']['given']}/{c['elevation_refused']['counted']}/{c['elevation_refused']['note']}")
        fig[f"collect.{name}.left_behind/foreign/wrong_account"] = f"{len(c['left_behind'])}/{len(c['foreign'])}/{len(c['wrong_account'])}"
        fig[f"collect.{name}.residue.readable/enum_skipped"] = f"{c['residue']['readable']}/{c['residue']['enum_skipped']}"
        fig[f"collect.{name}.copies.status"] = _vals(c["copies"], lambda x: x["status"])
    for name, f in sorted(fo.kind["final"].items()):
        fig[f"final.{name}.at"] = f["at"][:19]
        fig[f"final.{name}.verified/code/error"] = f"{f['verified']}/{f['code']}/{f['error']}"
        fig[f"final.{name}.collect.code/valid/invalid"] = f"{f['collect']['code']}/{f['collect']['valid']}/{len(f['collect']['invalid'])}"
        fig[f"final.{name}.probe_key_delete/after"] = f"{f['probe_key_delete']}/{f['probe_key_after']}"
        fig[f"final.{name}.removal.ok/steps/errors"] = f"{f['removal']['ok']}/{len(f['removal']['steps'])}/{len(f['removal']['errors'])}"
        fig[f"final.{name}.removal.steps"] = _vals(f["removal"]["steps"], lambda s: f"{s['step']}:{s['status']}")
        fig[f"final.{name}.sweep.clean/export_hits"] = f"{f['sweep']['clean']}/{f['sweep']['export']['hits']['total']}"
        fig[f"final.{name}.engine_sd.same/removed/added"] = (
            f"{f['engine_sd']['compare']['same']}/{len(f['engine_sd']['compare']['removed'])}/{len(f['engine_sd']['compare']['added'])}")
        fig[f"final.{name}.folder.removed/uncopied"] = f"{f['folder'].get('removed', 'key absent')}/{len(f['folder']['uncopied'])}"
    for name, p in sorted(fo.kind["partd"].items()):
        fig[f"partd.{name}.at/code"] = f"{p['at'][:19]} / {p['code']}"
        fig[f"partd.{name}.net_user/lookup_err/members/profile_present/list_entry_present/profile_folders"] = (
            f"{p['net_user']['state']}/{p['lookup']['Error']}/{len(p['members'])}/{p['profile_present']}/"
            f"{p['profile_list_entry']['Present']}/{len(p['profile_folders'])}")
        fig[f"partd.{name}.account_sid"] = p["account_sid"]
    for name, p in sorted(fo.kind["prepare"].items()):
        eng = p["security"]["engine"]["netsh_text"]
        fig[f"prepare.{name}.at"] = p["at"][:19]
        fig[f"prepare.{name}.nco_ace_in_engine_sd"] = "(A;;0x307ff;;;NO)" in eng
        fig[f"prepare.{name}.sweep.clean"] = p["sweep"]["clean"]
        fig[f"prepare.{name}.probe_proof.sha256/written_utc"] = f"{p['probe_proof']['sha256'][:8]} / {p['probe_proof']['content']['written_utc']}"
        fig[f"prepare.{name}.nco_sid"] = p["nco_sid"]
    pre = list(sorted(fo.kind["prepare"].items()))
    fin = list(sorted(fo.kind["final"].items()))
    for (pn, p), (fname, f) in zip(pre, fin):
        fig[f"engine_sd.prepare {pn[-19:-5]} == finish {fname[-19:-5]}"] = (
            p["security"]["engine"]["netsh_text"] == f["engine_sd"]["now"]["netsh_text"])
    # results-summary (printed beside, never used)
    s = fo.summary
    fig["record.results-summary.counts"] = json.dumps(s["counts"], sort_keys=True)
    fig["record.results-summary.records"] = len(s["records"])
    return fig


def cross_checks(fo: Folder, fig: dict[str, object]) -> list[str]:
    """Disagreements between a summary and the records it summarises."""
    out: list[str] = []
    s = fo.summary
    by_file = {k: v for k, v in fo.probe.items()}
    for rec in s["records"]:
        fn = RENAMED.get("runs/" + rec["file"], "runs/" + rec["file"])[5:]
        # the summary names the original spelling; the folder holds the renamed file
        src = by_file.get(fn) or by_file.get(rec["file"])
        if src is None:
            out.append(f"results-summary names {rec['file']}: no such probe record")
            continue
        checks = {
            "cond": (rec["cond"], src["cond"]),
            "elevation_type": (rec["elevation_type"], src["elevation_type"]["value"]),
            "add.rc": (rec["add"]["rc"], src["add"]["rc"]),
            "delete.rc": (rec["delete"]["rc"], src["delete"]["rc"]),
            "add.present_after": (rec["add"]["present_after"], src["add"]["present_after"]),
            "delete.present_after": (rec["delete"]["present_after"], src["delete"]["present_after"]),
            "add.filter_id": (rec["add"].get("filter_id"), src["add"].get("filter_id")),
            "nco_group.present": (rec["nco_group"]["present"], src["nco_group"]["present"]),
            "nco_group.attributes": (rec["nco_group"]["attributes"], src["nco_group"].get("attributes")),
            "administrators.present": (rec["administrators"]["present"], src["administrators"]["present"]),
            "administrators.attributes": (rec["administrators"]["attributes"], src["administrators"].get("attributes")),
            "is_expected_account": (rec["is_expected_account"], src["is_expected_account"]),
            "integrity": (rec["integrity"], src["integrity"]["label"]),
            "linked_token_present": (rec["linked_token_present"], src["linked_token"]["present"]),
            "residue": (rec["residue"], src["residue"]),
            "overall/exit": ((rec["overall"], rec["exit"]), (src["overall"], src["exit"])),
            "clock_start_utc": (rec["clock_start_utc"], src["clock_start"]["utc"]),
        }
        for k, (a, b) in checks.items():
            if a != b:
                out.append(f"results-summary {rec['file']} {k}: summary={a!r} record={b!r}")
    if len(s["records"]) != len(fo.probe):
        out.append(f"results-summary lists {len(s['records'])} records, folder holds {len(fo.probe)}")
    return out


# ---- claims: each README statement, with the value the records give --------------------------------------------

def claims(fo: Folder, fig: dict[str, object]) -> list[tuple[str, str, str, str]]:
    """(id, README location, stated, computed)."""
    P = fo.probe
    F, E, S, A = (fo.cond(c) for c in "FESA")
    cl: list[tuple[str, str, str, str]] = []

    def add(i: str, where: str, stated: object, computed: object) -> None:
        cl.append((i, where, str(stated), str(computed)))

    def allrc(rs: list[JsonObj], k: str, rc: str) -> int:
        return sum(1 for r in rs if r[k]["rc"] == rc)

    add("F.n", "L64,L107", 4, len(F))
    add("F.add_denied_0x5", "L15-16,L107", "4 of 4", f"{allrc(F, 'add', '0x00000005')} of {len(F)}")
    add("F.delete_0x80320003", "L107", "4 of 4", f"{allrc(F, 'delete', '0x80320003')} of {len(F)}")
    add("F.elevation_type_3", "L14-15", "4 of 4", f"{sum(1 for r in F if r['elevation_type']['value'] == 3)} of {len(F)}")
    add("F.group_attr_0x10", "L15,L107", "4 of 4", f"{sum(1 for r in F if r['nco_group']['attributes'] == '0x00000010' and r['nco_group']['use_for_deny_only'])} of {len(F)}")
    add("F.linked_token_present,medium,session1", "L107", "4 of 4",
        f"{sum(1 for r in F if r['linked_token']['present'] and r['integrity']['label'] == 'medium' and r['session_id']['value'] == 1)} of {len(F)}")
    add("F.admins_absent,none_left", "L107", "4 of 4", f"{sum(1 for r in F if not r['administrators']['present'] and r['residue'] == 'absent')} of {len(F)}")
    add("E.n", "L66,L109", 3, len(E))
    add("E.add_0x0", "L22,L109", "3 of 3", f"{allrc(E, 'add', '0x00000000')} of {len(E)}")
    add("E.delete_0x0", "L22,L109", "3 of 3", f"{allrc(E, 'delete', '0x00000000')} of {len(E)}")
    add("E.filter_ids", "L23,L109", "537392, 537393, 537394", ", ".join(str(r["add"]["filter_id"]) for r in E))
    add("E.present_after_add_absent_after_delete", "L23-24", "3 of 3",
        f"{sum(1 for r in E if r['add']['present_after'] and not r['delete']['present_after'])} of {len(E)}")
    add("E.elevation_type_1_no_linked_token_error", "L21,L109", "3 of 3",
        f"{sum(1 for r in E if r['elevation_type']['value'] == 1 and not r['linked_token']['present'] and r['linked_token']['error'] == 1312)} of {len(E)}")
    add("E.group_attr_0x7", "L21,L109", "3 of 3", f"{sum(1 for r in E if r['nco_group']['attributes'] == '0x00000007' and r['nco_group']['enabled'])} of {len(E)}")
    add("E.integrity_8448_session0", "L21,L109", "3 of 3",
        f"{sum(1 for r in E if r['integrity']['sid'] == 'S-1-16-8448' and r['session_id']['value'] == 0)} of {len(E)}")
    add("E.admins_absent,none_left", "L109", "3 of 3", f"{sum(1 for r in E if not r['administrators']['present'] and r['residue'] == 'absent')} of {len(E)}")
    add("S.n/add_denied/delete_0x80320003", "L110", "3; 3 of 3; 3 of 3", f"{len(S)}; {allrc(S, 'add', '0x00000005')} of {len(S)}; {allrc(S, 'delete', '0x80320003')} of {len(S)}")
    add("S.elev3,admins_0x10,nco_absent", "L110", "3 of 3",
        f"{sum(1 for r in S if r['elevation_type']['value'] == 3 and r['administrators']['attributes'] == '0x00000010' and not r['nco_group']['present'])} of {len(S)}")
    add("A.n/add_ok/delete_ok", "L111", "3; 3 of 3; 3 of 3", f"{len(A)}; {allrc(A, 'add', '0x00000000')} of {len(A)}; {allrc(A, 'delete', '0x00000000')} of {len(A)}")
    add("A.elev2,admins_0xF,nco_absent,none_left", "L111", "3 of 3",
        f"{sum(1 for r in A if r['elevation_type']['value'] == 2 and r['administrators']['attributes'] == '0x0000000F' and not r['nco_group']['present'] and r['residue'] == 'absent')} of {len(A)}")
    add("F,E.is_expected_account_true", "L114", "7 of 7", f"{sum(1 for r in F + E if r['is_expected_account'])} of {len(F + E)}")
    add("S,A.is_expected_account_false", "L114", "6 of 6", f"{sum(1 for r in S + A if not r['is_expected_account'])} of {len(S + A)}")
    n1 = next(v for k, v in fo.controls.items() if "-n1-" in k)["records"]
    add("N1.n/add/delete_0x5", "L112,L188", "3; 3 of 3; 3 of 3",
        f"{len(n1)}; {sum(1 for r in n1 if r['steps']['n1_add']['direct']['rc_hex'] == '0x00000005')} of {len(n1)}; "
        f"{sum(1 for r in n1 if r['steps']['n1_delete']['direct']['rc_hex'] == '0x00000005')} of {len(n1)}")
    add("probe_records_total", "L237", "13 (F 4, S 3, A 3, E 3)", f"{len(P)} (F {len(F)}, S {len(S)}, A {len(A)}, E {len(E)})")
    col = fo.kind["collect"]
    add("driver_record_files", "L238", "2 prepare, 5 collect, 2 final, 2 part D",
        f"{len(fo.kind['prepare'])} prepare, {len(col)} collect, {len(fo.kind['final'])} final, {len(fo.kind['partd'])} part D")
    c1 = col["case4-collect-20261020-012258.json"]
    add("collect1.valid/invalid", "L116", "10 valid, 0 invalid (F 4, S 3, A 3)",
        f"{len(c1['valid'])} valid, {len(c1['invalid'])} invalid ({', '.join(f'{k} {v}' for k, v in sorted(Counter(v['file'].split('-')[1] for v in c1['valid']).items()))})")
    c2 = col["case4-collect-20261020-102913.json"]
    add("collect2.valid/invalid", "L116-117", "3 valid, 0 invalid (E 3)", f"{len(c2['valid'])} valid, {len(c2['invalid'])} invalid (E {sum(1 for v in c2['valid'] if '-E-' in v['file'])})")
    note = c1["elevation_refused"]["note"] or ""
    add("E_route1.refusals", "L16-18,L65,L108", "4 (cancelled four times)",
        f"{'four' if 'four times' in note else 'unparsed'}; counted={c1['elevation_refused']['counted']}; no E record in first sitting's collect: "
        f"{sum(1 for v in c1['valid'] if '-E-' in v['file'])}")
    add("E_route1.in_summary", "L108,L186", "4 attempts, 0 runs", f"{fo.summary['counts']['E_prompt_route_refusals']} refusals; prompt_route.n={fo.summary['per_condition']['E']['prompt_route']['n']}")
    c102824 = col["case4-collect-20261020-102824.json"]
    add("second_collect.first.exit_21_enum_skipped", "L128-129", "exit 21, enumeration skipped, 3 valid",
        f"exit {c102824['code']}, enum_skipped={c102824['residue']['enum_skipped']}, {len(c102824['valid'])} valid")
    add("second_collect.rerun.exit_0", "L130-131", "10:29:13, exit 0, residue readable, nothing left behind",
        f"{c2['at'][11:19]}, exit {c2['code']}, readable={c2['residue']['readable']}, left_behind={len(c2['left_behind'])}")
    add("first_collect.time", "L128", "10:28:24", c102824["at"][11:19])
    f1 = fo.kind["final"]["case4-final-20261020-012312.json"]
    add("final1.verified_false_code7", "L124-127", "verified false, code 7", f"verified {f1['verified']}, code {f1['code']}")
    pd1 = fo.kind["partd"]["case4-partd-20261020-014216.json"]
    pd2 = fo.kind["partd"]["case4-partd-20261020-110756.json"]
    add("partd1.time/exit", "L127", "01:42:16, exit 20", f"{pd1['at'][11:19]}, exit {pd1['code']}")
    add("partd2.time/exit", "L136", "11:07:56, exit 20", f"{pd2['at'][11:19]}, exit {pd2['code']}")
    add("partd.four_items_absent", "L127,L136", "all four absent (both)", all(
        p["net_user"]["state"] == "absent" and p["lookup"]["Error"] == 1332 and not p["members"] and not p["profile_list_entry"]["Present"]
        and not p["profile_folders"] and not p["profile_present"] for p in (pd1, pd2)))
    add("rids", "L43", "2250 then 2251", f"{_vals(F, lambda r: r['user_sid'].rsplit('-', 1)[1])} then {_vals(E, lambda r: r['user_sid'].rsplit('-', 1)[1])}")
    add("F_times", "L146", "4 F runs between 01:05 and 01:15", " ".join(_hms(r["clock_start"]["local"]) for r in F))
    add("S_A_times", "L146-147", "S and A runs each within 3 seconds (01:21:45 to 01:22:43)",
        f"S {_hms(S[0]['clock_start']['local'])}..{_hms(S[-1]['clock_start']['local'])}; A {_hms(A[0]['clock_start']['local'])}..{_hms(A[-1]['clock_start']['local'])}")
    add("E_times", "L147", "09:33:12, 09:37:10, 09:42:29 over 9 minutes", " ".join(_hms(r["clock_start"]["local"]) for r in E))
    pre = fo.kind["prepare"]
    p1, p2 = pre["case4-prepare-20261020-004848.json"], pre["case4-prepare-20261020-092824.json"]
    add("sitting1.span", "L41", "00:48 to 01:43", f"prepare {p1['at'][11:19]}; partd {pd1['at'][11:19]} (01:43 is the by-hand folder removal, AS_RUN)")
    add("sitting2.span", "L41", "09:28 to 11:12", f"prepare {p2['at'][11:19]}; partd {pd2['at'][11:19]} (11:12 is the by-hand check, AS_RUN)")
    add("control_records.window", "L41", "2026-10-19, 16:49 to 16:51", " ".join(sorted(
        [v["at"][:19] if "at" in v else v["started"][:19] for k, v in fo.controls.items()] +
        [v["finished"][:19] for v in fo.controls.values() if "finished" in v])))
    add("engine_acl_identical_before_after", "L45", "identical both times in both sittings",
        all(pre[a]["security"]["engine"]["netsh_text"] == fo.kind["final"][b]["engine_sd"]["now"]["netsh_text"]
            for a, b in (("case4-prepare-20261020-004848.json", "case4-final-20261020-012312.json"),
                         ("case4-prepare-20261020-092824.json", "case4-final-20261020-102928.json"))))
    add("engine_acl_group_entry", "L28,L45", "(A;;0x307ff;;;NO) present", all("(A;;0x307ff;;;NO)" in p["security"]["engine"]["netsh_text"] for p in (p1, p2)))
    add("probe_sha256", "L46", "4fde1ad6...3a0e14d4 in every probe record", _vals(list(P.values()), lambda r: r["probe_exe_sha256"]))
    add("probe_cs_sha256_prefix", "L46", "28bc05d5...", _vals(list(P.values()), lambda r: r["probe_cs_sha256"][:8]))
    add("probe_proof_hash_first", "AS_RUN L17", "77f7b126...", _vals([r for r in P.values() if r["cond"] != "E"], lambda r: r["proof"]["sha256"][:8]))
    add("filter_BLOCK_weight_stale", "L44", "BLOCK (0x1001), weight 0x1000, stale SID ...-91763, layer ALE_AUTH_CONNECT_V4 (c38d57d1-...)",
        _vals(list(P.values()), lambda r: f"{r['filter']['action']} {r['filter']['weight']} {r['filter']['user_sid']} {r['filter']['layer']}"))
    add("filter_persistent_nondynamic_session", "L44,L54-55", "persistent filter; non-dynamic session",
        _vals(list(P.values()), lambda r: f"flags={r['filter']['flags']} session_flags={r['engine']['open']['session_flags']}"))
    ctl = fo.controls
    tcn = next(v for k, v in ctl.items() if "taskcheck" in k)
    n1r = next(v for k, v in ctl.items() if "-n1-" in k)
    add("sweep_before_each_control_phase_clean", "L141-142", "read clean",
        f"taskcheck pre_cleanup.sweep_before.clean={tcn['pre_cleanup']['Steps']['sweep_before']['clean']}; "
        f"n1 pre_cleanup.sweep_before.clean={n1r['pre_cleanup']['Steps']['sweep_before']['clean']}; "
        f"n1 per-pass sweep_before={_vals(n1r['records'], lambda r: r['steps']['sweep_before']['clean'])}; "
        f"taskcheck per-pass sweep_before={_vals(tcn['records'], lambda r: r['steps'].get('sweep_before', {}).get('clean', 'no key'))}")
    add("N1_phase_time", "L69", "n1 phase re-run 2026-10-19 at 16:49", n1r["started"][:16])
    add("scheduled_tasks_327", "L137", "327 scheduled tasks (by-hand check)",
        "327" if "327" in fo.as_run else "absent from AS_RUN.md; unsettled by records")
    return cl


# ---- raw comparison ------------------------------------------------------------------------------------------

def normalise_raw(text: str, rel: str) -> str:
    for pat, rep in RULES:
        text = re.sub(pat, rep, text)  # type: ignore[arg-type]
    for a, b in LOCAL_PAIRS:
        text = re.sub(r"(?<!\w)" + re.escape(a) + r"(?!\w)", b, text)
    return text


def compare_raw(pub: Path, raw: Path) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    diffs: list[str] = []
    pubfiles = sorted(p.relative_to(pub).as_posix() for p in (pub / "runs").rglob("*") if p.is_file())
    rawfiles = sorted(p.relative_to(raw).as_posix() for p in (raw / "runs").rglob("*") if p.is_file()
                      and p.relative_to(raw).as_posix() not in UNPUBLISHED)
    mapped = [RENAMED.get(r, r) for r in rawfiles]
    lines.append(f"raw.files = {len(rawfiles)}; published.files = {len(pubfiles)}")
    only_pub = sorted(set(pubfiles) - set(mapped))
    only_raw = sorted(set(mapped) - set(pubfiles))
    lines.append(f"raw.only_in_published = {only_pub}")
    lines.append(f"raw.only_in_raw = {only_raw}")
    if only_pub or only_raw:
        diffs.append(f"file sets differ: only published {only_pub}; only raw {only_raw}")
    counts = Counter()
    for rr in rawfiles:
        pr = RENAMED.get(rr, rr)
        if pr not in pubfiles:
            continue
        rb = (raw / rr).read_bytes()
        pb = (pub / pr).read_bytes()
        rt = normalise_raw(rb.decode("utf-8"), pr)
        pt = pb.decode("utf-8")
        skip = HAND_EDITED.get(pr, set())
        if skip:
            ra_, pa_ = rt.split("\n"), pt.split("\n")
            keep = [i for i in range(max(len(ra_), len(pa_))) if i + 1 not in skip]
            same = len(ra_) == len(pa_) and all(ra_[i] == pa_[i] for i in keep)
            if same:
                counts[f"identical after recorded replacements, {len(skip)} hand-edited lines skipped"] += 1
                continue
        if rt == pt:
            counts["identical after recorded replacements"] += 1
            if rb == pb:
                counts["byte-identical with no replacement"] += 1
        else:
            counts["residue"] += 1
            ra, pa = rt.splitlines(), pt.splitlines()
            for n, (x, y) in enumerate(zip(ra, pa), 1):
                if x != y:
                    diffs.append(f"{pr} line {n}: raw(after rules)={x[:160]!r} published={y[:160]!r}")
                    break
            else:
                diffs.append(f"{pr}: line counts raw {len(ra)} published {len(pa)}")
    for k, v in counts.items():
        lines.append(f"raw.compare.{k} = {v}")
    return lines, diffs


def hash_checks(fo: Folder, raw: Path) -> tuple[list[str], list[str]]:
    """AS_RUN's hash and size table, the collect records' per-file sha256 and the summary's sha256_lf, against the originals."""
    lines: list[str] = []
    diffs: list[str] = []
    table = re.findall(r"^\| `(case4-[^`]+\.json|results-summary\.json|controls/[^`]+)`[^|]*\| (\d+) \| `([0-9a-f]{64})` \|$", fo.as_run, re.M)
    lines.append(f"as_run.file_table_rows = {len(table)}")
    bad = 0
    for name, size, sha in table:
        p = raw / "runs" / name
        if not p.exists():
            diffs.append(f"AS_RUN table names {name}: no original at {p}")
            continue
        b = p.read_bytes()
        lf = b.replace(CRLF, LF)
        sizes = {len(b), len(lf), len(lf.replace(LF, CRLF))}
        ok = (int(size) in sizes, _lf_sha(b) == sha)
        if not all(ok):
            bad += 1
            diffs.append(f"AS_RUN table {name}: size stated {size}, original is {len(b)} as stored / {len(lf)} LF / {len(lf.replace(LF, CRLF))} CRLF; sha256 LF stated {sha[:12]} original {_lf_sha(b)[:12]}")

    lines.append(f"as_run.file_table_rows_matching_originals = {len(table) - bad} of {len(table)}")
    # the collect records name the copies by sha256 of the live (pre-rewrite) bytes: they match no file here
    pubhashes: set[str] = set()
    for q in fo.root.rglob("*"):
        if q.is_file():
            pubhashes.add(hashlib.sha256(q.read_bytes()).hexdigest())
            pubhashes.add(_lf_sha(q.read_bytes()))
    stated: dict[str, str] = {}
    for cname, c in fo.kind["collect"].items():
        for v in c["valid"] + c["copies"]:
            stated[v["sha256"]] = v["file"]
    rawh = set()
    for q in (raw / "runs").rglob("*.json"):
        rawh.add(hashlib.sha256(q.read_bytes()).hexdigest())
        rawh.add(_lf_sha(q.read_bytes()))
    lines.append(f"collect.sha256 values stated = {len(stated)}; equal to a hash of an original in {raw.name}/runs = {sum(1 for h in stated if h in rawh)}; "
                 f"equal to a hash of a published file = {sum(1 for h in stated if h in pubhashes)}")
    for tag, hs in (("AS_RUN table", set(re.findall(r"`([0-9a-f]{64})`", fo.as_run))),
                    ("results-summary sha256_lf", {r["sha256_lf"] for r in fo.summary["records"]})):
        lines.append(f"{tag} hashes equal to a hash of a published file = {sum(1 for h in hs if h in pubhashes)} of {len(hs)}")
        # a hash for a file that exists unchanged (the stale-free scripts) would be legitimate; list them
        for h in sorted(hs & pubhashes):
            lines.append(f"  {tag}: {h[:12]} is also the hash of a published file")
    for rec in fo.summary["records"]:
        p = raw / "runs" / rec["file"]
        if _lf_sha(p.read_bytes()) != rec["sha256_lf"]:
            diffs.append(f"results-summary {rec['file']}.sha256_lf={rec['sha256_lf'][:12]} original LF={_lf_sha(p.read_bytes())[:12]}")
    lines.append(f"summary.sha256_lf vs originals = compared ({len(fo.summary['records'])} records)")
    return lines, diffs


def readme_hash_table(pub: Path) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    diffs: list[str] = []
    text = (pub / "README.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| `([^`]+)` \| `([0-9a-f]{64})` \|$", text, re.M)
    rows = [(n, h) for n, h in rows if n not in ()]
    actual = {p.relative_to(pub).as_posix(): _lf_sha(p.read_bytes())
              for p in pub.rglob("*") if p.is_file() and p.name not in ("README.md", ".sanitized", "RECOUNT.md") or (p.is_file() and p.parent != pub and p.name == "README.md")}
    named = {n for n, _ in rows}
    for n, h in rows:
        if n not in actual:
            diffs.append(f"README hash table names {n}: no such file")
        elif actual[n] != h:
            diffs.append(f"README hash table {n}: stated {h[:12]} computed {actual[n][:12]}")
    missing = sorted(set(actual) - named)
    for n in missing:
        diffs.append(f"README hash table omits {n}")
    lines.append(f"readme.hash_table_rows = {len(rows)}; published files (excluding README.md, .sanitized, RECOUNT.md) = "
                 f"{len(actual)}")
    lines.append(f"readme.hash_table_rows_matching = {sum(1 for n, h in rows if actual.get(n) == h)}")
    return lines, diffs


def readme_inline_hashes(pub: Path, repo: Path | None) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    diffs: list[str] = []
    text = (pub / "README.md").read_text(encoding="utf-8")
    d1 = "47fcd179b28f15b6deb9d9bfeb41ee501f7e43ee8824364c2bc757707f6c031a"
    d2 = "4c0b559eb47014c6b69d43573d29cf6af8d5bc0784c9a402ad5a273c7c9e3fdd"
    for h in (d1, d2, "4fde1ad6db744fa289b65eb6f639628cd1f04ead6f3b5e6db247fcdc3a0e14d4"):
        lines.append(f"readme.states {h[:8]} = {h in text}")
    if repo is not None:
        base = "docs/research/containment-evidence-2026-10-05/nep0005-open-questions/nco/"
        want = [("1ed25f50", "scripts/spike-nep5-c4-driver.ps1", d1), ("1881f15d", "scripts/spike-nep5-c4-driver.ps1", d2),
                ("21cb384d", "probe/NcoProbe.cs", "28bc05d583135c446ae5dff073907b42c855e522123ba7106c76ff185a42f794")]
        for c, path, h in want:
            r = subprocess.run(["git", "-C", str(repo), "show", f"{c}:{base}{path}"], capture_output=True)
            got = _lf_sha(r.stdout) if r.returncode == 0 else f"git show failed ({r.returncode})"
            lines.append(f"git {c}:{path} sha256(LF) = {got}")
            if got != h:
                diffs.append(f"README/AS_RUN states {h[:12]} for {c}:{path}; git gives {got[:12]}")
        for c in ("e4383096", "4ebad95c"):
            r = subprocess.run(["git", "-C", str(repo), "show", f"{c}:{base}scripts/spike-nep5-c4-driver.ps1"], capture_output=True)
            lines.append(f"git {c}:scripts/spike-nep5-c4-driver.ps1 sha256(LF) = {_lf_sha(r.stdout) if r.returncode == 0 else 'failed'}")
        for c in ("1ed25f50", "1881f15d", "4ebad95c"):
            r = subprocess.run(["git", "-C", str(repo), "show", f"{c}:{base}scripts/case4-lock-corpus.json"], capture_output=True)
            lines.append(f"git {c}:scripts/case4-lock-corpus.json sha256(LF) = {_lf_sha(r.stdout) if r.returncode == 0 else 'failed'}")
    return lines, diffs


BASE = "docs/research/containment-evidence-2026-10-05/nep0005-open-questions/nco/"


def structure_checks(fo: Folder, pub: Path, raw: Path | None, repo: Path | None) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    diffs: list[str] = []
    readme = (pub / "README.md").read_text(encoding="utf-8")
    files = [p for p in pub.rglob("*") if p.is_file() and p.name not in ("recount.py", "RECOUNT.md")]
    # 1. every path the README names inside this folder exists
    named = set(re.findall(r"`((?:runs|scripts|probe)/[^`\s*{}]+|PROVENANCE\.md|SPEC\.md|RUN_SHEET\.md|\.sanitized)`", readme))
    for n in sorted(named):
        if not (pub / n).exists() and not (n == "PROVENANCE.md" and (pub.resolve().parents[1] / n).exists())                 and not n.endswith("051400-5880.json") and n not in UNPUBLISHED:
            diffs.append(f"README names `{n}`: not in the folder")
    lines.append(f"readme.paths_named = {len(named)}; not in this folder = {sorted(n for n in named if not (pub / n).exists())} "
                 f"(PROVENANCE.md is read at the repository root)")
    # 2. AS_RUN line numbers the README cites (L91: lines 14 and 81 to 84)
    ar = fo.as_run.splitlines()
    d1, d2 = "47fcd179", "4c0b559e"
    lines.append(f"as_run.line14 has {d1} = {d1 in ar[13]}; line81 has {d1} = {d1 in ar[80]}; line82 has {d2} = {d2 in ar[81]}; "
                 f"lines 83-84 have {[h in ar[i] for i, h in ((82, 'c48019a3'), (83, '06d63d97'))]}")
    # 3. the renamed file: spelling in each file
    old, new = "051400-5880", "051400-05880"
    sp = {p.relative_to(pub).as_posix(): (old in p.read_text(encoding="utf-8"), new in p.read_text(encoding="utf-8"))
          for p in files if p.suffix in (".json", ".md") and p.name != "README.md"}
    lines.append("renamed.file_name_spelling old-only: " + ", ".join(sorted(k for k, v in sp.items() if v[0] and not v[1])))
    lines.append("renamed.file_name_spelling new: " + ", ".join(sorted(k for k, v in sp.items() if v[1])) + " (none)" * (not any(v[1] for v in sp.values())))
    # 4. `text` key renamed in prepare, final, part-D
    def keys(o: Any) -> set[str]:
        out: set[str] = set()
        if isinstance(o, dict):
            for k, v in o.items():
                out.add(k)
                out |= keys(v)
        elif isinstance(o, list):
            for v in o:
                out |= keys(v)
        return out
    for kind in ("prepare", "final", "partd"):
        for n, r in fo.kind[kind].items():
            ks = keys(r)
            lines.append(f"{n}: has key 'text' = {'text' in ks}; has 'netsh_text' = {'netsh_text' in ks}")
    # 5. machine SIDs left, placeholders
    sid = Counter()
    for p in files:
        if p.suffix in (".json", ".md", ".ps1", ".cs"):
            for m in re.findall(r"S-1-5-21-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+", p.read_text(encoding="utf-8")):
                sid[m] += 1
    lines.append("sid.domains = " + ", ".join(f"{k} (x{v})" for k, v in sorted(sid.items())))
    for k in sid:
        if k not in ("S-1-5-21-X-X-X", "S-1-5-21-Y-Y-Y"):
            diffs.append(f"domain SID other than the two placeholders: {k}")
    # 8. git facts the README states
    if repo is not None:
        def git(*a: str) -> str:
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
            return r.stdout.strip() if r.returncode == 0 else f"failed({r.returncode})"
        for f in ("probe/build-probe.ps1", "probe/run-probe-selftest.ps1", "scripts/run-limited.ps1"):
            lines.append(f"git log main --format=%h -- {f}: {git('log', 'main', '--format=%h', '--', BASE + f).split()}")
        for c in ("e4383096", "4ebad95c", "1ed25f50", "1881f15d", "21cb384d"):
            lines.append(f"git: {c} is ancestor of main = {subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', c, 'main']).returncode == 0}")
        if raw is not None:
            lines.append(f"main-line driver sha256(LF) = {_lf_sha((raw / 'scripts' / 'spike-nep5-c4-driver.ps1').read_bytes())}")
            lines.append(f"main-line NcoProbe.cs sha256(LF) = {_lf_sha((raw / 'probe' / 'NcoProbe.cs').read_bytes())}")
            lines.append(f"main-line case4-lock-corpus.json sha256(LF) = {_lf_sha((raw / 'scripts' / 'case4-lock-corpus.json').read_bytes())}")
    return lines, diffs


def main(argv: list[str]) -> int:
    args = list(argv)
    raw = repo = None
    if "--raw" in args:
        i = args.index("--raw")
        raw = Path(args[i + 1])
        del args[i:i + 2]
    if "--repo" in args:
        i = args.index("--repo")
        repo = Path(args[i + 1])
        del args[i:i + 2]
    if "--local" in args:
        i = args.index("--local")
        for a, b in json.loads(Path(args[i + 1]).read_text(encoding="utf-8"))["replacements"]:
            LOCAL_PAIRS.append((a, b))
        del args[i:i + 2]
    pub = Path(args[0])
    fo = Folder(pub)
    fig = figures(fo)
    for k, v in fig.items():
        print(f"{k} = {v}")
    bad = 0
    print("\n# cross-checks (summary against its records)")
    cc = cross_checks(fo, fig)
    for d in cc:
        print("DIFF", d)
    print(f"cross_check.differences = {len(cc)}")
    bad += len(cc)
    print("\n# claims (README statement | computed from records)")
    for i, where, stated, computed in claims(fo, fig):
        if _same(stated, computed):
            ok = "ok"
        elif _strict(stated):
            ok = "DIFFERS"
        else:
            ok = "READ"
        print(f"claim {i} stated={stated!r} computed={computed!r} -> {ok}")
        if ok == "DIFFERS":
            bad += 1
    print("\n# README hash table, structure and statements about other files")
    for lines, diffs in (readme_hash_table(pub), readme_inline_hashes(pub, repo), structure_checks(fo, pub, raw, repo)):
        for l in lines:
            print(l)
        for d in diffs:
            print("DIFF", d)
        bad += len(diffs)
    if raw is not None:
        print("\n# originals")
        for lines, diffs in (compare_raw(pub, raw), hash_checks(fo, raw)):
            for l in lines:
                print(l)
            for d in diffs:
                print("DIFF", d)
            bad += len(diffs)
        rf = figures(Folder(raw, UNPUBLISHED))

        def through_rules(v: object) -> object:
            return normalise_raw(str(v), "")
        rdiff = [k for k in sorted(set(fig) | set(rf))
                 if str(fig.get(k)) != str(through_rules(rf.get(k))) and str(fig.get(k)) != str(rf.get(k))]
        raw_only = [k for k in sorted(set(fig) | set(rf)) if str(fig.get(k)) != str(rf.get(k))]
        print(f"figure_names.published = {len(fig)}; figure_names.original = {len(rf)}; figures differing as written = {len(raw_only)}; "
              f"still differing after the recorded replacements are applied to the original = {len(rdiff)}")
        for k in rdiff:
            print(f"DIFF figure {k}: published={fig.get(k)!r} original={rf.get(k)!r}")
        bad += len(rdiff)
    print(f"\ntotal.differences = {bad}")
    return 1 if bad else 0


def _strict(stated: str) -> bool:
    """A stated value that is a bare count or an `N of M` is compared for equality; prose is printed for reading."""
    return bool(re.fullmatch(r"\d+( of \d+)?|\d+(; \d+ of \d+)+|\d+; \d+ of \d+; \d+ of \d+", stated.strip()))


def _same(stated: str, computed: str) -> bool:
    return re.sub(r"\s+", " ", stated.strip().lower()) == re.sub(r"\s+", " ", computed.strip().lower())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
