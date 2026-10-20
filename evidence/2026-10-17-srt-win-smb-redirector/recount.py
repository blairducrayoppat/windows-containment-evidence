#!/usr/bin/env python3
"""Recount every figure the README of this folder states, from the proof-of-concept run records, the harness records
and the owner-attribution transcripts of one evidence folder, and print them as `name = value` lines. Standard
library only.

  python recount.py <folder>                print the figures
  python recount.py <folderA> <folderB>     print both and the differences (exit 1 on any difference)

Sources read, and nothing else:

- `poc-runs/*/result.json` and the last `run_status=... result=... exit=...` line of each `console.txt`. Per-pass
  figures are recomputed from each pass's payload records (C1, C2, T, C3) and from `all_listener_records` (the
  listener log, matched to a pass by its `phase`). The record's own summary fields (`C1_listener_records`,
  `T_new_connections`, `T_smb_headers`, `outcome`, `summary`, `run_status`, `result`) are printed beside the
  recomputed figure under a `record.` name, never used in its place.
- the virtual-machine runs in `poc-runs/v3-vm-suite-absent/`. A folder that still carries the earlier name of that
  directory, `poc-runs/v3-vm-suite-absent-26300.9457/`, is read from that name instead; that is the only path mapped.
  Its figures are printed under `vm.`, so the two layouts compare name for name.
- `evidence/run-20261017-4` to `-7`: `listener.jsonl` (the per-record witness), `session-extract-U0-U1p-U1.json`
  (payload results and fence checks), `wfp-before.json`, `wfp-after.json`, `verdict.json`; `counts.json` is printed
  beside as `record.`.
- `evidence/run-20261017-8` and `-9`: `listener.jsonl`, `counts.json` (passes per state and pktmon counts),
  `verdict.json` (the per-state error codes, which these runs record nowhere else in the folder).
- `evidence/owner-attribution-20261017/repeat-*.txt`.
- the sha256 of every file under `poc/`.

Run groups. `host.v1-3` is every main-host run named `v1-run-*`, `v2-run-*` or `v3-run-*`; `host.v1-4` adds
`v4-run-1`. Toggle runs (names with `toggle` or `location-check`) are fail-loud checks and enter no aggregate.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

JsonObj = dict[str, Any]
Figures = dict[str, object]

VM_DIRS = ("v3-vm-suite-absent", "v3-vm-suite-absent-26300.9457")
REPRO_RUN_RE = re.compile(r"^v[1-4]-run-")
SMB1_NEGOTIATE_HEAD = "00000045ff534d4272"
SMB1_NEGOTIATE_LEN = 73
FINAL_LINE_RE = re.compile(r"run_status=(\S+) result=(\S+) exit=(\S+)")
HARNESS_SMB_RUNS = (4, 5, 6, 7)
HARNESS_WEBDAV_RUNS = (8, 9)
WEBDAV_STATES = ("U0", "U0t", "U2a", "U2at", "U2b", "U2bt", "U2p", "U2pt", "U3b", "U3tb")


def _load(path: Path) -> JsonObj:
    obj: JsonObj = json.loads(path.read_text(encoding="utf-8-sig"))
    return obj


def _jsonl(path: Path) -> list[JsonObj]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _join(values: list[object], sep: str = " / ") -> str:
    return sep.join(str(v) for v in values)


def _final_line(console: Path) -> tuple[str, str, str]:
    """(run_status, result, exit) from the last `run_status=` line the script printed, or ("absent",)*3."""
    text = console.read_bytes().decode("utf-8", errors="replace")
    found = FINAL_LINE_RE.findall(text)
    return found[-1] if found else ("absent", "absent", "absent")


def _is_smb73(rec: JsonObj) -> bool:
    return rec.get("nbytes") == SMB1_NEGOTIATE_LEN and str(rec.get("head", "")).startswith(SMB1_NEGOTIATE_HEAD)


def _refused(payload: JsonObj | None) -> bool:
    return payload is not None and payload.get("result") == "refused" and payload.get("winerror") == 10013


class PocRun:
    """Recomputed per-pass figures of one proof-of-concept `result.json`."""

    def __init__(self, run_dir: Path, poc_hashes: dict[str, str]) -> None:
        self.dir = run_dir
        self.rec = _load(run_dir / "result.json")
        self.final = _final_line(run_dir / "console.txt")
        self.poc_hashes = poc_hashes
        self.passes: list[JsonObj] = self.rec.get("passes") or []
        self.blocked: int | None = (self.rec.get("ports") or {}).get("blocked")
        self.listener: list[JsonObj] = self.rec.get("all_listener_records") or []

    def phase(self, n: int, step: str) -> list[JsonObj]:
        return [r for r in self.listener if r.get("phase") == f"p{n}-{step}"]

    def t_records(self, n: int) -> list[JsonObj]:
        return [r for r in self.phase(n, "T") if r.get("lport") == self.blocked]

    def c2_owner_is_fenced_pid(self, p: JsonObj) -> bool:
        recs = self.phase(p["pass"], "C2")
        pid = (p.get("C2") or {}).get("pid")
        return len(recs) == 1 and pid is not None and (recs[0].get("owner") or {}).get("pid") == pid

    def outside_phases(self) -> list[str]:
        """Phases of records on the blocked port that fall outside a pass's measured windows (pN-C1, pN-T, pN-C3)."""
        window = re.compile(r"^p\d+-(C1|T|C3)$")
        return [
            str(r.get("phase"))
            for r in self.listener
            if r.get("lport") == self.blocked and not window.match(str(r.get("phase")))
        ]

    def blocked_outside_windows(self) -> int:
        return len(self.outside_phases())

    def figures(self, pre: str) -> Figures:
        rec, fig = self.rec, {}
        sha = rec.get("script_sha256")
        fig[pre + "script.version"] = rec.get("version")
        fig[pre + "script.sha256"] = sha if sha else "absent (not recorded)"
        fig[pre + "script.sha256_matches_file"] = (
            ",".join(sorted(k for k, v in self.poc_hashes.items() if v == sha)) or "none" if sha else "n/a"
        )
        fig[pre + "record.started/finished_utc"] = (
            f"{str(rec.get('started_utc', 'absent'))[:19]} / {str(rec.get('finished_utc', 'absent'))[:19]}"
        )
        fig[pre + "srt_win.sha256"] = (rec.get("srt_win") or {}).get("sha256", "absent")
        wv = rec.get("wfp_verify")
        probe = re.search(r'"egress_probe":"(\w+)"', str((wv or {}).get("text", "")))
        fig[pre + "wfp_verify.egress_probe"] = probe.group(1) if probe else "absent"
        launch = rec.get("launch") or {}
        fig[pre + "launch.elevated/integrity"] = f"{launch.get('elevated')}/{launch.get('integrity')}"
        os_ = rec.get("os")
        fig[pre + "os.build.ubr"] = (
            f"{os_.get('build')}.{os_.get('ubr')} {os_.get('display_version')}" if os_ else "absent"
        )
        sp = rec.get("security_products")
        fig[pre + "security_products"] = (
            f"antivirus={','.join(sp.get('antivirus') or []) or 'none'}; firewall={','.join(sp.get('firewall') or []) or 'none'}"
            if sp
            else "absent"
        )
        fig[pre + "ports.blocked/permitted/range"] = (
            "{blocked}/{permitted}/{permit_range_assumed}".format(**rec["ports"]) if rec.get("ports") else "absent"
        )
        prc = rec.get("permit_range_check")
        fig[pre + "permit_range_check"] = (
            _join([f"{c['port']}:{c['egress_probe']}(expected {c['expected']})" for c in prc], ", ")
            if prc
            else "absent"
        )
        fig[pre + "passes"] = len(self.passes)
        if self.passes:
            ps = self.passes
            fig[pre + "C1.result/winerror"] = _join([f"{p['C1'].get('result')}/{p['C1'].get('winerror')}" for p in ps])
            fig[pre + "C1.listener_records"] = _join([len(self.phase(p["pass"], "C1")) for p in ps])
            fig[pre + "record.C1_listener_records"] = _join([p.get("C1_listener_records") for p in ps])
            fig[pre + "C2.result"] = _join([p["C2"].get("result") for p in ps])
            fig[pre + "C2.listener_records"] = _join([len(self.phase(p["pass"], "C2")) for p in ps])
            fig[pre + "C2.owner_is_fenced_pid"] = _join([self.c2_owner_is_fenced_pid(p) for p in ps])
            fig[pre + "open_sockets_to_blocked_before_T"] = _join(
                [p.get("open_client_sockets_to_blocked_port_before_T") for p in ps]
            )
            fig[pre + "T.connections"] = _join([len(self.t_records(p["pass"])) for p in ps])
            fig[pre + "record.T_new_connections"] = _join([p.get("T_new_connections") for p in ps])
            fig[pre + "T.owner_pid4"] = _join(
                [sum((r.get("owner") or {}).get("pid") == 4 for r in self.t_records(p["pass"])) for p in ps]
            )
            fig[pre + "T.smb1_negotiate_73"] = _join([sum(_is_smb73(r) for r in self.t_records(p["pass"])) for p in ps])
            fig[pre + "record.T_smb_headers"] = _join([p.get("T_smb_headers") for p in ps])
            fig[pre + "T.net_exe_win32"] = _join([p["T"].get("win32") for p in ps])
            fig[pre + "T.seconds"] = _join([p["T"].get("seconds") for p in ps])
            fig[pre + "C3.result/winerror"] = _join([f"{p['C3'].get('result')}/{p['C3'].get('winerror')}" for p in ps])
            fig[pre + "C3.listener_records"] = _join([len(self.phase(p["pass"], "C3")) for p in ps])
            fig[pre + "record.C3_listener_records"] = _join([p.get("C3_listener_records") for p in ps])
            fig[pre + "identity_ok"] = _join(
                [sum(bool((p.get(s) or {}).get("identity_ok")) for s in ("C1", "C2", "T", "C3")) for p in ps]
            )
            fig[pre + "record.pass_outcome"] = _join([p.get("outcome") for p in ps])
            if any("foreign_smb_during_T" in p for p in ps):
                fig[pre + "foreign_smb_during_T"] = _join([self._foreign(p.get("foreign_smb_during_T")) for p in ps])
        outside = self.outside_phases()
        fig[pre + "blocked_port_records_outside_windows"] = (
            (f"{len(outside)} (phases {','.join(outside)})" if outside else 0) if self.listener else "n/a"
        )
        fig[pre + "record.unphased_records_on_blocked_port"] = len(rec.get("unphased_records_on_blocked_port") or [])
        if "notes" in rec:
            fig[pre + "record.notes"] = len(rec.get("notes") or [])
        fig[pre + "record.summary"] = rec.get("summary", "absent")
        fig[pre + "record.run_status/result"] = f"{rec.get('run_status')}/{rec.get('result')}"
        fig[pre + "console.run_status/result/exit"] = "/".join(self.final)
        fig[pre + "record.problems"] = len(rec.get("problems") or [])
        if rec.get("problems") and not REPRO_RUN_RE.match(self.dir.name) and self.dir.parent.name not in VM_DIRS:
            fig[pre + "record.problems_text"] = " || ".join(rec["problems"])
        return fig

    @staticmethod
    def _foreign(f: JsonObj | None) -> str:
        if not f:
            return "absent"
        errs = [w for w in ("before", "after") if (f.get(w) or {}).get("error")]
        if errs:
            return "error(" + ",".join(errs) + ")"
        ports = f.get("remote_ports") or []
        return "ports " + ",".join(map(str, ports)) if ports else "none"


class Agg:
    """Aggregates over a list of proof-of-concept runs, recomputed from their passes."""

    def __init__(self, runs: list[PocRun]) -> None:
        self.runs = runs

    def figures(self, pre: str) -> Figures:
        fig: Figures = {}
        rs = self.runs
        all_p = [(r, p) for r in rs for p in r.passes]
        fig[pre + "runs"] = len(rs)
        fig[pre + "passes"] = len(all_p)
        fig[pre + "derivation"] = " + ".join(f"{r.dir.name}({len(r.passes)})" for r in rs)
        fig[pre + "record.run_status"] = ",".join(
            f"{k}x{v}" for k, v in sorted(Counter(r.rec["run_status"] for r in rs).items())
        )
        fig[pre + "record.result"] = ",".join(
            f"{k}x{v}" for k, v in sorted(Counter(r.rec["result"] for r in rs).items())
        )
        t = [r.t_records(p["pass"]) for r, p in all_p]
        fig[pre + "T.delivered_passes"] = f"{sum(bool(x) for x in t)} of {len(t)}"
        conns = [c for x in t for c in x]
        fig[pre + "T.connections"] = len(conns)
        fig[pre + "T.owner_pid4"] = f"{sum((c.get('owner') or {}).get('pid') == 4 for c in conns)} of {len(conns)}"
        fig[pre + "T.smb1_negotiate_73"] = f"{sum(_is_smb73(c) for c in conns)} of {len(conns)}"
        c13 = [(r, p, s) for r, p in all_p for s in ("C1", "C3")]
        fig[pre + "C1+C3.refused_10013_no_record"] = (
            f"{sum(_refused(p.get(s)) and not r.phase(p['pass'], s) for r, p, s in c13)} of {len(c13)}"
        )
        fig[pre + "C2.connected_witnessed_owner_fenced_pid"] = (
            f"{sum(p['C2'].get('result') == 'connected' and r.c2_owner_is_fenced_pid(p) for r, p in all_p)} of {len(all_p)}"
        )
        pay = [(p.get(s) or {}) for _, p in all_p for s in ("C1", "C2", "T", "C3")]
        fig[pre + "identity_ok_payloads"] = (
            f"{sum(bool(x.get('identity_ok')) for x in pay)} of {len(pay)} (passes x 4 payloads)"
        )
        w = Counter(p["T"].get("win32") for _, p in all_p)
        fig[pre + "T.net_exe_win32_passes"] = ",".join(
            f"error {k}: {v}" for k, v in sorted(w.items(), key=lambda kv: str(kv[0]))
        )
        odd = [(r, p) for r, p in all_p if p["T"].get("win32") != 64]
        fig[pre + "T.non_64_passes"] = (
            "; ".join(
                f"{r.dir.name} pass {p['pass']}: error {p['T'].get('win32')}, {len(r.t_records(p['pass']))} connection(s), "
                f"{p['T'].get('seconds')} s"
                for r, p in odd
            )
            or "none"
        )
        fig[pre + "open_sockets_to_blocked_before_T_nonzero"] = sum(
            bool(p.get("open_client_sockets_to_blocked_port_before_T")) for _, p in all_p
        )
        fig[pre + "blocked_port_records_outside_windows"] = sum(r.blocked_outside_windows() for r in rs)
        return fig


def _poc(folder: Path) -> Figures:
    fig: Figures = {}
    poc_dir = folder / "poc"
    hashes = {p.relative_to(poc_dir).as_posix(): _sha256(p) for p in sorted(poc_dir.rglob("*")) if p.is_file()}
    for name, h in hashes.items():
        fig[f"poc_file.{name}.sha256"] = h
    runs_dir = folder / "poc-runs"
    host: list[PocRun] = []
    for d in sorted(p for p in runs_dir.iterdir() if p.is_dir() and p.name not in VM_DIRS):
        run = PocRun(d, hashes)
        fig.update(run.figures(f"poc.{d.name}."))
        if REPRO_RUN_RE.match(d.name):
            host.append(run)
    fig.update(Agg([r for r in host if r.rec.get("version") in (1, 2, 3)]).figures("host.v1-3."))
    fig.update(Agg(host).figures("host.v1-4."))
    vm_dir = next((runs_dir / n for n in VM_DIRS if (runs_dir / n).is_dir()), None)
    if vm_dir is None:
        fig["vm"] = "absent"
        return fig
    vm = [PocRun(d, hashes) for d in sorted(vm_dir.glob("run-*")) if d.is_dir()]
    for run in vm:
        fig.update(run.figures(f"vm.{run.dir.name}."))
    fig.update(Agg(vm).figures("vm.all."))
    wv = _load(vm_dir / "winver.json")
    fig["vm.winver"] = f"{wv.get('build')}.{wv.get('ubr')} {wv.get('display_version')} product={wv.get('product')}"
    sc = _load(vm_dir / "security_center.json")
    av = sc.get("antivirus") or []
    fig["vm.security_center.antivirus"] = ",".join(f"{a.get('name')}(state {a.get('state')})" for a in av) or "none"
    fig["vm.security_center.firewall"] = len(sc.get("firewall") or [])
    fig["vm.security_center.antispyware"] = len(sc.get("antispyware") or [])
    dfd = sc.get("defender") or {}
    fig["vm.security_center.defender"] = (
        f"realtime={dfd.get('RealTimeProtectionEnabled')} engine={dfd.get('AMProductVersion')} "
        f"signatures={dfd.get('AntivirusSignatureVersion')}"
    )
    inst = _load(vm_dir / "srt-win-install.json")
    m = re.search(r"proxy_port_range=(\S+?), filters=(\d+)", str(inst.get("install", "")))
    fig["vm.srt_win_install"] = (
        f"exit={inst.get('install_exit')} permit={m.group(1)} filters={m.group(2)}"
        if m
        else f"exit={inst.get('install_exit')}"
    )
    return fig


def _owner_pid(rec: JsonObj) -> object:
    return (rec.get("owner") or {}).get("pid") if "owner" in rec else "no-field"


def _harness_smb(folder: Path, n: int) -> Figures:
    fig: Figures = {}
    d = folder / "evidence" / f"run-20261017-{n}"
    pre = f"harness.run-{n}."
    lst = _jsonl(d / "listener.jsonl")
    ext = _load(d / "session-extract-U0-U1p-U1.json")
    counts = _load(d / "counts.json")
    verdict = _load(d / "verdict.json")
    has_owner = any("owner" in r for r in lst if r.get("kind") == "connect")
    fig[pre + "harness_version(derived: owner field present)"] = "B" if has_owner else "A"
    fig[pre + "record.connection_ledger_present"] = "connections_by_pass" in counts.get("U1", {})
    for state, port in (("U1", 61781), ("U1p", 60082)):
        tags = [p["tag"] for p in ext[state]["passes"]]
        s = state.lower()
        recs = {t: [r for r in lst if r.get("tag") == t and r.get("lport") == port] for t in tags}
        conn = {t: [r for r in v if r.get("kind") == "connect"] for t, v in recs.items()}
        byts = {t: [r for r in v if r.get("kind") == "bytes"] for t, v in recs.items()}
        fig[pre + f"{s}.passes"] = len(tags)
        fig[pre + f"{s}.passes_with_smb_on_{port}"] = sum(any(_is_smb73(b) for b in byts[t]) for t in tags)
        fig[pre + f"{s}.listener_records(connect+bytes)"] = _join([len(recs[t]) for t in tags])
        fig[pre + f"record.{s}.listener_by_pass"] = _join(list(counts[state]["listener_by_pass"].values()))
        fig[pre + f"{s}.connect_records"] = _join([len(conn[t]) for t in tags])
        ledger = counts[state].get("connections_by_pass")
        fig[pre + f"record.{s}.ledger_new/reused"] = (
            _join([f"{len(v['new'])}/{len(v['reused'])}" for v in ledger.values()]) if ledger else "absent"
        )
        fig[pre + f"{s}.smb1_negotiate_73"] = (
            f"{sum(_is_smb73(b) for t in tags for b in byts[t])} of {sum(len(byts[t]) for t in tags)}"
        )
        own = Counter(str(_owner_pid(c)) for t in tags for c in conn[t])
        fig[pre + f"{s}.owners"] = ",".join(
            f"pid {k} x{v}" if k != "no-field" else f"no owner field x{v}" for k, v in sorted(own.items())
        )
        fig[pre + f"{s}.net_exe_win32"] = _join([p["result"].get("win32") for p in ext[state]["passes"]])
        fig[pre + f"{s}.payload_user"] = ",".join(sorted({str(p["result"].get("user")) for p in ext[state]["passes"]}))
        for when in ("before", "after"):
            fd = ext[state].get(f"fence_detail_{when}") or {}
            direct = fd.get("direct") or []
            fig[pre + f"{s}.fence_{when}"] = (
                f"{fd.get('state')}; direct refused 10013 {sum(x.get('outcome') == 'refused' and x.get('win32') == 10013 for x in direct)}"
                f" of {len(direct)}; verify {fd.get('verify_outcome')}"
                if fd
                else "absent"
            )
    u0 = ext["U0"]["passes"]
    fig[pre + "u0.refused_10013"] = (
        f"{sum(p['outcome'] == 'refused' and p['result'].get('win32') == 10013 for p in u0)} of {len(u0)}"
    )
    fig[pre + "u0.listener_records"] = sum(1 for r in lst if str(r.get("tag", "")).startswith("u0-"))
    other = [r for r in lst if r.get("kind") == "connect" and "owner" in r and r.get("service") != "smb"]
    fig[pre + "non_smb_connects_with_owner"] = (
        f"{len(other)} ({','.join(sorted({str(r.get('tag')).split('-')[0] for r in other}))}; pids "
        f"{','.join(sorted({str(_owner_pid(r)) for r in other}))})"
        if other
        else 0
    )
    for when in ("before", "after"):
        w = _load(d / f"wfp-{when}.json")
        out = str((w.get("verify") or {}).get("output", ""))
        m = re.search(r'"egress_probe":"(\w+)"', out)
        fig[pre + f"wfp_{when}.elevated_verify"] = (
            f"{m.group(1) if m else 'unparsed'} exit={(w.get('verify') or {}).get('exit')}"
        )
        fig[pre + f"wfp_{when}.srtwin_sha256"] = str(w.get("srtwin", "absent")).lower()
    fig[pre + "verdict.overall"] = verdict.get("overall")
    fig[pre + "verdict.fixtures"] = ",".join(f"{k}={v['status']}" for k, v in sorted(verdict["fixtures"].items()))
    fig[pre + "verdict.codes.U1/U1p/U1pt"] = _join([verdict["codes"].get(k) for k in ("U1", "U1p", "U1pt")])
    fig[pre + "verdict.rollback_proven"] = verdict.get("rollback_proven")
    fig[pre + "verdict.suite"] = _suite(verdict)
    fig.update(_harness_smb_other_states(pre, lst, verdict))
    return fig


def _family(rec: JsonObj) -> str:
    """State family of a listener record: its tag without the pass suffix (`u2pt-p1` -> `u2pt`)."""
    return str(rec.get("tag", "")).rsplit("-p", 1)[0]


def _harness_smb_other_states(pre: str, lst: list[JsonObj], verdict: JsonObj) -> Figures:
    """Runs 4-7: the WebDAV states that ran before the SMB fixture stopped the batch, the test-account SMB states,
    and the order in which the state families first reached the listener."""
    fig: Figures = {}
    codes: JsonObj = verdict.get("codes") or {}
    fig[pre + "verdict.codes.U0/U0t"] = _join([codes.get("U0"), codes.get("U0t")])
    fig[pre + "verdict.u0"] = ",".join(f"{k}={v['state']}" for k, v in sorted((verdict.get("u0") or {}).items()))
    fig[pre + "U0t.listener_records"] = sum(1 for r in lst if _family(r) == "u0t")
    for st in ("U2a", "U2at", "U2b", "U2bt", "U2p", "U2pt"):
        recs = [r for r in lst if _family(r) == st.lower()]
        conn = [r for r in recs if r.get("kind") == "connect"]
        fig[pre + f"{st}.codes(verdict)"] = _join(codes[st], ",") if codes.get(st) else "none"
        fig[pre + f"{st}.listener_records"] = len(recs)
        if conn:
            fig[pre + f"{st}.new_connections"] = len(conn)
            fig[pre + f"{st}.lports"] = ",".join(sorted({str(r.get("lport")) for r in conn}))
            fig[pre + f"{st}.owners"] = ",".join(sorted({str(_owner_pid(r)) for r in conn}))
    blocked = [r for r in lst if _family(r) in ("u2a", "u2at", "u2b", "u2bt")]
    fig[pre + "U2_blocked_port_states.listener_records"] = len(blocked)
    webdav = {str(_owner_pid(r)) for r in lst if _family(r) in ("u2p", "u2pt") and r.get("kind") == "connect"}
    fig[pre + "U2p+U2pt.distinct_owners"] = (
        f"{len(webdav)} ({','.join(sorted(webdav))}); pid 4 among them: {'4' in webdav}"
    )
    first: dict[str, str] = {}
    for r in lst:
        fam = _family(r)
        if fam in ("u2p", "u2pt", "u1p", "u1pt", "u1") and (fam not in first or str(r["ts"]) < first[fam]):
            first[fam] = str(r["ts"])
    fig[pre + "first_record_order"] = " < ".join(
        f"{k} {v[11:19]}" for k, v in sorted(first.items(), key=lambda kv: kv[1])
    )
    last_webdav = max((str(r["ts"]) for r in lst if _family(r) in ("u2p", "u2pt")), default="")
    first_smb = min((str(r["ts"]) for r in lst if r.get("service") == "smb"), default="")
    fig[pre + "every_webdav_record_before_first_smb_record"] = bool(
        last_webdav and first_smb and last_webdav < first_smb
    )
    fxb = (verdict.get("fixtures") or {}).get("fx-b") or {}
    fig[pre + "verdict.fx-b"] = f"{fxb.get('status')}: {fxb.get('reason')}"
    fig[pre + "U1t.code(verdict)"] = _join(codes["U1t"], ",") if codes.get("U1t") else "none (no U1t key)"
    fig[pre + "U1t.listener_records"] = sum(1 for r in lst if _family(r) == "u1t")
    u1pt = [r for r in lst if _family(r) == "u1pt"]
    u1pt_conn = [r for r in u1pt if r.get("kind") == "connect"]
    fig[pre + "U1pt.code(verdict)"] = _join(codes["U1pt"], ",") if codes.get("U1pt") else "none"
    fig[pre + "U1pt.listener_records/new_connections"] = f"{len(u1pt)}/{len(u1pt_conn)}"
    fig[pre + "U1pt.lports"] = ",".join(sorted({str(r.get("lport")) for r in u1pt_conn})) or "none"
    own = Counter(str(_owner_pid(r)) for r in u1pt_conn)
    fig[pre + "U1pt.owners"] = ",".join(
        f"pid {k} x{v}" if k != "no-field" else f"no owner field x{v}" for k, v in sorted(own.items())
    )
    return fig


def _suite(verdict: JsonObj) -> str:
    """Counts of the security-suite detection reasons the harness recorded before the batch, by kind."""
    reasons: list[str] = (verdict.get("suite_detected_before") or {}).get("reasons") or []
    return (
        f"present={(verdict.get('suite_detected_before') or {}).get('present')} "
        f"av={sum(r.startswith('av:') for r in reasons)} fw={sum(r.startswith('fw:') for r in reasons)} "
        f"services={sum(r.startswith('service:') for r in reasons)}"
    )


def _harness_webdav(folder: Path, n: int) -> Figures:
    fig: Figures = {}
    d = folder / "evidence" / f"run-20261017-{n}"
    pre = f"harness.run-{n}."
    lst = _jsonl(d / "listener.jsonl")
    counts = _load(d / "counts.json")
    verdict = _load(d / "verdict.json")
    fig[pre + "verdict.overall"] = verdict.get("overall")
    fig[pre + "verdict.fixtures"] = ",".join(f"{k}={v['status']}" for k, v in sorted(verdict["fixtures"].items()))
    fig[pre + "verdict.u0"] = ",".join(f"{k}={v['state']}" for k, v in sorted(verdict["u0"].items()))
    fig[pre + "verdict.fence_unchecked/not_run"] = f"{len(verdict['fence_unchecked'])}/{len(verdict['fence_not_run'])}"
    fig[pre + "verdict.rollback_proven"] = verdict.get("rollback_proven")
    fig[pre + "verdict.suite"] = _suite(verdict)
    fig[pre + "smb_records(lport 61781/60082)"] = sum(1 for r in lst if r.get("lport") in (61781, 60082))
    pkt = 0
    for st in WEBDAV_STATES:
        c = counts[st]
        tags = list(c["listener_by_pass"].keys())
        recs = [r for r in lst if r.get("tag") in tags]
        conn = [r for r in recs if r.get("kind") == "connect"]
        pkt += sum(c.get("pktmon_by_port", {}).values())
        fig[pre + f"{st}.passes"] = len(tags)
        fig[pre + f"{st}.codes(verdict)"] = _join(verdict["codes"].get(st) or ["none"], ",")
        fig[pre + f"{st}.listener_records"] = len(recs)
        fig[pre + f"{st}.new_connections"] = len(conn)
        fig[pre + f"record.{st}.listener_by_pass"] = sum(c["listener_by_pass"].values())
        ledger = c.get("connections_by_pass") or {}
        fig[pre + f"record.{st}.ledger_new"] = sum(len(v["new"]) for v in ledger.values())
        if conn:
            fig[pre + f"{st}.owners"] = ",".join(sorted({str(_owner_pid(r)) for r in conn}))
            fig[pre + f"{st}.lports"] = ",".join(sorted({str(r.get("lport")) for r in conn}))
    fig[pre + "pktmon_total"] = pkt
    own = {
        st: {
            str(_owner_pid(r))
            for r in lst
            if r.get("kind") == "connect" and r.get("tag", "").startswith(st.lower() + "-")
        }
        for st in ("U2p", "U2pt")
    }
    fig[pre + "U2p_and_U2pt_share_one_owner"] = (
        len(own["U2p"]) == 1 and own["U2p"] == own["U2pt"] and "4" not in own["U2p"]
    )
    return fig


def _owner_attribution(folder: Path) -> Figures:
    d = folder / "evidence" / "owner-attribution-20261017"
    user_ok, user_n, smb_ok, smb_n = 0, 0, 0, 0
    per: list[str] = []
    for f in sorted(d.glob("repeat-*.txt")):
        text = f.read_text(encoding="utf-8-sig")
        me_m = re.search(r"^me (\d+)$", text, re.MULTILINE)
        me = int(me_m.group(1)) if me_m else None
        rows = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
        u = [r for r in rows if r.get("label") == "user-connect"]
        s = [r for r in rows if r.get("label") == "smb-redirector"]
        u_ok = sum(all(x.get("pid") == me for x in r["rows"]) and bool(r["rows"]) for r in u)
        s_ok = sum(all(x.get("pid") == 4 for x in r["rows"]) and bool(r["rows"]) for r in s)
        user_ok, user_n, smb_ok, smb_n = user_ok + u_ok, user_n + len(u), smb_ok + s_ok, smb_n + len(s)
        per.append(f"{f.stem}: user {u_ok}/{len(u)}, smb {s_ok}/{len(s)}")
    return {
        "owner_attribution.files": len(per),
        "owner_attribution.per_file": "; ".join(per),
        "owner_attribution.user_connect_owned_by_own_pid": f"{user_ok} of {user_n}",
        "owner_attribution.smb_redirector_owned_by_pid4": f"{smb_ok} of {smb_n}",
    }


def recount(folder: Path) -> Figures:
    fig = _poc(folder)
    for n in HARNESS_SMB_RUNS:
        fig.update(_harness_smb(folder, n))
    with_smb = sum(int(str(fig[f"harness.run-{n}.u1.passes_with_smb_on_61781"])) for n in HARNESS_SMB_RUNS)
    u1_passes = sum(int(str(fig[f"harness.run-{n}.u1.passes"])) for n in HARNESS_SMB_RUNS)
    fig["harness.runs4-7.u1_passes_with_smb"] = f"{with_smb} of {u1_passes}"
    attributed, pid4 = 0, 0
    for n in HARNESS_SMB_RUNS:
        for r in _jsonl(folder / "evidence" / f"run-20261017-{n}" / "listener.jsonl"):
            if r.get("kind") == "connect" and str(r.get("tag", "")).startswith("u1-") and "owner" in r:
                attributed += 1
                pid4 += (r.get("owner") or {}).get("pid") == 4
    fig["harness.runs4-7.u1_attributed_sockets_pid4"] = f"{pid4} of {attributed}"
    for n in HARNESS_WEBDAV_RUNS:
        fig.update(_harness_webdav(folder, n))
    fig.update(_owner_attribution(folder))
    return fig


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(argv) == 1:
        for k, v in recount(Path(argv[0])).items():
            print(f"{k} = {v}")
        return 0
    if len(argv) == 2:
        a, b = recount(Path(argv[0])), recount(Path(argv[1]))
        for label, fig in (("first", a), ("second", b)):
            print(f"## {label} folder: {argv[0] if label == 'first' else argv[1]}")
            for k, v in fig.items():
                print(f"{k} = {v}")
        diffs = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
        print(f"{len(a)} figures in the first folder, {len(b)} in the second, {len(diffs)} difference(s)")
        for k in diffs:
            print(f"DIFF {k}: {a.get(k)!r} != {b.get(k)!r}")
        return 1 if diffs else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
