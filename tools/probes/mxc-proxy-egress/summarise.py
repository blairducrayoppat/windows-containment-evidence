"""Verdicts for the MXC loopback-proxy egress probe: per run, per (arm, state) batch, and the output-path guard.

What this measures: nothing; it turns the raw run records into one of HOLD / FAIL / REFUSED / REFUSED-AT-LAUNCH /
INSTRUMENT-BLIND.

Per run (judge_run), in this order:
  REFUSED            the dry-run refused the policy (exact text is in the record).
  FAIL               a run-tagged direct connect reached the second loopback listener (B3), or the container
                     connected to the LAN peer (B4(i)) or to 1.1.1.1:443 (B4(ii)), or the container reports a B3
                     connect that no listener logged (conservative: a connect that succeeded is a reach).
  REFUSED-AT-LAUNCH  the dry-run accepted but the launch itself exited non-zero with no payload report, no
                     run-tagged or in-window entry in the proxy log or any listener log (the workload never ran),
                     and recognisable refusal text in the launch's stderr, stdout or MXC log; those tails are the
                     reasons, verbatim. A non-zero exit with any sign the workload ran is INSTRUMENT-BLIND.
  INSTRUMENT-BLIND   the instrument cannot support a HOLD: payload report missing or incomplete, a listener failed
                     its pre-launch host control, B2 did not pass, an unexplained listener or proxy connection
                     after the launch started, a launcher timeout, a B3/B4 not-connected result whose error code is not the
                     enforcement code (a timeout is not a refusal), an unfenced 1.1.1.1:443 control that did not
                     connect both before and after the launch, or no LAN peer port that the unfenced control could
                     reach (B4(i) NOT-MEASURABLE, never HOLD).
  HOLD               none of the above: B2 passed, B3, B4(i) and B4(ii) each failed with the enforcement code.
B2 passes only if all three run-tagged requests appear in the proxy log (forwarded, status 200), in the second
listener's log, and as status 200 in the container's report. Enforcement code: WinError 10013 only.
Per batch (judge_batch): FAIL if any run FAILed; else REFUSED / REFUSED-AT-LAUNCH if all runs were; else
INSTRUMENT-BLIND if any run was blind or any unfenced control (B5) failed; else HOLD if all expected runs HOLD;
STOPPED-STATE-CHANGE (never HOLD) when any run's before/after snapshot differed; otherwise MIXED or INCOMPLETE (stated, never rounded into one of the others).

How to run: `python -I summarise.py <output-folder>` rewrites batch-summary.json inside that folder from the
run-*.json and control-b5.json records already there. run_probe.py calls the same functions.
What it writes: batch-summary.json in the given folder only; it refuses a folder inside a git working tree.

NOT MEASURED: any build other than the one(s) run; behaviour on a host whose --probe reports host-loopback ingress
unsupported (the earlier 26200.9457 condition); an identity-scoped proxy (allowedProxyPeer); the session-isolation
backend; UDP, ICMP or DNS egress under the proxy policy; host-to-container ingress (the doc's own open limitation);
nono under MXC; anything about the fork or any other sandbox. A verdict is a statement about the runs recorded, on
that build, with that policy, and nothing wider.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

Rec = dict[str, Any]
B2_EXPECTED = 3
ENFORCEMENT_CODES = frozenset({10013})
CHECKS = frozenset({"fail", "untagged", "nonenforcement", "unfenced", "refused_at_launch", "ran_evidence", "timeout"})
REFUSAL_TEXT = re.compile(r"refus|reject|not supported|unsupported|requires|invalid|validation failed", re.I)


def refuse_git_path(path: Path) -> None:
    """Raise SystemExit unless `path` is outside every git working tree (fail-closed if git cannot answer)."""
    probe = path.resolve()
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    base = probe if probe.is_dir() else probe.parent
    try:
        cp = subprocess.run(["git", "-C", str(base), "rev-parse", "--show-toplevel"], capture_output=True,
                            text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"REFUSED: cannot determine whether {path} is inside a git working tree ({exc!r})")
    if cp.returncode == 0:
        raise SystemExit(f"REFUSED: output path {path} is inside the git working tree {cp.stdout.strip()}")
    if "not a git repository" not in cp.stderr.lower():
        raise SystemExit(f"REFUSED: git could not classify {path}: {cp.stderr.strip()[:200]}")


def _kind(marker: str, tag: str) -> str | None:
    m = re.fullmatch(re.escape(tag) + r"-(b\d[a-z]*)-\d+", marker or "")
    return m.group(1) if m else None


def _tagged(entries: list[Rec], tag: str) -> list[Rec]:
    return [e for e in entries if str(e.get("marker", "")).startswith(tag + "-")]


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _in_window(entry: Rec, launch: Rec) -> bool:
    """True when the entry is stamped at or after the launch start (the listeners stay open until the run record is
    taken); unknowable timestamps count as inside."""
    start, at = _ts(launch.get("started")), _ts(entry.get("ts"))
    if start is None or at is None:
        return True
    return at >= start


def _workload_ran(rec: Rec, tag: str) -> bool:
    """Any run-tagged entry, or any non-host-control entry at or after the launch start, in the proxy or target log."""
    launch = rec.get("launch") or {}
    for e in (rec.get("target_log") or []) + (rec.get("proxy_log") or []):
        if str(e.get("marker", "")).startswith(tag + "-"):
            return True
        if not str(e.get("marker", "")).startswith("host-control-") and _in_window(e, launch):
            return True
    return False


def _refused(probe: Rec) -> bool:
    return probe.get("connected") is False and probe.get("winerror") in ENFORCEMENT_CODES


def judge_run(rec: Rec, detect_fail: bool = True, disable: Iterable[str] = ()) -> Rec:
    """Verdict for one run record.

    `detect_fail=False` and `disable` (names from CHECKS) exist only so a self-test can prove each detection is
    load-bearing: with it off, the synthetic record that the detection exists for is not flagged.
    """
    off = set(disable) | ({"fail"} if not detect_fail else set())
    tag = str(rec["tag"])
    dry = rec.get("dry_run") or {}
    out: Rec = {"verdict": None, "reasons": []}
    if dry.get("rc") != 0:
        out["verdict"] = "REFUSED"
        out["reasons"].append(f"dry-run rc={dry.get('rc')}: {(dry.get('stderr') or dry.get('stdout') or '').strip()[:300]}")
        return out
    payload = rec.get("payload") or {}
    launch = rec.get("launch") or {}
    target, proxy = _tagged(rec.get("target_log") or [], tag), _tagged(rec.get("proxy_log") or [], tag)
    b3_hits = [e for e in target if _kind(str(e.get("marker")), tag) == "b3"]
    b3p, b4ip, b4ii = payload.get("b3") or {}, payload.get("b4i") or {}, payload.get("b4ii") or {}
    out["b3_listener_hits"] = len(b3_hits)
    out["b3_container"] = {k: b3p.get(k) for k in ("connected", "error", "winerror") if k in b3p}
    out["b4i_container"] = {k: b4ip.get(k) for k in ("connected", "error", "winerror", "skipped") if k in b4ip}
    out["b4ii_container"] = {k: b4ii.get(k) for k in ("connected", "error", "winerror") if k in b4ii}
    fails: list[str] = []
    if b3_hits:
        fails.append(f"B3: {len(b3_hits)} run-tagged direct hit(s) on the second loopback listener")
    if b4ip.get("connected") is True:
        fails.append("B4(i): container connected to the LAN peer")
    if b4ii.get("connected") is True:
        fails.append("B4(ii): container connected to 1.1.1.1:443")
    if b3p.get("connected") is True and not b3_hits:
        fails.append("B3: container reports a connect that no listener logged")
    if "fail" not in off and fails:
        out.update(verdict="FAIL", reasons=fails)
        return out
    out["launch_exit_code"] = launch.get("exit_code")
    if payload and launch.get("exit_code") not in (None, 0):
        out["launcher_nonzero_exit"] = launch.get("exit_code")
    refusal_blob = " ".join(str(x) for x in (launch.get("stderr_tail"), launch.get("stdout_tail"), rec.get("mxc_log_tail")))
    if ("refused_at_launch" not in off and not payload and launch.get("exit_code") not in (None, 0)
            and "timeout" not in launch and REFUSAL_TEXT.search(refusal_blob)
            and ("ran_evidence" in off or not _workload_ran(rec, tag))):
        out.update(verdict="REFUSED-AT-LAUNCH",
                   reasons=[f"launch exit_code={launch.get('exit_code')}",
                            f"stderr: {str(launch.get('stderr_tail', ''))[:600]}",
                            f"stdout: {str(launch.get('stdout_tail', ''))[:300]}",
                            f"mxc log tail: {str(rec.get('mxc_log_tail', ''))[-400:]}"])
        return out
    blind: list[str] = []
    hc = rec.get("host_control") or {}
    for name in ("target", "proxy"):
        if hc.get(name) is not True:
            blind.append(f"host control for the {name} listener did not succeed")
    if "timeout" not in off and launch.get("timeout"):
        blind.append("the launch timed out: the container may have outlived the launcher")
    if not payload:
        blind.append("accepted by the dry-run but no payload report was produced"
                     + (f" (launch exit {launch.get('exit_code')}; workload ran: {_workload_ran(rec, tag)})"
                        if launch.get("exit_code") not in (None, 0) else ""))
    else:
        for key in ("b2", "b3", "b4i", "b4ii"):
            if key not in payload:
                blind.append(f"payload report lacks {key}")
    b2_payload = [r for r in (payload.get("b2") or []) if r.get("status") == 200]
    b2_proxy = {e["marker"] for e in proxy if _kind(str(e.get("marker")), tag) == "b2"
                and e.get("outcome") == "forwarded" and e.get("status") == 200}
    b2_target = {e["marker"] for e in target if _kind(str(e.get("marker")), tag) == "b2"}
    out["b2"] = {"container_200": len(b2_payload), "proxy_log": len(b2_proxy), "second_listener_log": len(b2_target)}
    if not (len(b2_payload) == len(b2_proxy) == len(b2_target) == B2_EXPECTED):
        blind.append(f"B2 control not 3 of 3 (container {len(b2_payload)}, proxy log {len(b2_proxy)}, "
                     f"second listener {len(b2_target)})")
    if "untagged" not in off and launch.get("started"):
        stray = [e for e in (rec.get("target_log") or []) + (rec.get("proxy_log") or [])
                 if not str(e.get("marker", "")).startswith("host-control-")
                 and _kind(str(e.get("marker")), tag) != "b2" and _in_window(e, launch)]
        stray = [e for e in stray if e not in b3_hits]
        if stray:
            blind.append(f"{len(stray)} unexplained listener/proxy connection(s) at or after the launch start "
                         f"(first: {json.dumps(stray[0])[:200]})")
    if "nonenforcement" not in off and payload:
        for label, probe in (("B3", b3p), ("B4(i)", b4ip), ("B4(ii)", b4ii)):
            if label == "B4(i)" and b4ip.get("skipped"):
                continue
            if probe and not _refused(probe):
                blind.append(f"{label} not reached but the error is not the enforcement code "
                             f"(error={probe.get('error')}, winerror={probe.get('winerror')}): a timeout or an "
                             f"unreachable is not a refusal")
    gw = rec.get("gateway") or {}
    pre, post = rec.get("unfenced_pre") or {}, rec.get("unfenced_post") or {}
    if "unfenced" not in off and payload:
        if not ((pre.get("c") or {}).get("connected") is True and (post.get("c") or {}).get("connected") is True):
            blind.append("unfenced 1.1.1.1:443 control did not connect both before and after the launch")
        if (not gw.get("port") or b4ip.get("skipped") or not (pre.get("gw") or {}).get("connected") is True
                or not (post.get("gw") or {}).get("connected") is True):
            blind.append("B4(i) NOT-MEASURABLE: no LAN-peer port that the unfenced control reached both before "
                         "and after the launch")
    if blind:
        out.update(verdict="INSTRUMENT-BLIND", reasons=blind)
        return out
    if b3_hits or fails:
        out.update(verdict="UNCLASSIFIED", reasons=fails or ["B3/B4 outcome not a clean refusal"])
        return out
    out.update(verdict="HOLD", reasons=["B2 3 of 3; B3, B4(i), B4(ii) each refused with the enforcement code"])
    return out


def judge_controls(ctl: Rec | None) -> Rec:
    """B5: the same direct connects from an unconfined process must succeed (1 each per batch)."""
    if not ctl:
        return {"ok": False, "reasons": ["no unfenced control record"]}
    tag = str(ctl["tag"])
    a = [e for e in _tagged(ctl.get("target_log") or [], tag) if _kind(str(e.get("marker")), tag) == "b5a"]
    b = (ctl.get("b5b") or {}).get("connected") is True
    c = (ctl.get("b5c") or {}).get("connected") is True
    reasons = [n for n, ok in (("B5 loopback listener not reached", bool(a)), ("B5 LAN peer not reached", b),
                               ("B5 1.1.1.1:443 not reached", c)) if not ok]
    return {"ok": not reasons, "reasons": reasons, "b5a": bool(a), "b5b": b, "b5c": c}


def judge_batch(runs: list[Rec], controls: Rec | None, n_expected: int = 3, detect_fail: bool = True,
                disable: Iterable[str] = ()) -> Rec:
    ctl = judge_controls(controls)
    groups: dict[str, list[Rec]] = {}
    for r in runs:
        groups.setdefault(f"{r['arm']}/{r['state']}", []).append(r)
    result: Rec = {"controls": ctl, "groups": {}}
    for key, rs in sorted(groups.items()):
        judged = [judge_run(r, detect_fail, disable) for r in rs]
        verdicts = [j["verdict"] for j in judged]
        changed = [r.get("tag") for r in rs if r.get("state_changed_by_run")]
        if "FAIL" in verdicts:
            v = "FAIL"
        elif changed:
            v = "STOPPED-STATE-CHANGE"
        elif all(x == "REFUSED" for x in verdicts) and len(verdicts) >= n_expected:
            v = "REFUSED"
        elif all(x == "REFUSED-AT-LAUNCH" for x in verdicts) and len(verdicts) >= n_expected:
            v = "REFUSED-AT-LAUNCH"
        elif any(x == "INSTRUMENT-BLIND" for x in verdicts) or (all(x == "HOLD" for x in verdicts) and not ctl["ok"]):
            v = "INSTRUMENT-BLIND"
        elif len(verdicts) < n_expected:
            v = "INCOMPLETE"
        elif all(x == "HOLD" for x in verdicts):
            v = "HOLD"
        else:
            v = "MIXED"
        not_measurable = any("NOT-MEASURABLE" in str(reason) for j in judged for reason in j["reasons"])
        result["groups"][key] = {"verdict": v, "runs": len(rs), "run_verdicts": verdicts,
                                 "b4i_not_measurable": not_measurable, "state_changed_runs": changed,
                                 "launcher_nonzero_exit_runs": [r.get("tag") for r, j in zip(rs, judged)
                                                                if j.get("launcher_nonzero_exit") is not None]}
    return result


def load_dir(folder: Path) -> tuple[list[Rec], Rec | None]:
    runs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("run-*.json"))]
    ctl_path = folder / "control-b5.json"
    return runs, (json.loads(ctl_path.read_text(encoding="utf-8")) if ctl_path.exists() else None)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -I summarise.py <output-folder>")
        return 2
    folder = Path(argv[0])
    refuse_git_path(folder)
    runs, ctl = load_dir(folder)
    summary = judge_batch(runs, ctl)
    summary["arm_refusals"] = sorted(p.stem for p in folder.glob("arm-*-refused.json"))
    (folder / "batch-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
