"""Self-test for the MXC loopback-proxy egress probe. Runs without MXC, non-elevated, no real container.

What this measures: that the probe's instruments and verdict logic behave as specified, using synthetic records
and a fake launcher that stands in for wxc-exec (fenced, open, refusing, proxy-blind, timing-out, stray-connection
and launch-refusing modes). Every detection has a toggle check: with that detection disabled, the synthetic record
it exists for is not flagged, which proves the check can see it.
Checks: forwarding proxy forwards, logs and default-denies; listeners log run tags, bind loopback only and
exclusively; summarise gives HOLD / FAIL / REFUSED / REFUSED-AT-LAUNCH / INSTRUMENT-BLIND on synthetic records
(including timeouts that are not refusals, unexplained connections in the launch window, failed unfenced controls
and a non-measurable LAN peer); the output-path guard refuses a git tree; launch.ps1 refuses a mismatched hash, a
missing hash file, a missing line and a missing file, and passes its own hash on; the arm-B precondition refuses
when the probe flag is false or absent; the state snapshot carries firewall, loopback-exemption, WinHTTP-proxy and
WFP entries and a change in it stops the batch; the harness end to end against the fake launcher; fixtures fx-a
and fx-b carry identical measured state; the probe files carry no numbered references and no operator account name.

How to run: python -I self_test.py        (prints PASS/FAIL per check; exit code non-zero on any FAIL)
What it writes: temporary folders under the system temp directory only, removed at the end. It binds 127.0.0.1
only, ports 18110, 18111 and 18113, and connects nowhere else (the 1.1.1.1 destination and the LAN peer are
remapped to a local stand-in listener).

NOT MEASURED: any build other than the one(s) run; behaviour on a host whose --probe reports host-loopback
ingress unsupported (the earlier 26200.9457 condition); an identity-scoped proxy (allowedProxyPeer); the
session-isolation backend; UDP, ICMP or DNS egress under the proxy policy; host-to-container ingress; nono under
MXC; anything about the fork or any other sandbox. This self-test does not exercise MXC at all: a PASS here says
the instrument works, not that any launcher holds.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import net_payload  # noqa: E402
import run_probe  # noqa: E402
import summarise  # noqa: E402
from proxy import ForwardingProxy, ProbeListener  # noqa: E402

PWSH = Path("C:/Program Files/PowerShell/7/pwsh.exe")
STAND_IN_PORT = 18113
RESULTS: list[tuple[str, bool, str]] = []
START, END, INSIDE, BEFORE, AFTER = ("2026-10-15T15:00:00.000-04:00", "2026-10-15T15:00:10.000-04:00",
                                     "2026-10-15T15:00:05.000-04:00", "2026-10-15T14:59:00.000-04:00",
                                     "2026-10-15T15:00:12.000-04:00")


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


# ------------------------------------------------------------------ synthetic records

def syn(tag: str = "T1", *, b2: int = 3, b3_hit: bool = False, b4i_conn: bool = False, b4ii_conn: bool = False,
        dry_rc: int = 0, host_ok: bool = True, with_payload: bool = True, stray: str | None = None,
        container_only_connect: bool = False, b3_err: int | None = 10013, b4i_err: int | None = 10013,
        b4ii_err: int | None = 10013, gw_port: int = 80, pre_c: bool = True, post_c: bool = True,
        pre_gw: bool = True, post_gw: bool = True, launch_exit: int = 0, arm: str = "B", state: str = "B1",
        stderr: str = "launch said no", launch_timeout: bool = False, changed: bool = False) -> dict:
    mk = lambda k, i: f"{tag}-{k}-{i}"  # noqa: E731
    proxy_log = [{"marker": mk("b2", i), "outcome": "forwarded", "status": 200, "ts": INSIDE} for i in range(1, b2 + 1)]
    target_log = [{"marker": mk("b2", i), "ts": INSIDE} for i in range(1, b2 + 1)]
    if b3_hit:
        target_log.append({"marker": mk("b3", 1), "ts": INSIDE})
    if stray == "inside":
        target_log.append({"marker": "", "ts": INSIDE, "bytes": 0})
    elif stray == "after":
        target_log.append({"marker": "", "ts": AFTER, "bytes": 0})
    elif stray == "before":
        target_log.append({"marker": "", "ts": BEFORE, "bytes": 0})
    refusal = lambda code: {"connected": False, "error": "PermissionError" if code else "TimeoutError", "winerror": code}  # noqa: E731
    payload = None
    if with_payload:
        payload = {"b2": [{"status": 200} for _ in range(b2)],
                   "b3": {"connected": True} if (b3_hit or container_only_connect) else refusal(b3_err),
                   "b4i": {"connected": True} if b4i_conn else (refusal(b4i_err) if gw_port else {"skipped": "no gateway port"}),
                   "b4ii": {"connected": True} if b4ii_conn else refusal(b4ii_err)}
    launch = {"exit_code": launch_exit, "started": START, "ended": END, "stderr_tail": stderr, "stdout_tail": ""}
    if launch_timeout:
        launch = {"timeout": True, "started": START}
    return {"arm": arm, "state": state, "tag": tag, "state_changed_by_run": {"x": [1, 2]} if changed else {}, "dry_run": {"rc": dry_rc, "stdout": "", "stderr": "refused text"},
            "launch": launch, "payload": payload, "target_log": target_log, "proxy_log": proxy_log,
            "gateway": {"port": gw_port}, "mxc_log_tail": "log tail",
            "unfenced_pre": {"c": {"connected": pre_c}, "gw": {"connected": pre_gw}},
            "unfenced_post": {"c": {"connected": post_c}, "gw": {"connected": post_gw}},
            "host_control": {"target": host_ok, "proxy": True}}


def verdict(rec: dict, **kw: object) -> str:
    return summarise.judge_run(rec, **kw)["verdict"]  # type: ignore[arg-type]


def test_instruments() -> None:
    lock, tlog, plog = threading.Lock(), [], []
    target = ProbeListener("target", "127.0.0.1", 18111, tlog, lock)
    proxy = ForwardingProxy(18110, {18111}, plog, lock)
    try:
        r = net_payload.http_via_proxy("127.0.0.1", 18110, "127.0.0.1", 18111, "RUN9-b2-1")
        check("proxy forwards a request to the allowlisted target", r.get("status") == 200 and "listener-target-ok" in str(r.get("body")), str(r))
        check("proxy logs the forwarded request with its run tag",
              any(e["marker"] == "RUN9-b2-1" and e["outcome"] == "forwarded" and e["status"] == 200 for e in plog), str(plog))
        check("second listener logs the proxied request with its run tag", any(e["marker"] == "RUN9-b2-1" for e in tlog), str(tlog))
        d = net_payload.tcp_probe("127.0.0.1", 18111, "RUN9-b3-1")
        check("listener logs a direct connect with its run tag", d.get("connected") is True and any(e["marker"] == "RUN9-b3-1" for e in tlog), str(d))
        denied = net_payload.http_via_proxy("127.0.0.1", 18110, "127.0.0.1", 18999, "RUN9-b2-2")
        check("proxy refuses a non-allowlisted target (default deny)", denied.get("status") == 403 and plog[-1]["outcome"] == "refused-target", str(denied))
    finally:
        proxy.close()
        target.close()
    for label, build in (("listener", lambda h: ProbeListener("x", h, 18111, [], threading.Lock())),
                         ("proxy", lambda h: ForwardingProxy(18110, set(), [], threading.Lock(), host=h))):
        try:
            build("0.0.0.0")
            ok = False
        except ValueError:
            ok = True
        check(f"{label} refuses to bind a non-loopback address", ok)

    def squatter(port: int) -> socket.socket:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return s

    for label, port, build in (("proxy", 18110, lambda: ForwardingProxy(18110, set(), [], threading.Lock())),
                               ("listener", 18111, lambda: ProbeListener("x", "127.0.0.1", 18111, [], threading.Lock()))):
        sq = squatter(port)
        try:
            built = build()
            built.close()
            ok = False
        except OSError:
            ok = True
        finally:
            sq.close()
        check(f"{label} refuses a port already held by a SO_REUSEADDR socket (exclusive bind)", ok)
    sq = squatter(18110)
    try:
        plain = ThreadingHTTPServer(("127.0.0.1", 18110), BaseHTTPRequestHandler)
        plain.server_close()
        sees = True
    except OSError:
        sees = False
    finally:
        sq.close()
    check("TOGGLE: a default http.server co-binds on top of the same squatter (the exclusive bind is load-bearing)", sees)


def test_summarise() -> None:
    check("synthetic HOLD record -> HOLD", verdict(syn()) == "HOLD", str(summarise.judge_run(syn())))
    check("synthetic B3 listener hit -> FAIL", verdict(syn(b3_hit=True)) == "FAIL")
    check("synthetic B4(i) container connect to the LAN peer -> FAIL", verdict(syn(b4i_conn=True)) == "FAIL")
    check("synthetic B4(ii) 1.1.1.1:443 connect -> FAIL", verdict(syn(b4ii_conn=True)) == "FAIL")
    check("container-reported B3 connect with no listener log -> FAIL", verdict(syn(container_only_connect=True)) == "FAIL")
    check("FAIL outranks a missing B2", verdict(syn(b3_hit=True, b2=0)) == "FAIL")
    for label, kw in (("B3 hit", dict(b3_hit=True)), ("B4(i) connect", dict(b4i_conn=True)), ("B4(ii) connect", dict(b4ii_conn=True))):
        check(f"TOGGLE: FAIL detection disabled -> synthetic {label} NOT flagged FAIL", verdict(syn(**kw), detect_fail=False) != "FAIL")  # type: ignore[arg-type]
    check("B2 missing -> INSTRUMENT-BLIND", verdict(syn(b2=0)) == "INSTRUMENT-BLIND")
    check("B2 only 2 of 3 -> INSTRUMENT-BLIND", verdict(syn(b2=2)) == "INSTRUMENT-BLIND")
    check("no payload report (launch exit 0) -> INSTRUMENT-BLIND", verdict(syn(with_payload=False)) == "INSTRUMENT-BLIND")
    check("failed listener host control -> INSTRUMENT-BLIND", verdict(syn(host_ok=False)) == "INSTRUMENT-BLIND")
    check("dry-run refusal -> REFUSED", verdict(syn(dry_rc=1, with_payload=False)) == "REFUSED")
    # unexplained connection in the launch window
    inside = summarise.judge_run(syn(stray="inside"))
    check("untagged listener connection inside the launch window -> INSTRUMENT-BLIND (never HOLD)",
          inside["verdict"] == "INSTRUMENT-BLIND" and any("unexplained" in r for r in inside["reasons"]), str(inside))
    check("untagged listener connection before the launch (host control period) is outside the window -> HOLD", verdict(syn(stray="before")) == "HOLD")
    check("untagged connection AFTER the launch ended (listeners still open) -> INSTRUMENT-BLIND", verdict(syn(stray="after")) == "INSTRUMENT-BLIND")
    check("TOGGLE: untagged-connection check disabled -> synthetic late stray NOT blind", verdict(syn(stray="after"), disable=["untagged"]) == "HOLD")
    check("launcher timeout with a clean payload -> INSTRUMENT-BLIND", verdict(syn(launch_timeout=True)) == "INSTRUMENT-BLIND")
    check("TOGGLE: timeout check disabled -> synthetic launcher timeout NOT blind", verdict(syn(launch_timeout=True), disable=["timeout"]) == "HOLD")
    nz = summarise.judge_run(syn(launch_exit=7))
    check("non-zero launcher exit with a payload report: verdict unchanged (HOLD), exit code recorded and flagged",
          nz["verdict"] == "HOLD" and nz["launcher_nonzero_exit"] == 7 and nz["launch_exit_code"] == 7, str(nz))
    check("untagged connection plus a container-reported B3 connect -> FAIL", verdict(syn(stray="inside", container_only_connect=True)) == "FAIL")
    check("TOGGLE: untagged-connection check disabled -> synthetic stray connection NOT blind", verdict(syn(stray="inside"), disable=["untagged"]) == "HOLD")
    # timeouts are not refusals
    for label, kw in (("B4(ii)", dict(b4ii_err=None)), ("B4(i)", dict(b4i_err=None)), ("B3", dict(b3_err=None))):
        check(f"{label} timeout (no enforcement code) -> INSTRUMENT-BLIND", verdict(syn(**kw)) == "INSTRUMENT-BLIND")  # type: ignore[arg-type]
    check("a different Windows error code (10060) is not the enforcement code -> INSTRUMENT-BLIND", verdict(syn(b4ii_err=10060)) == "INSTRUMENT-BLIND")
    check("TOGGLE: enforcement-code check disabled -> synthetic B4(ii) timeout NOT blind", verdict(syn(b4ii_err=None), disable=["nonenforcement"]) == "HOLD")
    # unfenced controls around the launch
    check("unfenced 1.1.1.1:443 failed before the launch -> INSTRUMENT-BLIND", verdict(syn(pre_c=False)) == "INSTRUMENT-BLIND")
    check("unfenced 1.1.1.1:443 failed after the launch -> INSTRUMENT-BLIND", verdict(syn(post_c=False)) == "INSTRUMENT-BLIND")
    check("TOGGLE: unfenced-control check disabled -> synthetic failed control NOT blind", verdict(syn(post_c=False), disable=["unfenced"]) == "HOLD")
    nm = summarise.judge_run(syn(gw_port=0))
    check("no reachable LAN-peer port -> B4(i) NOT-MEASURABLE, INSTRUMENT-BLIND, never HOLD",
          nm["verdict"] == "INSTRUMENT-BLIND" and any("NOT-MEASURABLE" in r for r in nm["reasons"]), str(nm))
    check("LAN-peer unfenced connect failed after the launch -> NOT-MEASURABLE, never HOLD", verdict(syn(post_gw=False)) == "INSTRUMENT-BLIND")
    check("TOGGLE: with the unfenced check disabled a skipped B4(i) is NOT blind", verdict(syn(gw_port=0), disable=["unfenced"]) == "HOLD")
    # refusal at launch
    refusal_text = "error: launch refused: policy not supported by this launcher"
    true_ref = syn(with_payload=False, launch_exit=3, b2=0, stderr=refusal_text)
    ran_failed = syn(with_payload=False, launch_exit=3, b2=3, stderr=refusal_text)
    stray_failed = syn(with_payload=False, launch_exit=3, b2=0, stderr=refusal_text, stray="inside")
    ral = summarise.judge_run(true_ref)
    check("true refusal (exit non-zero, no payload, no traffic, refusal text) -> REFUSED-AT-LAUNCH with the launch's own text",
          ral["verdict"] == "REFUSED-AT-LAUNCH" and any("policy not supported" in r for r in ral["reasons"]), str(ral))
    check("launched-then-failed (same exit, same text, 3 run-tagged forwards in the logs) -> INSTRUMENT-BLIND", verdict(ran_failed) == "INSTRUMENT-BLIND")
    check("launched-then-failed (untagged connection in the window, no tagged traffic) -> INSTRUMENT-BLIND", verdict(stray_failed) == "INSTRUMENT-BLIND")
    check("non-zero exit with unrecognisable text and no traffic -> INSTRUMENT-BLIND",
          verdict(syn(with_payload=False, launch_exit=3, b2=0, stderr="exit 3")) == "INSTRUMENT-BLIND")
    check("TOGGLE: ran-evidence check disabled -> the launched-then-failed record is wrongly REFUSED-AT-LAUNCH",
          verdict(ran_failed, disable=["ran_evidence"]) == "REFUSED-AT-LAUNCH")
    check("TOGGLE: refused-at-launch check disabled -> the true refusal falls to INSTRUMENT-BLIND",
          verdict(true_ref, disable=["refused_at_launch"]) == "INSTRUMENT-BLIND")
    # batches
    ctl_ok = {"tag": "C1", "target_log": [{"marker": "C1-b5a-1"}], "b5b": {"connected": True}, "b5c": {"connected": True}}
    holds = [syn(f"R{i}") for i in range(3)]
    grp = lambda runs, ctl=ctl_ok, **kw: summarise.judge_batch(runs, ctl, **kw)["groups"]["B/B1"]  # noqa: E731
    check("batch of 3 HOLD + passing controls -> HOLD", grp(holds)["verdict"] == "HOLD")
    check("batch HOLD with a failed unfenced control -> INSTRUMENT-BLIND", grp(holds, dict(ctl_ok, b5c={"connected": False}))["verdict"] == "INSTRUMENT-BLIND")
    check("batch HOLD with the LAN-peer control failed -> INSTRUMENT-BLIND", grp(holds, dict(ctl_ok, b5b={"connected": False}))["verdict"] == "INSTRUMENT-BLIND")
    check("batch with one FAIL -> FAIL", grp(holds[:2] + [syn("R9", b3_hit=True)])["verdict"] == "FAIL")
    nm_batch = grp([syn(f"N{i}", gw_port=0) for i in range(3)])
    check("batch with B4(i) not measurable -> INSTRUMENT-BLIND and flagged, never HOLD", nm_batch["verdict"] == "INSTRUMENT-BLIND" and nm_batch["b4i_not_measurable"] is True)
    refused = [syn(f"A{i}", dry_rc=1, with_payload=False, arm="A", state="A1") for i in range(3)]
    check("batch of 3 REFUSED -> REFUSED", summarise.judge_batch(refused, ctl_ok)["groups"]["A/A1"]["verdict"] == "REFUSED")
    ral3 = [syn(f"L{i}", with_payload=False, launch_exit=3, b2=0, stderr=refusal_text) for i in range(3)]
    check("batch of 3 REFUSED-AT-LAUNCH -> REFUSED-AT-LAUNCH", grp(ral3)["verdict"] == "REFUSED-AT-LAUNCH")
    sc = grp([syn("S0"), syn("S1"), syn("S2", changed=True)])
    check("batch whose last run changed host state -> STOPPED-STATE-CHANGE, never HOLD",
          sc["verdict"] == "STOPPED-STATE-CHANGE" and sc["state_changed_runs"] == ["S2"], str(sc))
    check("the same batch with no state change -> HOLD", grp([syn("S0"), syn("S1"), syn("S2")])["verdict"] == "HOLD")
    nzb = grp([syn("Z0", launch_exit=7), syn("Z1"), syn("Z2")])
    check("batch flags runs with a non-zero launcher exit without changing the verdict",
          nzb["verdict"] == "HOLD" and nzb["launcher_nonzero_exit_runs"] == ["Z0"], str(nzb))
    check("batch of 2 HOLD of 3 expected -> INCOMPLETE", grp(holds[:2])["verdict"] == "INCOMPLETE")


def test_guard_and_fixtures() -> None:
    inside = HERE / "should_not_exist_out"
    refused = False
    try:
        summarise.refuse_git_path(inside)
    except SystemExit as exc:
        refused = "inside the git working tree" in str(exc)
    check("output-path guard refuses a path inside a git working tree", refused)
    with tempfile.TemporaryDirectory() as td:
        ok = True
        try:
            summarise.refuse_git_path(Path(td) / "a" / "b")
        except SystemExit:
            ok = False
        check("output-path guard accepts a path outside every git tree", ok)
    try:
        rc = run_probe.main(["--out", str(inside), "--dry-run-only"])
        check("harness main refuses an in-tree --out before creating anything", False, f"returned {rc}")
    except SystemExit:
        check("harness main refuses an in-tree --out before creating anything", not inside.exists())
    for flag, expect in ((True, True), (False, False), (None, False)):
        probes = {} if flag is None else {run_probe.PROXY_FLAG: flag}
        check(f"arm-B precondition with flag {flag!r} -> {'allowed' if expect else 'refused'}",
              run_probe.check_arm_b_precondition({"probes": probes})[0] is expect)
    check("arm-B precondition refuses an unparsed probe", run_probe.check_arm_b_precondition({"unparsed": "x"})[0] is False)
    known = next(iter(run_probe.KNOWN_BUILDS))
    kc = run_probe.KNOWN_BUILDS[known]
    check("arm commit: a given commit is used", run_probe.resolve_arm_commit("zz", "abc123")[0] == "abc123")
    check("arm commit: from the known-build table when the sha256 matches", run_probe.resolve_arm_commit(known, None)[0] == kc)
    check("arm commit: neither given nor known -> refused", run_probe.resolve_arm_commit("zz", None)[0] is None)
    check("arm commit: a given commit contradicting the table -> refused", run_probe.resolve_arm_commit(known, "deadbeef")[0] is None)
    a = run_probe.fixture("fx-a", "cmd", Path("W"), Path("P"))
    b = run_probe.fixture("fx-b", "cmd", Path("W"), Path("P"))
    check("fx-a and fx-b are identical", a == b)
    check("fixture state: proxy set, no allowedProxyPeer, ingress allow, hostLoopback allow, egress deny, no rules",
          a["runtimeConfig"] == {"networkProxy": "http://127.0.0.1:18110"} and "allowedProxyPeer" not in json.dumps(a)
          and a["network"] == {"egress": {"default": "deny"}, "ingress": {"default": "allow", "hostLoopback": "allow"}})
    with tempfile.TemporaryDirectory() as td:
        snap = run_probe.snapshot([Path(td)], Path(td), [Path(sys.executable)])
        need = {"firewall_rules_for_interpreters", "firewall_profiles", "loopback_exempt", "winhttp_proxy", "wfp_mxc_filters"}
        check("snapshot carries firewall rules, profiles, loopback exemptions, WinHTTP proxy and WFP count", need <= set(snap), str(set(snap)))
        check("snapshot reads the firewall profiles (not 'unreadable')", isinstance(snap["firewall_profiles"], list) and len(snap["firewall_profiles"]) >= 1, str(snap["firewall_profiles"]))


def test_launch_ps1() -> None:
    if not PWSH.exists():
        check("launch.ps1 tests (pwsh present)", False, str(PWSH))
        return
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        names = ("run_probe.py", "net_payload.py", "proxy.py", "summarise.py")
        for n in names:
            shutil.copy(HERE / n, d / n)
        shutil.copy(HERE / "launch.ps1", d / "launch.ps1")
        good = "\n".join(f"{run_probe.sha256_of(d / n)}  {n}" for n in names) + "\n"

        def run(approved: Path, *extra: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.run([str(PWSH), "-NoProfile", "-File", str(d / "launch.ps1"), "-ApprovedFile", str(approved), *extra],
                                  capture_output=True, text=True, timeout=120, creationflags=0x08000000, check=False,
                                  env={**os.environ, **(env or {})})

        ap = d / "APPROVED.txt"
        ap.write_text(good, encoding="utf-8")
        r = run(ap, "-VerifyOnly")
        check("launch.ps1 verifies matching hashes (VerifyOnly)", r.returncode == 0 and "VERIFIED" in r.stdout, r.stdout + r.stderr)
        ap.write_text(good.replace(good[:8], "00000000", 1), encoding="utf-8")
        r = run(ap, "-VerifyOnly")
        check("launch.ps1 refuses a mismatched hash", r.returncode == 1 and "hash mismatch" in r.stdout, r.stdout + r.stderr)
        r = run(d / "no_such_approved.txt", "-VerifyOnly")
        check("launch.ps1 refuses a missing approved-hash file", r.returncode == 1 and "approved-hash file missing" in r.stdout, r.stdout + r.stderr)
        ap.write_text("\n".join(good.splitlines()[1:]) + "\n", encoding="utf-8")
        r = run(ap, "-VerifyOnly")
        check("launch.ps1 refuses a file with no approved line", r.returncode == 1 and "no approved hash" in r.stdout, r.stdout + r.stderr)
        # stub probe: launch.ps1 must pass its own sha256 on
        (d / "run_probe.py").write_text("import sys\nprint('ARGV', sys.argv[1:])\n", encoding="utf-8")
        good2 = "\n".join(f"{run_probe.sha256_of(d / n)}  {n}" for n in names) + "\n"
        ap.write_text(good2, encoding="utf-8")
        r = run(ap, "-SelfTestElevation", "elevated", "--arms", "A", env={"BLARAI_PROBE_PYTHON": sys.executable})
        own = run_probe.sha256_of(d / "launch.ps1")
        check("launch.ps1 starts the probe and passes its own sha256 and the probe args",
              r.returncode == 0 and f"--launch-sha256', '{own}'" in r.stdout and "'--arms', 'A'" in r.stdout, r.stdout + r.stderr)
        r = run(ap, "-SelfTestElevation", "standard", "--arms", "A", env={"BLARAI_PROBE_PYTHON": sys.executable})
        check("launch.ps1 refuses a live run when not elevated and says why", r.returncode == 1 and "elevated" in r.stdout and "ARGV" not in r.stdout, r.stdout + r.stderr)
        r = run(ap, "-SelfTestElevation", "standard", "--dry-run-only", env={"BLARAI_PROBE_PYTHON": sys.executable})
        check("launch.ps1 allows --dry-run-only without elevation", r.returncode == 0 and "--dry-run-only" in r.stdout, r.stdout + r.stderr)
        ap.write_text(good2, encoding="utf-8")
        (d / "proxy.py").unlink()
        r = run(ap, "-VerifyOnly")
        check("launch.ps1 refuses a missing probe file", r.returncode == 1 and "file missing: proxy.py" in r.stdout, r.stdout + r.stderr)


# ------------------------------------------------------------------ end to end against a fake launcher

FAKE_LAUNCHER = r'''
import json, os, runpy, shlex, socket, sys
args = sys.argv[1:]
mode = os.environ.get("FAKE_MODE", "fenced")
if args == ["--probe"]:
    print(json.dumps({"tier": "base-container", "probes": {"baseContainerSupportsIdentitylessLoopbackProxy": os.environ.get("FAKE_FLAG", "true") == "true"}}))
    sys.exit(0)
cfg = json.load(open(args[0], encoding="utf-8"))
if "--dry-run" in args:
    if mode == "refuse":
        print("error: policy refused by the fake launcher", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
if mode == "launchrefuse":
    print("error: launch refused by the fake launcher", file=sys.stderr)
    sys.exit(3)
toks = [t.strip('"') for t in shlex.split(cfg["process"]["commandLine"], posix=False)]
proxy_port = int(cfg["runtimeConfig"]["networkProxy"].rsplit(":", 1)[1])
target_port = int(toks[toks.index("--target-port") + 1])
orig = socket.create_connection
if mode == "stray":
    orig(("127.0.0.1", target_port), timeout=3).close()
def patched(addr, *a, **k):
    host, port = addr
    if mode == "open":
        return orig(addr, *a, **k)
    if mode in ("fenced", "stray", "crash", "exit7") and port == proxy_port:
        return orig(addr, *a, **k)
    if mode == "timeout" and port == proxy_port:
        return orig(addr, *a, **k)
    if mode == "timeout":
        raise TimeoutError("timed out")
    raise OSError(0, "fake fence", None, 10013)
socket.create_connection = patched
sys.argv = [toks[2]] + toks[3:]
code = 0
try:
    runpy.run_path(toks[2], run_name="__main__")
except SystemExit as e:
    code = e.code or 0
if mode == "crash":
    os.unlink(toks[toks.index("--out") + 1])
    print("error: request refused: payload crashed", file=sys.stderr)
    sys.exit(1)
if mode == "exit7":
    sys.exit(7)
sys.exit(code)
'''


def run_harness(td: Path, arm: str, mode: str, flag: str = "true", runs: int = 3, commit: str | None = "fakecommit",
                out: Path | None = None) -> tuple[int, str, Path]:
    fake_py = td / "fake_wxc.py"
    fake_py.write_text(FAKE_LAUNCHER, encoding="utf-8")
    bat = td / "fake_wxc.bat"
    bat.write_text(f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n', encoding="ascii")
    out = out or td / f"out-{arm}-{mode}-{flag}-{len(list(td.glob('out-*')))}"
    run_probe.LAUNCHERS[arm] = bat
    os.environ.update(FAKE_MODE=mode, FAKE_FLAG=flag)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        extra = ["--arm-b-commit" if arm == "B" else "--arm-b0-commit", commit] if (commit and arm in ("B", "B0")) else []
        rc = run_probe.main(["--out", str(out), "--arms", arm, "--runs", str(runs), *extra])
    return rc, buf.getvalue(), out


def group(out: Path, key: str) -> dict:
    return json.loads((out / "batch-summary.json").read_text(encoding="utf-8"))["groups"][key]


def test_end_to_end() -> None:
    stand_log: list = []
    stand = ProbeListener("standin", "127.0.0.1", STAND_IN_PORT, stand_log, threading.Lock())
    orig_probe = net_payload.tcp_probe

    def remap(host: str, port: int, marker: str | None, timeout: float = 5.0) -> dict:
        if host == "1.1.1.1":
            return orig_probe("127.0.0.1", STAND_IN_PORT, marker, timeout)
        return orig_probe(host, port, marker, timeout)

    net_payload.tcp_probe = remap  # type: ignore[assignment]
    saved = (run_probe.TOOLCHAIN, run_probe.CONTAINER_PY, dict(run_probe.LAUNCHERS), run_probe.gateway_ip,
             run_probe.GATEWAY_PORTS, run_probe.snapshot)
    run_probe.gateway_ip = lambda: "127.0.0.1"  # type: ignore[assignment]
    run_probe.GATEWAY_PORTS = (STAND_IN_PORT,)
    try:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            run_probe.TOOLCHAIN, run_probe.CONTAINER_PY = td / "toolchain", Path(sys.executable)
            rc, text, out = run_harness(td, "B", "fenced")
            g = group(out, "B/B1")
            s = json.loads((out / "batch-summary.json").read_text(encoding="utf-8"))
            check("end to end, fenced fake launcher: batch HOLD over 3 runs", rc == 0 and g["verdict"] == "HOLD" and g["runs"] == 3, text[-600:] + json.dumps(s)[:500])
            check("end to end: unfenced control B5 passed", s["controls"]["ok"] is True, json.dumps(s["controls"]))
            rec = json.loads(sorted(out.glob("run-B-B1-*.json"))[0].read_text(encoding="utf-8"))
            check("run record carries policy, dry-run, launch, logs, machine, snapshots, unfenced pre/post; no internal-reference field",
                  all(k in rec for k in ("policy_as_submitted", "dry_run", "launch", "proxy_log", "target_log", "machine",
                                         "snapshot_before", "snapshot_after", "unfenced_pre", "unfenced_post"))
                  and "lan_log" not in rec and ("ti" + "cket") not in rec and "windows_build" in rec["machine"], str(list(rec)))
            h = json.loads((out / "batch-header.json").read_text(encoding="utf-8"))
            check("batch header records arm-B commit, interpreter hashes, launch.ps1 hash, firewall product, gateway, scope note, host prep",
                  h["arm_commits"]["B"]["commit"] == "fakecommit" and len(h["interpreters"]["host"]["sha256"]) == 64
                  and len(h["interpreters"]["container"]["sha256"]) == 64 and len(h["launch_ps1_sha256"]) == 64
                  and "firewall_product" in h and "gateway" in h and "B" in h["scope_notes"] and "host_prep" in h, str(list(h)))
            check("batch header says whether --probe reports a PSEC version (false for the fake) and asserts none itself",
                  h["launchers"]["B"]["probe_reports_psec_version"] is False and "PSEC" not in json.dumps(h["scope_notes"]))
            rc, text, out = run_harness(td, "B", "open")
            runs = sorted(out.glob("run-B-B1-*.json"))
            check("end to end, open fake launcher: prints STOP line, returns 5, stops after the first FAIL",
                  rc == 5 and "STOP: FAIL condition met" in text and len(runs) == 1
                  and json.loads(runs[0].read_text(encoding="utf-8"))["verdict"]["verdict"] == "FAIL", f"rc={rc} runs={len(runs)} {text[-400:]}")
            rc, text, out = run_harness(td, "A", "refuse")
            r0 = json.loads(sorted(out.glob("run-A-A1-*.json"))[0].read_text(encoding="utf-8"))
            check("end to end, refusing launcher: batch REFUSED with the exact text and no launch",
                  group(out, "A/A1")["verdict"] == "REFUSED" and "policy refused by the fake launcher" in r0["dry_run"]["stderr"]
                  and r0["dry_run"]["rc"] == 1 and r0["launch"].get("skipped"))
            rc, text, out = run_harness(td, "B", "launchrefuse")
            r0 = json.loads(sorted(out.glob("run-B-B1-*.json"))[0].read_text(encoding="utf-8"))
            check("end to end, dry-run accepted but launch refused: batch REFUSED-AT-LAUNCH with the launch's own stderr",
                  group(out, "B/B1")["verdict"] == "REFUSED-AT-LAUNCH" and any("launch refused by the fake launcher" in x for x in r0["verdict"]["reasons"]),
                  json.dumps(r0["verdict"])[:400])
            rc, text, out = run_harness(td, "B", "blind")
            check("end to end, proxy path blocked (B2 cannot pass): batch INSTRUMENT-BLIND", group(out, "B/B1")["verdict"] == "INSTRUMENT-BLIND")
            rc, text, out = run_harness(td, "B", "timeout")
            check("end to end, direct connects time out instead of being refused: batch INSTRUMENT-BLIND (a timeout is not a refusal)",
                  group(out, "B/B1")["verdict"] == "INSTRUMENT-BLIND", json.dumps(group(out, "B/B1")))
            rc, text, out = run_harness(td, "B", "stray")
            r0 = json.loads(sorted(out.glob("run-B-B1-*.json"))[0].read_text(encoding="utf-8"))
            check("end to end, an untagged connection to the second listener during the launch: run INSTRUMENT-BLIND, never HOLD",
                  r0["verdict"]["verdict"] == "INSTRUMENT-BLIND" and any("unexplained" in x for x in r0["verdict"]["reasons"]), json.dumps(r0["verdict"])[:400])
            counter = iter(range(10_000))
            run_probe.snapshot = lambda *a, **k: {"n": next(counter)}  # type: ignore[assignment]
            rc, text, out = run_harness(td, "B", "fenced")
            check("end to end, any change between the before and after snapshot stops the batch (STOP, exit 4) and the summary agrees",
                  rc == 4 and "STOP: changed state" in text and len(list(out.glob("run-B-B1-*.json"))) == 1
                  and group(out, "B/B1")["verdict"] == "STOPPED-STATE-CHANGE", f"rc={rc} {text[-300:]}")
            counter = iter(range(10_000))
            run_probe.snapshot = lambda *a, **k: {"n": 0 if next(counter) < 5 else 1}  # type: ignore[assignment]
            rc, text, out = run_harness(td, "B", "fenced")
            run_probe.snapshot = saved[5]  # type: ignore[assignment]
            check("end to end, state change only in the LAST run: exit 4 and the summary says STOPPED-STATE-CHANGE, not HOLD",
                  rc == 4 and len(list(out.glob("run-B-B1-*.json"))) == 3 and group(out, "B/B1")["verdict"] == "STOPPED-STATE-CHANGE",
                  f"rc={rc} {json.dumps(group(out, 'B/B1'))}")
            rc, text, out = run_harness(td, "B", "crash")
            r0 = json.loads(sorted(out.glob("run-B-B1-*.json"))[0].read_text(encoding="utf-8"))
            check("end to end, container ran then the launcher failed with refusal-like text and no report: INSTRUMENT-BLIND, not REFUSED-AT-LAUNCH",
                  r0["verdict"]["verdict"] == "INSTRUMENT-BLIND" and group(out, "B/B1")["verdict"] == "INSTRUMENT-BLIND", json.dumps(r0["verdict"])[:400])
            rc, text, out = run_harness(td, "B", "exit7")
            r0 = json.loads(sorted(out.glob("run-B-B1-*.json"))[0].read_text(encoding="utf-8"))
            check("end to end, launcher exit 7 with a clean payload: HOLD, exit code recorded and flagged in the summary",
                  group(out, "B/B1")["verdict"] == "HOLD" and r0["launch"]["exit_code"] == 7
                  and len(group(out, "B/B1")["launcher_nonzero_exit_runs"]) == 3, json.dumps(group(out, "B/B1"))[:300])
            rc, text, out = run_harness(td, "B", "fenced", runs=1)
            rc2, text2, _ = run_harness(td, "B", "fenced", runs=1, out=out)
            check("a second batch into an output folder that already holds a batch header is refused",
                  rc == 0 and rc2 == 2 and "fresh output folder" in text2, text2[-200:])
            rc, text, out = run_harness(td, "B", "fenced", commit=None)
            check("arm B with no commit and an unknown launcher sha256: refused, nothing runs",
                  (out / "arm-B-refused.json").exists() and not list(out.glob("run-*.json")) and "known-build" in text, text[-300:])
            bat_sha = run_probe.sha256_of(td / "fake_wxc.bat")
            run_probe.KNOWN_BUILDS[bat_sha] = "knowncommit"
            rc, text, out = run_harness(td, "B", "fenced", commit=None, runs=1)
            h = json.loads((out / "batch-header.json").read_text(encoding="utf-8"))
            check("arm B with no commit but a launcher sha256 in the known-build table: runs, basis recorded from the table",
                  rc == 0 and h["arm_commits"]["B"]["commit"] == "knowncommit" and "known-build table" in h["arm_commits"]["B"]["basis"], text[-300:])
            rc, text, out = run_harness(td, "B", "fenced", commit="other", runs=1)
            check("arm B with a commit that contradicts the known-build table: refused",
                  (out / "arm-B-refused.json").exists() and not list(out.glob("run-*.json")), text[-300:])
            del run_probe.KNOWN_BUILDS[bat_sha]
            rc, text, out = run_harness(td, "B", "fenced", flag="false")
            refusal = out / "arm-B-refused.json"
            check("end to end, arm B with the proxy flag false: refused, recorded, no run records",
                  refusal.exists() and not list(out.glob("run-*.json")) and "REFUSED" in text
                  and run_probe.PROXY_FLAG in json.loads(refusal.read_text(encoding="utf-8"))["reason"], text[-300:])
            run_probe.LAUNCHERS["B"] = td / "absent" / "wxc-exec.exe"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_probe.main(["--out", str(td / "out-absent"), "--arms", "B", "--runs", "1"])
            check("arm B with the launcher file absent: refused cleanly",
                  (td / "out-absent" / "arm-B-refused.json").exists() and "absent" in buf.getvalue())
    finally:
        net_payload.tcp_probe = orig_probe  # type: ignore[assignment]
        (run_probe.TOOLCHAIN, run_probe.CONTAINER_PY, _, run_probe.gateway_ip, run_probe.GATEWAY_PORTS,
         run_probe.snapshot) = saved  # type: ignore[assignment]
        run_probe.LAUNCHERS.clear()
        run_probe.LAUNCHERS.update(saved[2])
        stand.close()


def test_hygiene() -> None:
    bad: list[str] = []
    for p in sorted(HERE.glob("*")):
        if p.suffix not in (".py", ".ps1", ".cmd", ".md"):
            continue
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"#\d|\bp\d+-|" + "mr" + "bla", text, re.I):
            bad.append(f"{p.name}: {m.group(0)!r}")
    check("probe files carry no hash-digit refs, p<digits>- fixture names or operator account name", not bad, "; ".join(bad[:5]))
    src = (HERE / "run_probe.py").read_text(encoding="utf-8") + (HERE / "proxy.py").read_text(encoding="utf-8")
    check("no code path binds a listener on a non-loopback address (no lan_ip, no 0.0.0.0 bind)",
          "def lan_ip" not in src and "bind((\"0.0.0.0\"" not in src and "LAN_PORT" not in src)


def main() -> int:
    for fn in (test_instruments, test_summarise, test_guard_and_fixtures, test_launch_ps1, test_end_to_end, test_hygiene):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a crashed check is a FAIL, never a skip
            check(f"{fn.__name__} ran to completion", False, repr(exc))
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)} PASS, {len(failed)} FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
