"""MXC loopback-proxy egress probe: harness, policy fixtures and per-run driver.

What this measures: with `runtimeConfig.networkProxy` pointing at a loopback proxy the run controls, per launcher
(arm A signed v1.0.0; arm B main build; optional arm B0 older main build):
  A1/B1  the same policy (fx-a / fx-b): accepted or refused by `--dry-run`, with the exact error text and exit
         code; the tier and flags `--probe` reports. Policy: networkProxy http://127.0.0.1:<proxy_port>, no
         allowedProxyPeer, ingress.default allow, ingress.hostLoopback allow, egress.default deny, no egress rules.
  If accepted, in the same container run: B2 three HTTP requests through the forwarding proxy to a second
  loopback listener (instrument control); B3 a direct connect to that listener; B4 connect-only attempts to
  a real LAN peer (the default gateway, on a port an unfenced pre-check reached) (i) and to 1.1.1.1:443 (ii).
  Once per batch, B5: the same direct connects from this unconfined process (control); and immediately before
  and after every launch the unfenced 1.1.1.1:443 and gateway connects are repeated.
  Reach for B2 and B3 is judged from the HOST-SIDE listener logs (run tag required; any unexplained listener
  connection during the launch window blinds the run); B4(i) and B4(ii) from the container's error code, where
  only WinError 10013 counts as a refusal. No listener is ever bound on a non-loopback address.
  Verdicts (HOLD / FAIL / REFUSED / REFUSED-AT-LAUNCH / INSTRUMENT-BLIND) come from summarise.py.
  Arm B (and B0) is refused unless `--probe` reports baseContainerSupportsIdentitylessLoopbackProxy == true.
  On any FAIL the harness prints `STOP: FAIL condition met` and runs nothing further.

How to run (use launch.ps1, which verifies the approved hashes first):
  python -I run_probe.py [--out DIR] [--runs 3] [--arms A,B[,B0]] [--dry-run-only] [--arm-b-commit SHA] [--arm-b0-commit SHA]
Live runs are launched ELEVATED (launch.ps1 refuses a live run otherwise); elevation is recorded here regardless.
An --out folder that already holds a batch header is refused.
`--dry-run-only` builds each arm's policy, applies the arm-B precondition and runs `--dry-run` only: no
listeners, no container. Elevation is recorded, not required.

What it writes: raw records ONLY under --out (default <home>/blarai-research-data/mxc-proxy-egress/run-<date>-<n>);
a path inside a git working tree is refused. Everything the harness stages (policy files, payload copy, work and
state directories, MXC logs) lives under <out>/staging. Files: batch-header.json, control-b5.json,
arm-<arm>-refused.json, run-<arm>-<state>-r<i>-<time>.json, batch-summary.json.

NOT MEASURED: any build other than the one(s) run; behaviour on a host whose --probe reports host-loopback
ingress unsupported (the earlier 26200.9457 condition); an identity-scoped proxy (allowedProxyPeer); the session-isolation backend; UDP, ICMP or DNS egress under the proxy policy;
host-to-container ingress (the doc's own open limitation); nono under MXC (no MXC backend ships); anything
about the fork or any other sandbox. Also not measured: IPv6, HTTPS or CONNECT through the proxy, destination
ports other than those named, and run-to-run variance beyond the counts recorded.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import net_payload  # noqa: E402
import summarise  # noqa: E402
from proxy import ForwardingProxy, ProbeListener, now_iso  # noqa: E402

Rec = dict[str, Any]

MXC_ROOT = Path("C:/blarai-spike-mxc")
LAUNCHERS: dict[str, Path] = {
    "A": MXC_ROOT / "dl/x64/wxc-exec.exe",
    "B": MXC_ROOT / "build-main-20261015/target/x86_64-pc-windows-msvc/release/wxc-exec.exe",
    "B0": MXC_ROOT / "build1406/target/x86_64-pc-windows-msvc/release/wxc-exec.exe",
}
ARM_FIXTURE = {"A": ("fx-a", "A1"), "B": ("fx-b", "B1"), "B0": ("fx-b", "B1")}
TOOLCHAIN = Path("C:/blarai-spike/toolchain")
CONTAINER_PY = TOOLCHAIN / "Python314/python.exe"
PROXY_PORT, TARGET_PORT = 18110, 18111
GATEWAY_PORTS = (80, 443, 53)
KNOWN_BUILDS = {
    "e951922beec5ad5f0ba967e398763640c3b24c96cbf97f2d198174a949e5f8cc": "525d0f25763b2edaab56e29651fb7c12c4cbbd93",
    "3cf91a4598a9acb657f8ca959a7393dab5b79ece2d993dfe3c392f2615279311": "70fc7d52",
}
PROXY_FLAG = "baseContainerSupportsIdentitylessLoopbackProxy"
HARNESS_FILES = ("run_probe.py", "net_payload.py", "proxy.py", "summarise.py")
PWSH = "C:/Program Files/PowerShell/7/pwsh.exe"
CREATE_NO_WINDOW = 0x08000000
BELOW_NORMAL = 0x00004000
REG_MAPPINGS = (r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion"
                r"\ProcessSandboxes\Mappings")
REG_AC_MAPPINGS = (r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion"
                   r"\AppContainer\Mappings")


def win(p: Path | str) -> str:
    return str(p).replace("/", "\\")


def hidden(argv: list[str], state_dir: Path | None = None, timeout: float = 600,
           extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(extra_env or {})
    if state_dir is not None:
        env["MXC_DACL_STATE_DIR"] = str(state_dir)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env,
                          creationflags=CREATE_NO_WINDOW | BELOW_NORMAL, check=False)


def default_out() -> Path:
    root = Path.home() / "blarai-research-data" / "mxc-proxy-egress"
    stamp = datetime.now().strftime("%Y%m%d")
    n = 1
    while (root / f"run-{stamp}-{n}").exists():
        n += 1
    return root / f"run-{stamp}-{n}"


# ---------------------------------------------------------------- policy fixtures

def policy_core(proxy_port: int) -> Rec:
    """The part of the policy that defines the measured state; identical for fx-a and fx-b."""
    return {
        "network": {"egress": {"default": "deny"}, "ingress": {"default": "allow", "hostLoopback": "allow"}},
        "runtimeConfig": {"networkProxy": f"http://127.0.0.1:{proxy_port}"},
    }


def fixture(name: str, command_line: str, work_dir: Path, payload_dir: Path, proxy_port: int = PROXY_PORT) -> Rec:
    """Policy for fixture `name` (fx-a: arm A, fx-b: arm B and B0). Only the fixture name differs in provenance."""
    if name not in ("fx-a", "fx-b"):
        raise ValueError(f"unknown fixture {name!r}")
    core = policy_core(proxy_port)
    return {
        "version": "1.0.0", "containment": "processcontainer", "lifecycle": {"destroyOnExit": True},
        "fallback": {"allowDaclMutation": False},
        "process": {"commandLine": command_line, "cwd": win(work_dir), "inheritDefaultEnv": True, "timeout": 150000},
        "filesystem": {"readwritePaths": [win(work_dir)], "readonlyPaths": [win(TOOLCHAIN), win(payload_dir)]},
        "network": core["network"], "runtimeConfig": core["runtimeConfig"],
        "ui": {"disable": False, "clipboard": "none", "injection": False},
    }


# ---------------------------------------------------------------- preconditions

def check_arm_b_precondition(probe_json: Rec) -> tuple[bool, str]:
    """Arm B/B0 run only if `--probe` reports the identity-less loopback proxy flag as exactly true."""
    flag = (probe_json.get("probes") or {}).get(PROXY_FLAG) if isinstance(probe_json, dict) else None
    if flag is True:
        return True, f"{PROXY_FLAG} == true"
    return False, f"{PROXY_FLAG} is {flag!r} in the launcher's --probe output (required: true)"


def resolve_arm_commit(sha256: str | None, given: str | None) -> tuple[str | None, str]:
    """Source commit for a built launcher: the one given on the command line, else the known-build table's entry for
    the launcher's sha256. A given commit that contradicts the table, or neither source, yields (None, reason)."""
    known = KNOWN_BUILDS.get(sha256 or "")
    if given and known and not (known.startswith(given) or given.startswith(known)):
        return None, f"--*-commit {given!r} contradicts the known build for this launcher sha256 ({known})"
    if given:
        return given, "given on the command line" + (" (matches the known-build table)" if known else "")
    if known:
        return known, "from the known-build table (launcher sha256 matched)"
    return None, "no commit given and the launcher sha256 is not in the known-build table"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def launcher_info(exe: Path) -> Rec:
    """Hash, Authenticode status and full --probe output; {'present': False} when the file is absent."""
    if not exe.exists():
        return {"path": str(exe), "present": False}
    probe = hidden([str(exe), "--probe"])
    try:
        pj: Rec = json.loads(probe.stdout)
    except ValueError:
        pj = {"unparsed": probe.stdout[-500:], "stderr": probe.stderr[-300:]}
    sig = hidden([PWSH, "-NoProfile", "-Command",
                  f"$s=Get-AuthenticodeSignature '{exe}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\""])
    return {"path": str(exe), "present": True, "sha256": sha256_of(exe), "size": exe.stat().st_size,
            "signature": sig.stdout.strip(), "probe_rc": probe.returncode, "probe": pj}


# ---------------------------------------------------------------- machine and state

def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class _PowerStatus(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", wintypes.DWORD), ("BatteryFullLifeTime", wintypes.DWORD)]


def machine_conditions() -> Rec:
    out: Rec = {"elevated": is_elevated(), "time": now_iso()}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            build = winreg.QueryValueEx(k, "CurrentBuildNumber")[0]
            ubr = winreg.QueryValueEx(k, "UBR")[0]
            out["windows_build"] = f"{build}.{ubr}"
            out["windows_product"] = winreg.QueryValueEx(k, "ProductName")[0]
    except OSError as exc:
        out["windows_build"] = f"unavailable: {exc!r}"
    try:
        ps = _PowerStatus()
        ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(ps))
        out["ac_power"] = {1: True, 0: False}.get(ps.ACLineStatus)
        out["battery_percent"] = ps.BatteryLifePercent
    except (AttributeError, OSError):
        out["ac_power"] = None
    cp = hidden(["tasklist", "/fo", "csv", "/nh"], timeout=60)
    names = [ln.split('","')[0].strip('"') for ln in cp.stdout.splitlines() if ln.strip()]
    matched = sorted(n for n in names if re.search(r"bd|bitdefender|vsserv|epsecurity|"
                                                   r"epintegration|updatesrv|seccenter|epprotected", n, re.I))
    out["bitdefender_processes"] = len(matched)
    out["bitdefender_process_names"] = matched
    return out


def sddl_of(path: Path) -> str:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kern = ctypes.WinDLL("kernel32", use_last_error=True)
    vp = ctypes.c_void_p
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, vp, vp, vp, vp,
                                          ctypes.POINTER(vp)]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [vp, wintypes.DWORD, wintypes.DWORD,
                                                                          ctypes.POINTER(wintypes.LPWSTR), vp]
    kern.LocalFree.argtypes = [vp]
    sd = vp()
    rc = adv.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(sd))
    if rc:
        return f"<unreadable: error {rc}>"
    text = wintypes.LPWSTR()
    ok = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, ctypes.byref(text), None)
    value = text.value if ok else "<convert failed>"
    if ok:
        kern.LocalFree(ctypes.cast(text, vp))
    kern.LocalFree(sd)
    return value or ""


def reg_list(key: str) -> list[str]:
    cp = hidden(["reg", "query", key])
    return (sorted(ln.strip() for ln in cp.stdout.splitlines() if ln.strip().startswith("HKEY"))
            if cp.returncode == 0 else ["<absent>"])


FIREWALL_PS = r"""
$progs = @($env:BLARAI_PROGS -split ';' | Where-Object { $_ })
$rules = @()
foreach ($f in Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) {
  if ($progs -contains $f.Program) {
    foreach ($r in ($f | Get-NetFirewallRule)) {
      $rules += "$($r.Name)|$($r.DisplayName)|$($r.Enabled)|$($r.Direction)|$($r.Action)|$($r.Profile)|$($f.Program)"
    }
  }
}
$prof = @(Get-NetFirewallProfile | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.DefaultInboundAction)|$($_.DefaultOutboundAction)|$($_.NotifyOnListen)" })
$product = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue | ForEach-Object { "$($_.displayName)|$($_.productState)" })
@{ rules = @($rules | Sort-Object); profiles = $prof; product = $product } | ConvertTo-Json -Compress -Depth 3
"""


def firewall_state(programs: list[Path]) -> Rec:
    """Firewall rules whose program is one of `programs`, the profiles, and the registered firewall product."""
    cp = hidden([PWSH, "-NoProfile", "-Command", FIREWALL_PS], timeout=180,
                extra_env={"BLARAI_PROGS": ";".join(win(p) for p in programs)})
    try:
        return json.loads(cp.stdout)
    except ValueError:
        return {"unreadable": (cp.stdout[-200:] + cp.stderr[-200:])}


def wfp_mxc_filter_count(scratch: Path) -> object:
    """Count of WFP filters whose name mentions mxc/wxc; 'unreadable' when the read needs elevation."""
    if not is_elevated():
        return "unreadable: not elevated"
    target = scratch / "wfp-filters.xml"
    cp = hidden(["netsh", "wfp", "show", "filters", f"file={target}"], timeout=180)
    if cp.returncode != 0 or not target.exists():
        return f"unreadable: netsh rc={cp.returncode}"
    raw = target.read_bytes()
    text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", errors="replace")
    target.unlink()
    return len(re.findall(r"<name>[^<]*(?:mxc|wxc)[^<]*</name>", text, re.I))


def snapshot(watched: list[Path], state_dir: Path, programs: list[Path] | None = None) -> Rec:
    """State that a run must leave unchanged. Any difference between before and after stops the batch."""
    fw = firewall_state(programs or [])
    return {"acl": {str(p): hashlib.sha256(sddl_of(p).encode()).hexdigest()[:16] for p in watched},
            "process_sandboxes": reg_list(REG_MAPPINGS), "appcontainer_mappings": len(reg_list(REG_AC_MAPPINGS)),
            "state_dir": sorted(p.name for p in state_dir.glob("*")),
            "firewall_rules_for_interpreters": fw.get("rules", fw.get("unreadable")),
            "firewall_profiles": fw.get("profiles", fw.get("unreadable")),
            "loopback_exempt": hidden(["CheckNetIsolation", "LoopbackExempt", "-s"], timeout=60).stdout.strip(),
            "winhttp_proxy": hidden(["netsh", "winhttp", "show", "proxy"], timeout=60).stdout.strip(),
            "wfp_mxc_filters": wfp_mxc_filter_count(state_dir)}


def gateway_ip() -> str | None:
    """Default gateway IPv4 from the routing table (the LAN peer for B4(i)); None when it cannot be read."""
    cp = hidden([PWSH, "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
    ip = cp.stdout.strip().splitlines()[0].strip() if cp.stdout.strip() else ""
    return ip if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and ip != "0.0.0.0" else None


def pick_gateway_port(gw: str | None) -> int:
    """First port in GATEWAY_PORTS that an unfenced connect reaches; 0 when none (B4(i) is then NOT-MEASURABLE)."""
    if gw is None:
        return 0
    for port in GATEWAY_PORTS:
        if net_payload.tcp_probe(gw, port, None, 3).get("connected") is True:
            return port
    return 0


def unfenced(gw: str | None, gw_port: int) -> Rec:
    """The unfenced connects that attribute a refusal to the container: 1.1.1.1:443 and the gateway peer."""
    return {"c": net_payload.tcp_probe("1.1.1.1", 443, None, 4),
            "gw": (net_payload.tcp_probe(gw, gw_port, None, 4) if gw and gw_port
                   else {"connected": None, "skipped": "no gateway port"}),
            "ts": now_iso()}


# ---------------------------------------------------------------- instruments

class Instruments:
    """Fresh proxy + second loopback listener, each with its own log, host-control tested. Loopback only."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.target_log: list[Rec] = []
        self.proxy_log: list[Rec] = []
        self.target = ProbeListener("target", "127.0.0.1", TARGET_PORT, self.target_log, self.lock)
        self.proxy = ForwardingProxy(PROXY_PORT, {TARGET_PORT}, self.proxy_log, self.lock)

    def host_control(self) -> Rec:
        t = net_payload.tcp_probe("127.0.0.1", TARGET_PORT, "host-control-target-1", 3)
        p = net_payload.http_via_proxy("127.0.0.1", PROXY_PORT, "127.0.0.1", TARGET_PORT, "host-control-proxy-1")
        return {"target": t.get("connected") is True, "proxy": p.get("status") == 200,
                "detail": {"target": t, "proxy": p}}

    def close(self) -> None:
        for x in (self.target, self.proxy):
            x.close()


# ---------------------------------------------------------------- driver

def run_unfenced_control(gw: str | None, gw_port: int, out: Path) -> Rec:
    """B5: the same direct connects from this unconfined process, 1 each."""
    ins = Instruments()
    tag = f"ctl-{datetime.now().strftime('%H%M%S')}"
    try:
        hc = ins.host_control()
        a = net_payload.tcp_probe("127.0.0.1", TARGET_PORT, f"{tag}-b5a-1")
        u = unfenced(gw, gw_port)
        time.sleep(0.5)
    finally:
        ins.close()
    with ins.lock:
        rec: Rec = {"tag": tag, "host_control": hc, "b5a": a, "b5b": u["gw"], "b5c": u["c"],
                    "gateway_port": gw_port, "target_log": list(ins.target_log), "proxy_log": list(ins.proxy_log),
                    "machine": machine_conditions()}
    rec["judgement"] = summarise.judge_controls(rec)
    (out / "control-b5.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def payload_command(tag: str, result: Path, stg: dict[str, Path], gw: str | None, gw_port: int) -> str:
    return (f'"{win(CONTAINER_PY)}" -I "{win(stg["payload"] / "net_payload.py")}" --tag {tag} '
            f'--out "{win(result)}" --gateway-ip {gw or "0.0.0.0"} --gateway-port {gw_port} '
            f'--proxy-port {PROXY_PORT} --target-port {TARGET_PORT}')


def run_one(arm: str, run_no: int, gw: str | None, gw_port: int, out: Path, stg: dict[str, Path],
            watched: list[Path], programs: list[Path]) -> Rec:
    fx_name, state = ARM_FIXTURE[arm]
    exe = LAUNCHERS[arm]
    tag = f"{arm}-{state}-r{run_no}-{datetime.now().strftime('%H%M%S')}"
    result_path = stg["work"] / f"result-{tag}.json"
    policy = fixture(fx_name, payload_command(tag, result_path, stg, gw, gw_port), stg["work"], stg["payload"])
    cfg_path = stg["cfg"] / f"{tag}.json"
    cfg_path.write_text(json.dumps(policy, indent=1), encoding="utf-8")
    ins = Instruments()
    rec: Rec = {"arm": arm, "state": state, "fixture": fx_name, "run": run_no, "tag": tag, "launcher": str(exe),
                "policy_as_submitted": policy, "machine": machine_conditions(),
                "gateway": {"port": gw_port, "ip_recorded": gw},
                "snapshot_before": snapshot(watched, stg["state"], programs)}
    try:
        rec["host_control"] = ins.host_control()
        dry = hidden([str(exe), str(cfg_path), "--dry-run"], stg["state"])
        rec["dry_run"] = {"rc": dry.returncode, "stdout": dry.stdout.strip()[-4000:], "stderr": dry.stderr.strip()[-4000:]}
        if dry.returncode == 0:
            logf = stg["logs"] / f"{tag}.log"
            rec["unfenced_pre"] = unfenced(gw, gw_port)
            t0, started = time.perf_counter(), now_iso()
            try:
                cp = hidden([str(exe), str(cfg_path), "--log-file", str(logf)], stg["state"], timeout=300)
                rec["launch"] = {"exit_code": cp.returncode, "wall_secs": round(time.perf_counter() - t0, 3),
                                 "started": started, "stdout_tail": cp.stdout.strip()[-1500:],
                                 "stderr_tail": cp.stderr.strip()[-1500:]}
            except subprocess.TimeoutExpired:
                rec["launch"] = {"timeout": True, "started": started}
            time.sleep(0.5)
            rec["launch"]["ended"] = now_iso()
            rec["unfenced_post"] = unfenced(gw, gw_port)
            rec["mxc_log_tail"] = logf.read_text(encoding="utf-8", errors="replace")[-3000:] if logf.exists() else ""
            rec["payload"] = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else None
            if result_path.exists():
                result_path.unlink()
        else:
            rec["launch"] = {"skipped": "dry-run refused the policy"}
            rec["payload"] = None
    finally:
        ins.close()
    with ins.lock:
        rec.update(target_log=list(ins.target_log), proxy_log=list(ins.proxy_log))
    rec["snapshot_after"] = snapshot(watched, stg["state"], programs)
    rec["state_changed_by_run"] = {k: [rec["snapshot_before"][k], rec["snapshot_after"][k]]
                                   for k in rec["snapshot_before"] if rec["snapshot_before"][k] != rec["snapshot_after"][k]}
    rec["verdict"] = summarise.judge_run(rec)
    (out / f"run-{tag}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def dry_run_only(arm: str, gw: str | None, gw_port: int, out: Path, stg: dict[str, Path]) -> Rec:
    fx_name, state = ARM_FIXTURE[arm]
    tag = f"{arm}-{state}-dry-{datetime.now().strftime('%H%M%S')}"
    policy = fixture(fx_name, payload_command(tag, stg["work"] / "unused.json", stg, gw, gw_port),
                     stg["work"], stg["payload"])
    cfg_path = stg["cfg"] / f"{tag}.json"
    cfg_path.write_text(json.dumps(policy, indent=1), encoding="utf-8")
    dry = hidden([str(LAUNCHERS[arm]), str(cfg_path), "--dry-run"], stg["state"])
    rec: Rec = {"arm": arm, "state": state, "fixture": fx_name, "mode": "dry-run-only", "policy_as_submitted": policy,
                "machine": machine_conditions(),
                "dry_run": {"rc": dry.returncode, "stdout": dry.stdout.strip()[-4000:], "stderr": dry.stderr.strip()[-4000:]}}
    (out / f"dryrun-{arm}-{state}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--arms", default="A,B")
    ap.add_argument("--dry-run-only", action="store_true")
    ap.add_argument("--arm-b-commit", default=None, help="source commit of arm B's launcher (required unless its sha256 is a known build)")
    ap.add_argument("--arm-b0-commit", default=None, help="source commit of arm B0's launcher (same rule)")
    ap.add_argument("--launch-sha256", default=None, help="launch.ps1's own sha256 as it computed it")
    args = ap.parse_args(argv)
    arms = [a for a in args.arms.split(",") if a]
    if any(a not in LAUNCHERS for a in arms):
        print(f"REFUSED: unknown arm in {arms}; known: {sorted(LAUNCHERS)}")
        return 2
    out = (args.out or default_out()).resolve()
    summarise.refuse_git_path(out)
    if (out / "batch-header.json").exists():
        print(f"REFUSED: {out} already holds a batch header; each batch needs a fresh output folder")
        return 2
    print(f"elevated: {is_elevated()}", flush=True)
    stg = {k: out / "staging" / k for k in ("cfg", "logs", "payload", "work", "state")}
    for d in (out, *stg.values()):
        d.mkdir(parents=True, exist_ok=True)
    if not CONTAINER_PY.exists():
        print(f"REFUSED: container Python absent at {CONTAINER_PY}")
        return 2
    (stg["payload"] / "net_payload.py").write_bytes((HERE / "net_payload.py").read_bytes())
    programs = [Path(sys.executable), CONTAINER_PY]
    watched = [stg["work"], stg["payload"], TOOLCHAIN, CONTAINER_PY]
    kernel32 = ctypes.windll.kernel32
    kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), BELOW_NORMAL)
    gw = gateway_ip()
    gw_port = pick_gateway_port(gw)
    infos = {a: launcher_info(LAUNCHERS[a]) for a in arms}
    launch_ps1 = HERE / "launch.ps1"
    fw0 = firewall_state(programs)
    head: Rec = {"started": now_iso(), "account": getpass.getuser(), "elevated": is_elevated(),
                 "host_python": sys.version, "harness_sha256": {f: sha256_of(HERE / f) for f in HARNESS_FILES},
                 "launch_ps1_sha256": sha256_of(launch_ps1) if launch_ps1.exists() else None,
                 "launch_ps1_sha256_as_passed_by_launcher": args.launch_sha256,
                 "interpreters": {"host": {"path": sys.executable, "sha256": sha256_of(Path(sys.executable))},
                                  "container": {"path": str(CONTAINER_PY), "sha256": sha256_of(CONTAINER_PY)}},
                 "arm_commits": {},
                 "host_prep": {"run_by_harness": False, "note": "wxc-host-prep is not invoked by this harness"},
                 "firewall_product": fw0.get("product"), "firewall_profiles": fw0.get("profiles"),
                 "gateway": {"ip": gw, "port_selected": gw_port, "candidate_ports": list(GATEWAY_PORTS)},
                 "ports": {"proxy": PROXY_PORT, "target": TARGET_PORT},
                 "launchers": infos, "machine_start": machine_conditions(), "runs_per_arm": args.runs,
                 "dry_run_only": args.dry_run_only, "priority": "BelowNormal", "scope_notes": {}}
    for a, info in infos.items():
        probes = (info.get("probe") or {}).get("probes") or {}
        info["probe_reports_psec_version"] = "psec" in json.dumps(info.get("probe") or {}).lower()
        head["scope_notes"][a] = (
            f"--probe reports baseContainerSupportsIngressHostLoopbackAllow="
            f"{probes.get('baseContainerSupportsIngressHostLoopbackAllow')!r}, {PROXY_FLAG}={probes.get(PROXY_FLAG)!r}; "
            f"this run measures this launcher on this host only")
    (out / "batch-header.json").write_text(json.dumps(head, indent=1), encoding="utf-8")
    runnable: list[str] = []
    for arm in arms:
        info = infos[arm]
        if not info.get("present"):
            reason = f"launcher absent at {info['path']}"
        elif arm in ("B", "B0"):
            ok, reason = check_arm_b_precondition(info.get("probe") or {})
            commit, why = resolve_arm_commit(info.get("sha256"), args.arm_b_commit if arm == "B" else args.arm_b0_commit)
            head["arm_commits"][arm] = {"commit": commit, "basis": why}
            if ok and commit is None:
                ok, reason = False, why
            if ok:
                runnable.append(arm)
                continue
        else:
            runnable.append(arm)
            continue
        (out / f"arm-{arm}-refused.json").write_text(
            json.dumps({"arm": arm, "refused": True, "reason": reason, "launcher": info}, indent=1), encoding="utf-8")
        print(f"arm {arm} REFUSED: {reason}", flush=True)
    (out / "batch-header.json").write_text(json.dumps(head, indent=1), encoding="utf-8")
    if args.dry_run_only:
        for arm in runnable:
            r = dry_run_only(arm, gw, gw_port, out, stg)
            print(json.dumps({"arm": arm, "dry_rc": r["dry_run"]["rc"], "stderr": r["dry_run"]["stderr"][:300]}), flush=True)
        return 0
    try:
        ctl = run_unfenced_control(gw, gw_port, out)
    except OSError as exc:
        print(f"REFUSED: cannot bind the probe listeners/proxy (ports {PROXY_PORT}-{TARGET_PORT}): {exc!r}")
        return 3
    print(json.dumps({"B5_control": ctl["judgement"]}), flush=True)
    summary: Rec = {"groups": {}}
    for arm in runnable:
        for i in range(1, args.runs + 1):
            rec = run_one(arm, i, gw, gw_port, out, stg, watched, programs)
            print(json.dumps({"tag": rec["tag"], "verdict": rec["verdict"]["verdict"],
                              "reasons": rec["verdict"]["reasons"][:3], "dry_rc": rec["dry_run"]["rc"]}), flush=True)
            runs, ctl_rec = summarise.load_dir(out)
            summary = summarise.judge_batch(runs, ctl_rec, args.runs)
            summary["arm_refusals"] = sorted(p.stem for p in out.glob("arm-*-refused.json"))
            (out / "batch-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
            if rec["verdict"]["verdict"] == "FAIL":
                print("STOP: FAIL condition met")
                return 5
            if rec["state_changed_by_run"]:
                print("STOP: changed state; see the record")
                return 4
    head["finished"], head["machine_end"] = now_iso(), machine_conditions()
    (out / "batch-header.json").write_text(json.dumps(head, indent=1), encoding="utf-8")
    print(json.dumps({k: v["verdict"] for k, v in summary["groups"].items()} or {"arms": "none runnable"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
