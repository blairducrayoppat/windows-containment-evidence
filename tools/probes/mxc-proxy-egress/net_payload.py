"""In-container payload for the MXC loopback-proxy egress probe (also imported by the harness for the unfenced controls).

What this measures, from inside the container, in one run:
  B2  three HTTP requests THROUGH the configured proxy to a second loopback listener (instrument control).
  B3  one direct TCP connect to that second loopback listener, not through the proxy.
  B4  one connect-only attempt to a real LAN peer, the default gateway, on a port an unfenced connect reached
      (i), and one connect-only attempt to 1.1.1.1:443 (ii). Neither has a host-side listener.
B2 and B3 requests carry the run tag in their path and in an X-Probe-Marker header, shaped `<tag>-<kind>-<n>`
with kind in b2, b3, b5a. Reach for B2 and B3 is judged from the HOST-SIDE listener logs; this file's JSON
supplies the error codes for B4(i) and B4(ii), which have no host-side listener. A gateway port of 0 means no
port was reachable unfenced: B4(i) is then skipped and recorded as such.

How to run: launched by run_probe.py inside the container:
  python -I net_payload.py --tag T --out result.json --gateway-ip A.B.C.D --gateway-port R --proxy-port P --target-port Q
What it writes: one JSON result file (--out) and a one-line JSON summary on stdout.

NOT MEASURED: any build other than the one(s) run; behaviour on a host whose --probe reports host-loopback
ingress unsupported (the earlier 26200.9457 condition); an identity-scoped proxy
(allowedProxyPeer); the session-isolation backend; UDP, ICMP or DNS egress under the proxy policy;
host-to-container ingress (the doc's own open limitation); nono under MXC; anything about the fork or any
other sandbox. Also not measured here: IPv6, HTTPS or CONNECT through the proxy, other destination ports.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import time
from pathlib import Path

B2_REQUESTS = 3


def _t() -> float:
    return time.perf_counter()


def tcp_probe(host: str, port: int, marker: str | None, timeout: float = 5.0) -> dict[str, object]:
    """Connect; if `marker` is given, send a marked request. `marker=None` is connect-only."""
    t0 = _t()
    rec: dict[str, object] = {"target": f"{host}:{port}", "marker": marker}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            rec["connected"] = True
            if marker is not None:
                s.settimeout(timeout)
                s.sendall(f"GET /{marker} HTTP/1.0\r\nHost: {host}\r\nX-Probe-Marker: {marker}\r\n\r\n".encode())
                try:
                    rec["reply"] = s.recv(512).decode("latin-1", "replace")
                except OSError as exc:
                    rec["reply_error"] = repr(exc)
    except OSError as exc:
        rec.update(connected=False, error=type(exc).__name__, winerror=getattr(exc, "winerror", None),
                   errno=getattr(exc, "errno", None), detail=str(exc)[:120])
    rec["secs"] = round(_t() - t0, 3)
    return rec


def http_via_proxy(proxy_host: str, proxy_port: int, target_host: str, target_port: int, marker: str,
                   timeout: float = 8.0) -> dict[str, object]:
    """One GET sent to the proxy in absolute-form, the way an HTTP client configured with a proxy sends it."""
    t0 = _t()
    rec: dict[str, object] = {"proxy": f"{proxy_host}:{proxy_port}", "target": f"{target_host}:{target_port}",
                              "marker": marker}
    try:
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        conn.request("GET", f"http://{target_host}:{target_port}/{marker}",
                     headers={"Host": f"{target_host}:{target_port}", "X-Probe-Marker": marker})
        resp = conn.getresponse()
        rec.update(status=resp.status, body=resp.read(200).decode("latin-1", "replace"))
        conn.close()
    except OSError as exc:
        rec.update(error=type(exc).__name__, winerror=getattr(exc, "winerror", None), detail=str(exc)[:160])
    rec["secs"] = round(_t() - t0, 3)
    return rec


def run_states(tag: str, gateway_ip: str, gateway_port: int, proxy_port: int, target_port: int) -> dict[str, object]:
    res: dict[str, object] = {"tag": tag}
    res["b2"] = [http_via_proxy("127.0.0.1", proxy_port, "127.0.0.1", target_port, f"{tag}-b2-{i}")
                 for i in range(1, B2_REQUESTS + 1)]
    res["b3"] = tcp_probe("127.0.0.1", target_port, f"{tag}-b3-1")
    res["b4i"] = tcp_probe(gateway_ip, gateway_port, None) if gateway_port else {"skipped": "no gateway port"}
    res["b4ii"] = tcp_probe("1.1.1.1", 443, None)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--gateway-ip", required=True)
    ap.add_argument("--gateway-port", type=int, required=True)
    ap.add_argument("--proxy-port", type=int, required=True)
    ap.add_argument("--target-port", type=int, required=True)
    a = ap.parse_args()
    t0 = _t()
    res = run_states(a.tag, a.gateway_ip, a.gateway_port, a.proxy_port, a.target_port)
    res["env_proxy"] = {k: v for k, v in os.environ.items()
                        if k.lower() in ("http_proxy", "https_proxy", "no_proxy", "all_proxy")}
    res["total_secs"] = round(_t() - t0, 3)
    a.out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({"tag": a.tag, "b2_status": [r.get("status") for r in res["b2"]],  # type: ignore[union-attr]
                      "b3": res["b3"].get("connected"), "b4i": res["b4i"].get("connected"),  # type: ignore[union-attr]
                      "b4ii": res["b4ii"].get("connected")}))  # type: ignore[union-attr]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
