"""Non-elevated measurement: can the TCP table attribute the client socket of a loopback connection at accept time? (a) a user-mode connect;
(b) the SMB redirector (net use \\\\127.0.0.1\\x /TCPPORT:<port> /TRANSPORT:TCP) from this unfenced account to a log-only acceptor."""
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
from ctypes import wintypes

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5


class ROW(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("laddr", wintypes.DWORD), ("lport", wintypes.DWORD), ("raddr", wintypes.DWORD), ("rport", wintypes.DWORD), ("pid", wintypes.DWORD)]


def table() -> list[dict]:
    iphlp = ctypes.windll.iphlpapi
    size = wintypes.DWORD(0)
    iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    buf = ctypes.create_string_buffer(size.value + 4096)
    size = wintypes.DWORD(len(buf))
    rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != 0:
        raise OSError(rc)
    n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(ctypes.addressof(buf) + 4, ctypes.POINTER(ROW * n)).contents
    out = []
    for r in rows:
        out.append({"state": r.state, "laddr": socket.inet_ntoa(r.laddr.to_bytes(4, "little")), "lport": socket.ntohs(r.lport & 0xFFFF),
                    "raddr": socket.inet_ntoa(r.raddr.to_bytes(4, "little")), "rport": socket.ntohs(r.rport & 0xFFFF), "pid": r.pid})
    return out


def pname(pid: int) -> str:
    if pid == 4:
        return "System"
    k = ctypes.windll.kernel32
    h = k.OpenProcess(0x1000, False, pid)
    if not h:
        return f"unreadable (OpenProcess error {k.GetLastError()})"
    try:
        b = ctypes.create_unicode_buffer(1024)
        n = wintypes.DWORD(1024)
        return b.value if k.QueryFullProcessImageNameW(h, 0, b, ctypes.byref(n)) else f"unreadable (error {k.GetLastError()})"
    finally:
        k.CloseHandle(h)


found: list[dict] = []


def serve(port: int, label: str) -> socket.socket:
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen(8)

    def loop() -> None:
        while True:
            try:
                c, peer = srv.accept()
            except OSError:
                return
            rows = [r for r in table() if r["laddr"] == peer[0] and r["lport"] == peer[1] and r["rport"] == port]
            found.append({"label": label, "peer": f"{peer[0]}:{peer[1]}", "rows": rows, "owners": [(r["pid"], pname(r["pid"])) for r in rows]})
            try:
                c.settimeout(3)
                c.recv(4096)
            except OSError:
                pass
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv


print("me", os.getpid())
s1 = serve(61795, "user-connect")
c = socket.create_connection(("127.0.0.1", 61795))
time.sleep(1.0)
c.close()
s2 = serve(61796, "smb-redirector")
net = os.path.join(os.environ["SystemRoot"], "System32", "net.exe")
r = subprocess.run([net, "use", r"\\127.0.0.1\x", "/TCPPORT:61796", "/TRANSPORT:TCP"], capture_output=True, text=True, timeout=60)
print("net use exit", r.returncode, (r.stdout + r.stderr).strip()[:200])
subprocess.run([net, "use", r"\\127.0.0.1\x", "/delete", "/y"], capture_output=True, text=True, timeout=60)
time.sleep(1.0)
for f in found:
    print(json.dumps(f))
s1.close()
s2.close()
