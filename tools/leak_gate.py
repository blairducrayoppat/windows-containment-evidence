#!/usr/bin/env python3
"""Leak gate: refuse any file (or commit message) that carries something identifying a machine, a person or an
internal tracker. Standard library only; imports nothing from any other repository.

Run:
  python tools/leak_gate.py --staged                 files staged for commit, read from the index (the pre-commit hook)
  python tools/leak_gate.py --tree <dir>             every file under a directory (review, and the outside scan)
  python tools/leak_gate.py --tracked                every tracked file in this clone
  python tools/leak_gate.py --message <file>         a commit message (the commit-msg hook)
  python tools/leak_gate.py --self-test              each sanitisable pattern fails before tools/sanitize.py, passes after

Exit 0: no hit. Exit 1: at least one hit (each printed as path, line, rule; the matched text is never printed).
Exit 2: the gate cannot run (a precondition is missing, or a tree or index scan finds no file). It never passes a file
it could not check.

What it refuses:
  identity     the host name and the account name of the machine the gate runs on, read live at run time
               (COMPUTERNAME/USERNAME, else the platform host name and login name), and any extra names listed under
               "identities" in the local file. Neither this file nor anything else in the repository holds them. A
               name of five or more characters is matched anywhere, also glued to other letters; a shorter one only
               where no letter touches it.
  sid          a domain, machine or Entra ID SID (S-1-5-21- or S-1-12-1- followed by a digit, any letter case).
               Well-known SIDs such as S-1-5-18 are allowed.
  email        an e-mail address, except a code-host no-reply address without a numeric account prefix, a
               documentation domain (example.com/.org/.net) and noreply@ senders.
  mac-address  six hex pairs joined by colons or hyphens.
  public-ip    an IPv4 address outside the private, loopback, link-local and multicast ranges, other than the two
               measurement targets the records name (IPV4_OK).
  volume-serial  the header line that introduces a volume's serial in dir output (pattern: VOLUME_SERIAL_RE).
  home-path    <drive>:\\Users\\<name> (any number of backslashes, or slashes), /mnt/<drive>/Users/<name>, the
               profile environment variable (HOME_ENV below), and the extended-length prefix in front of a home path.
               Users\\Public and Users\\Default are allowed.
  guid         any GUID (8-4-4-4-12 hex, braces optional) not listed in tools/allowed_guids.txt.
  tracker      an internal tracker reference: #NNN or #NNNN unless written as owner/repo#N, a comment pointer
               (c.NNNN, or "comment NNNN"), any number listed under "tracker_numbers" in the local file wherever no
               digit touches it (outside a GUID), a fixture prefix
               p1NNN-, a session token S1NNN-, a 1NNN number between separators inside a name (a file name that
               carries a tracker number), and the tracker-field word spelled in TRACKER_WORD below (the blanked
               field is allowed: that word as a JSON key with the value "", or assigned '' in PowerShell).
  phrase       every phrase listed under "phrases" in the local file (case-insensitive; runs of whitespace match any
               whitespace). A match that lies wholly inside a form listed under "allowed_contexts" is allowed.
  word         every word listed under "words_cs" in the local file, matched case-sensitively as a whole word.
  path         a path that carries any of the above, a 4-digit 1NNN token, or a word listed under "path_words".

The local file (.leakgate.local.json at the repository root, never committed: .gitignore lists it) holds what would
itself be a leak if this public file named it. The gate refuses to run without it (exit 2). Shape:
  {"identities": [], "phrases": [], "allowed_contexts": [], "path_words": [], "words_cs": [], "tracker_numbers": []}
An empty list is a deliberate choice; a missing file is not.

HONEST LIMIT: text only (UTF-8, UTF-16 with a byte-order mark, else Latin-1, plus a copy with NULs removed). Not seen:
a name split by punctuation, a line break or a zero-width character; base64, hex, or any compressed form; a name in
another script; a SID or path whose digits or letters are escaped; a private tracker number written bare in prose
unless it is listed under "tracker_numbers"; an IPv6 address; a real name that is not one of the listed identities. A binary file (a NUL byte in the first 8 KiB that
is not UTF-16) is refused unless its extension is listed in BINARY_OK, which is empty.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL_FILE_NAME = ".leakgate.local.json"
LOCAL_KEYS = ("identities", "phrases", "allowed_contexts", "path_words", "words_cs", "tracker_numbers")
ALLOWED_GUIDS_FILE = ROOT / "tools" / "allowed_guids.txt"
BINARY_OK: frozenset[str] = frozenset()
MIN_NAME_LEN = 3
# Spelled in parts so that this file passes its own gate.
TRACKER_WORD = "tick" "et"
HOME_ENV = "%USER" "PROFILE%"

SID_RE = re.compile(r"S-1-5-21-[0-9]|S-1-12-1-[0-9]", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Addresses that name no person: the code host's no-reply form without a numeric account prefix, documentation
# domains, and noreply@ senders.
EMAIL_OK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*@users\.noreply\.github\.com$|@example\.(?:com|org|net)$|^noreply@",
                         re.IGNORECASE)
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(r"(?<![0-9.])(" + _OCTET + r"(?:\." + _OCTET + r"){3})(?![0-9.])")
# Public addresses that are measurement targets named in the records, not the operator's own.
IPV4_OK = frozenset({"1.1.1.1", "8.8.8.8"})
# Dotted version numbers that have the shape of an address: the WSL and WSL-kernel versions the 9P records hold. An
# address-shaped token directly followed by "-" or a letter (a version with a suffix) is not treated as an address.
NOT_ADDRESSES = frozenset({"3.0.3.0", "6.18.54.1", "6.18.40.1"})
VOLUME_SERIAL_RE = re.compile(r"volume\s+serial\s+number", re.IGNORECASE)
HOME_RE = re.compile(
    r"[A-Za-z]:(?:\\+|/+)Users(?:\\+|/+)(?!(?:Public|Default|All Users)\b)[A-Za-z0-9_.$-]"
    r"|/mnt/[A-Za-z]/Users/(?!(?:Public|Default)\b)[A-Za-z0-9_.$-]"
    r"|" + HOME_ENV +
    r"|\\\\+\?\\+[A-Za-z]:\\+Users",
    re.IGNORECASE,
)
GUID_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
TRACKER_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tracker-ref", re.compile(r"(?<![#&])#[0-9]{3,4}\b")),
    ("tracker-comment", re.compile(r"(?<![\w.])c\.[0-9]{3,5}\b|(?<![A-Za-z])comments?\s+(?:c\.)?[0-9]{3,5}\b",
                                   re.IGNORECASE)),
    ("fixture-prefix", re.compile(r"(?<![A-Za-z0-9])p1[0-9]{3}[-_]", re.IGNORECASE)),
    ("session-token", re.compile(r"(?<![A-Za-z0-9])S1[0-9]{3}-")),
    ("tracker-word", re.compile(r"(?<![A-Za-z])" + TRACKER_WORD + r"(?![A-Za-z])", re.IGNORECASE)),
    ("tracker-in-name", re.compile(
        r"(?<=[A-Za-z0-9][-_])(?<![0-9]{6}[-_])1[0-9]{3}(?=[-_.][A-Za-z0-9])|(?<=[/\\])1[0-9]{3}(?=[-_])"
        r"|(?<=[a-z][-_])1[0-9]{3}(?![0-9A-Za-z])")),
)
BLANK_TRACKER_FIELD_RE = re.compile(r"\"" + TRACKER_WORD + r"\"\s*:\s*\"\"|" + TRACKER_WORD + r"\s*=\s*''", re.IGNORECASE)
PATH_NUMBER_RE = re.compile(r"(?<![0-9])1[0-9]{3}(?![0-9])")


class GateCannotRun(Exception):
    """A precondition is missing; the gate exits 2 rather than pass anything unchecked."""


def live_names() -> list[str]:
    """The host name and the account name of the machine running the gate. Refuses if either cannot be read."""
    host = os.environ.get("COMPUTERNAME") or platform.node().split(".")[0]
    try:
        user = os.environ.get("USERNAME") or getpass.getuser()
    except Exception as exc:  # getpass raises when no login name can be found
        raise GateCannotRun(f"cannot read the account name: {exc}") from exc
    if not host or not user:
        raise GateCannotRun("cannot read both the host name and the account name of this machine")
    for n in (host, user):
        if len(n) < MIN_NAME_LEN:
            raise GateCannotRun(f"a live name is shorter than {MIN_NAME_LEN} characters; list it under identities instead")
    return [host, user]


def load_local(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        raise GateCannotRun(f"{LOCAL_FILE_NAME} not found at {path.parent}; create it (empty lists are allowed)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateCannotRun(f"{LOCAL_FILE_NAME} cannot be read: {exc}") from exc
    out: dict[str, list[str]] = {}
    for key in LOCAL_KEYS:
        val = data.get(key)
        if not isinstance(val, list) or not all(isinstance(v, str) and v.strip() for v in val):
            raise GateCannotRun(f"{LOCAL_FILE_NAME}: '{key}' must be a list of non-empty strings")
        out[key] = val
    return out


def load_allowed_guids(path: Path = ALLOWED_GUIDS_FILE) -> frozenset[str]:
    """One GUID per line, then its reason; '#' starts a comment. A malformed line stops the gate."""
    if not path.is_file():
        raise GateCannotRun(f"{path} not found")
    allowed = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(None, 1)
        guid = fields[0].lower()
        if not GUID_RE.fullmatch(guid) or len(fields) < 2:
            raise GateCannotRun(f"{path}: each line is a GUID and a reason: {line!r}")
        allowed.add(guid)
    return frozenset(allowed)


def _phrase_re(phrase: str) -> re.Pattern[str]:
    return re.compile(r"\s+".join(re.escape(p) for p in phrase.split()), re.IGNORECASE)


UPSTREAM_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SUBSTRING_NAME_LEN = 5


def _name_re(name: str) -> re.Pattern[str]:
    """A name of SUBSTRING_NAME_LEN or more characters is matched anywhere, glued to letters or not. A shorter name is
    matched only where no letter touches it, because it occurs inside ordinary words; digits never hide it."""
    if len(name) >= SUBSTRING_NAME_LEN:
        return re.compile(re.escape(name), re.IGNORECASE)
    return re.compile(r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])", re.IGNORECASE)


class Gate:
    def __init__(self, local: dict[str, list[str]], allowed_guids: frozenset[str], names: list[str]) -> None:
        self.identity_res = [_name_re(n) for n in names + local["identities"]]
        self.phrase_res = [_phrase_re(p) for p in local["phrases"]]
        self.allowed_context_res = [_phrase_re(c) for c in local["allowed_contexts"]]
        self.path_words = [w.lower() for w in local["path_words"]]
        self.word_res = [re.compile(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])") for w in local["words_cs"]]
        self.allowed_guids = allowed_guids
        nums = local["tracker_numbers"]
        if not all(n.isdigit() for n in nums):
            raise GateCannotRun(f"{LOCAL_FILE_NAME}: 'tracker_numbers' must hold digits only")
        self.tracker_number_re = (
            # Not inside a decimal fraction or a timestamp (".771"), a hex string or a longer number.
            re.compile(r"(?<![0-9A-Za-z.])(?:" + "|".join(sorted(nums, key=len, reverse=True)) + r")(?![0-9A-Za-z])")
            if nums else None
        )

    @staticmethod
    def views(data: bytes) -> list[str]:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", errors="replace")
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin-1")
        views = [text]
        if "\x00" in text:
            views.append(text.replace("\x00", ""))
        return views

    def scan_text(self, text: str) -> list[tuple[int, str]]:
        hits: list[tuple[int, str]] = []

        def add(pos: int, rule: str) -> None:
            hits.append((text.count("\n", 0, pos) + 1, rule))

        for rx in self.identity_res:
            for m in rx.finditer(text):
                add(m.start(), "identity")
        for m in SID_RE.finditer(text):
            add(m.start(), "sid")
        for m in EMAIL_RE.finditer(text):
            if not EMAIL_OK_RE.search(m.group()):
                add(m.start(), "email")
        for m in MAC_RE.finditer(text):
            add(m.start(), "mac-address")
        for m in IPV4_RE.finditer(text):
            a, b = (int(x) for x in m.group(1).split(".")[:2])
            local_range = (a in (0, 10, 127) or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31)
                           or (a == 192 and b == 168) or a >= 224)
            suffixed = re.match(r"[-A-Za-z]", text[m.end():m.end() + 1])
            if not local_range and not suffixed and m.group(1) not in IPV4_OK | NOT_ADDRESSES:
                add(m.start(), "public-ip")
        for m in VOLUME_SERIAL_RE.finditer(text):
            add(m.start(), "volume-serial")
        for m in HOME_RE.finditer(text):
            add(m.start(), "home-path")
        for m in GUID_RE.finditer(text):
            if m.group().lower() not in self.allowed_guids:
                add(m.start(), "guid")
        blanks = [m.span() for m in BLANK_TRACKER_FIELD_RE.finditer(text)]
        guid_spans = [m.span() for m in GUID_RE.finditer(text)]
        for rule, rx in TRACKER_RES:
            for m in rx.finditer(text):
                if rule == "tracker-word" and any(a <= m.start() < b for a, b in blanks):
                    continue
                if rule == "tracker-in-name" and any(a <= m.start() < b for a, b in guid_spans):
                    continue
                if rule == "tracker-ref" and UPSTREAM_PREFIX_RE.search(text[max(0, m.start() - 200):m.start()]):
                    continue
                add(m.start(), rule)
        if self.tracker_number_re:
            for m in self.tracker_number_re.finditer(text):
                upstream = text[m.start() - 1:m.start()] == "#" and UPSTREAM_PREFIX_RE.search(
                    text[max(0, m.start() - 201):m.start() - 1])
                if not upstream and not any(a <= m.start() < b for a, b in guid_spans):
                    add(m.start(), "tracker-number")
        allowed_spans = [m.span() for rx in self.allowed_context_res for m in rx.finditer(text)]
        for rx in self.phrase_res:
            for m in rx.finditer(text):
                if any(a <= m.start() and m.end() <= b for a, b in allowed_spans):
                    continue
                add(m.start(), "phrase")
        for rx in self.word_res:
            for m in rx.finditer(text):
                add(m.start(), "word")
        return hits

    def scan_bytes(self, data: bytes, rel: str) -> list[tuple[int, str]]:
        head = data[:8192]
        if b"\x00" in head and head[:2] not in (b"\xff\xfe", b"\xfe\xff") and Path(rel).suffix.lower() not in BINARY_OK:
            return [(0, "binary")]
        seen: set[tuple[int, str]] = set()
        for view in self.views(data):
            seen.update(self.scan_text(view))
        return sorted(seen)

    def scan_path(self, rel: str) -> list[tuple[int, str]]:
        hits = [(0, f"path:{rule}") for _, rule in self.scan_text(rel)]
        if PATH_NUMBER_RE.search(rel):
            hits.append((0, "path:tracker-number"))
        low = rel.lower()
        hits.extend((0, "path:word") for w in self.path_words if w in low)
        return hits


def _git(*args: str, cwd: Path) -> bytes:
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if res.returncode != 0:
        raise GateCannotRun(f"git {' '.join(args)} failed: {res.stderr.decode(errors='replace').strip()}")
    return res.stdout


def iter_staged(root: Path) -> list[tuple[str, bytes]]:
    names = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", cwd=root).split(b"\x00")
    return [(n.decode(), _git("show", f":{n.decode()}", cwd=root)) for n in names if n]


def iter_tracked(root: Path) -> list[tuple[str, bytes]]:
    names = _git("ls-files", "-z", cwd=root).split(b"\x00")
    return [(n.decode(), (root / n.decode()).read_bytes()) for n in names if n]


def iter_tree(base: Path) -> list[tuple[str, bytes]]:
    if not base.is_dir():
        raise GateCannotRun(f"not a directory: {base}")
    out = []
    for p in sorted(base.rglob("*")):
        rel = p.relative_to(base)
        if p.is_file() and ".git" not in rel.parts and p.name != LOCAL_FILE_NAME:
            out.append((rel.as_posix(), p.read_bytes()))
    return out


def run(gate: Gate, items: list[tuple[str, bytes]], check_paths: bool = True) -> int:
    total = 0
    for rel, data in items:
        hits = (gate.scan_path(rel) if check_paths else []) + gate.scan_bytes(data, rel)
        for line, rule in hits:
            print(f"HIT {rel}:{line} {rule}")
        total += len(hits)
    print(f"leak_gate: {len(items)} file(s) checked, {total} hit(s)")
    return 1 if total else 0


def run_nonempty(gate: Gate, items: list[tuple[str, bytes]]) -> int:
    """A tree or index scan that finds no file cannot report clean: a mis-pointed scan must not read as a pass."""
    if not items:
        raise GateCannotRun("no file to check (an empty or mis-pointed scan is not a clean one)")
    return run(gate, items)


def self_test(gate: Gate) -> int:
    """Each sanitisable pattern must fail the gate before tools/sanitize.py and pass after. Samples are built from
    parts so that this file never carries a hit itself."""
    sys.path.insert(0, str(ROOT / "tools"))
    import sanitize  # noqa: E402  (the sibling script in this repository)

    host, user = live_names()
    samples = {
        "identity-host": f"ran on {host} today",
        "identity-user": f"owner {user} wrote this",
        "sid": "account " + "S-1-5-" + "21-111-222-333-1001",
        "home-path": "C:" + "\\Users\\" + user + "\\work",
        "home-path-json": "\"C:" + "\\\\Users\\\\" + user + "\\\\work\"",
        "home-path-other-account": "C:" + "\\Users\\" + "svc-probe\\AppData",
        "home-path-wsl": "/mnt/c/" + "Users/" + user + "/x",
        "home-path-env": HOME_ENV + "\\x",
        "guid": "key " + "0badc0de-abcd" + "-2222-3333-444455556666",
        "tracker-ref": "fixed in " + "#" + "1234 today",
        "tracker-comment": "see c" + ".9876, then go",
        "fixture": "C:\\wsl\\" + "p" + "1234-run1\\leaf",
        "fixture-upper": "/mnt/c/WSL/" + "P" + "1234-RUN1/LEAF and " + "P" + "1234_MARKER.TXT",
        "name-suffix": "task blarai-probe-" + "1234 /delete",
        "tracker-field": "{\"" + TRACKER_WORD + "\": \"1234\"}",
        "session-token": "tail " + "S" + "1234-main-abc",
        "tracker-in-name": "schema 'probe-" + "1234-proof-v1' on build 26100.1.ge_release.240331-" + "1435",
        "tracker-in-paren": "fixed (" + "#" + "1234) and kept f() and @() and x.y()",
    }
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "src", Path(tmp) / "dst"
        src.mkdir()
        for name, text in samples.items():
            (src / f"{name}.txt").write_text(text, encoding="utf-8")
        before = {n: gate.scan_bytes((src / f"{n}.txt").read_bytes(), n) for n in samples}
        sanitize.sanitize_tree(src, dst, gate.allowed_guids, names=[host, user])
        after = {n: gate.scan_bytes((dst / f"{n}.txt").read_bytes(), n) for n in samples}
        for n in samples:
            ok = bool(before[n]) and not after[n]
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'} {n}: before={len(before[n])} hit(s), after={len(after[n])} hit(s)")
        build = (dst / "tracker-in-name.txt").read_text(encoding="utf-8")
        ok = build.endswith("240331-" + "1435") and "probe-proof-v1" in build
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} build-lab stamp survives, name number removed")
        upper = (dst / "fixture-upper.txt").read_text(encoding="utf-8")
        ok = upper == "/mnt/c/WSL/FX-A/LEAF and FX_MARKER.TXT"
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} fixture spelling keeps its letter case: {upper!r}")
        kept = (dst / "tracker-in-paren.txt").read_text(encoding="utf-8")
        ok = kept == "fixed and kept f() and @() and x.y()"
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} code parentheses survive: {kept!r}")
        marker = dst / sanitize.MARKER_NAME
        ok = marker.is_file() and host.lower() not in marker.read_text(encoding="utf-8").lower()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} marker written, counts only")
    # Classes the gate refuses and the sanitiser leaves to a person: each must hit.
    refuse = {
        "word-glued reference": "see word" + "#" + "4321 there",
        "comment pointer in words": "listed in com" + "ment 9876 today",
        "host glued to letters": "x" + host + "y",
        "lower-case SID": "s-1-5-" + "21-11-22-33-1001",
        "Entra SID": "S-1-12-" + "1-11-22-33-44",
        "e-mail with a name": "From: A Person <a.person" + "@example-mail.net>",
        "numeric no-reply e-mail": "12345+some" + "one@users" + ".noreply.github.com",
        "MAC address": "nic 00-1A-2B" + "-3C-4D-5E",
        "public IPv4": "from 203.0." + "113.77 today",
        "volume serial header": "Volume Serial " + "Number is 0000-0000",
    }
    for name, text in refuse.items():
        ok = bool(gate.scan_text(text))
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} refused: {name}")
    keep = {"upstream reference": "owner/repo" + "#" + "4321", "timestamp": "10:48:32.4321" + "-04:00",
            "version with suffix": "6.18.54.1" + "-microsoft", "loopback": "127.0." + "0.1:8000",
            "measurement target": "1.1." + "1.1:443"}
    loose_numbers = Gate({**{k: [] for k in LOCAL_KEYS}, "tracker_numbers": ["4321"]}, gate.allowed_guids, [host, user])
    for name, text in keep.items():
        ok = not loose_numbers.scan_text(text)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} allowed: {name}")
    ok = bool(loose_numbers.scan_text("review-" + "4321" + "-notes.md"))
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} refused: listed tracker number inside a name")
    with tempfile.TemporaryDirectory() as tmp:
        try:
            run_nonempty(gate, iter_tree(Path(tmp)))
            ok = False
        except GateCannotRun:
            ok = True
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} an empty tree scan cannot pass")
    # Toggle: with the allowlist emptied, an allowed GUID must hit; with it loaded, it must not.
    some = next(iter(gate.allowed_guids), None)
    if some:
        empty = {k: [] for k in LOCAL_KEYS}
        loose = Gate(empty, frozenset(), [host, user])
        ok = bool(loose.scan_text(some)) and not gate.scan_text(some)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} guid allowlist toggle")
    ok = not gate.scan_text("{\"" + TRACKER_WORD + "\": \"\"}")
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} blanked tracker field is allowed")
    ok = bool(gate.scan_text("x/" + "owner/repo" + "#12" + "34")) is False and bool(gate.scan_text("see " + "#12" + "34"))
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} owner/repo#N is allowed, a bare #N is not")
    # Not sanitisable by design: phrases and words from the local file fail and stay failing.
    print(f"NOTE local lists loaded: {len(gate.phrase_res)} phrase(s), {len(gate.word_res)} word(s), "
          f"{len(gate.identity_res) - 2} extra identit(ies), {len(gate.path_words)} path word(s)")
    print(f"self-test: {failures} failure(s)")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Refuse files that identify a machine, a person or an internal tracker.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--staged", action="store_true")
    g.add_argument("--tracked", action="store_true")
    g.add_argument("--tree", type=Path)
    g.add_argument("--message", type=Path)
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--local", type=Path, default=ROOT / LOCAL_FILE_NAME, help="the local file (default: repository root)")
    args = ap.parse_args(argv)
    try:
        gate = Gate(load_local(args.local), load_allowed_guids(), live_names())
        if args.self_test:
            return self_test(gate)
        if args.staged:
            return run(gate, iter_staged(ROOT))
        if args.tracked:
            return run_nonempty(gate, iter_tracked(ROOT))
        if args.tree:
            return run_nonempty(gate, iter_tree(args.tree))
        return run(gate, [("COMMIT_MESSAGE", args.message.read_bytes())], check_paths=False)
    except GateCannotRun as exc:
        print(f"leak_gate: CANNOT RUN: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
