#!/usr/bin/env python3
"""Sanitiser: copy a directory of raw results to a new directory with every machine, person and internal-tracker
identifier replaced by a placeholder. Standard library only; imports nothing from any other repository.

Run:
  python tools/sanitize.py <raw-dir> <out-dir>      out-dir must not exist; it is created
  python tools/sanitize.py <raw-dir> <out-dir> --local <path-to-.leakgate.local.json>

Replacements, applied to every text file in this order:
  1. host      the live host name (any letter case, also inside a longer token) -> HOST
  2. user      the live account name (as a word; digits beside it do not hide it) -> USER
  3. sid       S-1-5-21-<a>-<b>-<c>-<RID> -> S-1-5-21-X-X-X-<RID>. The RID is kept. Distinct domains in one run get
               distinct letters (X, Y, Z, W, ...): the most frequent domain gets X, ties by the first number, so
               records that compare two domains still compare. A truncated domain keeps its letter for each part present.
  3b. sid-binary  the same SID as a hex blob (revision 01, count, authority 000000000005, 15000000, then the domain's
               three 32-bit values and any more): the three domain values are written 00000000, the first 12 bytes and any
               relative id after them are kept.
  3c. inventory  every entry of an `appcontainer_mappings` array except a probe's own `mxcfx-` profile (and the
               `<absent>`/`<unreadable>` markers) is dropped: the array otherwise lists the packages installed on the machine.
               The array keeps its layout; the sibling counts are kept.
  3d. ipv6     each host-interface IPv6 address (see tools/leak_gate.py, rule ipv6-interface) -> ipv6-interface-<n>, one
               number per distinct address in the folder, in order of first appearance.
  3e. ticks    the tick count in a Bitdefender provider name (Bitdefender.<digits>-Provider) -> Bitdefender.TICKS-Provider:
               the count decodes to the product's installation date and time on the machine.
  4. home      <drive>:\\Users\\<name>\\... and /mnt/<drive>/Users/<name>/... -> ~ for the operator's own profile (the
               live account, USER, or the placeholders _OPERATOR_ and __USER__) and ~<name> for any other account
               (a test account's profile stays distinguishable); the profile environment variable -> ~; the
               extended-length prefix in front of a home path is dropped. Users\\Public, Users\\Default and
               Users\\All Users are shared profiles and stay as written, as the gate allows them.
  5. local     each [from, to] pair under "replacements" in the local file (whole word, case-sensitive). This is where
               vocabulary that would itself be a leak if named here is mapped, and where a bare upstream issue number is
               mapped to its owner/repo form. It runs BEFORE the reference rule so that a listed number is rewritten, not removed.
  6. tracker   the value of the tracker field -> "" (a JSON key) or '' (a PowerShell hashtable assignment); every bare
               #NNN to #NNNNN reference not directly after a word character, slash, dot, hash or hyphen (with a following
               "c.NNNN" comment pointer) and bare c.NNNN comment pointers are removed. A bare upstream number that the local
               file does not list is therefore removed too: write owner/repo#N in the source or list it under "replacements".
               The gate cannot see that loss (the citation is simply absent), so the PREFLIGHT item that re-counts every figure
               after sanitising, against the raw count and the marker's tracker count, is what catches a lost citation.
               A 1NNN number inside a name (name-1NNN-rest, 1NNN-name after a path separator, or a lower-case name ending
               -1NNN) is removed; a 2000-plus number inside a name is neither rewritten nor seen by the gate in content (the
               gate refuses it in a path). SNNNN- and SNNNNN- session tokens -> SXXXX-.
  7. fixture   pNNNN-run<n> and pNNNNN-run<n> -> fx-<letter> (run1 -> fx-a, run2 -> fx-b, ...); any other pNNNN- , pNNNNN-,
               pNNNN_ or pNNNNN_ prefix -> fx- / fx_. Letter case follows the original (PNNNN-RUN1 -> FX-A, PNNNN-Run1 ->
               Fx-A), because the case-spelling probes record the spelling they used.
  8. guid      any GUID not listed in tools/allowed_guids.txt -> GUID-<n> (one number per distinct GUID in the run).

A file that is not valid UTF-8 text stops the run (exit 2): nothing is copied that was not read. Line endings, a UTF-8
byte-order mark and every byte outside a match are kept. A marker file named .sanitized is written at the root of
out-dir: per file, per rule, how many replacements were made. It never holds an original value.

The output is not trusted because this ran: run tools/leak_gate.py --tree <out-dir> afterwards. Prose that a rule leaves
awkward (a sentence that named a removed reference) is a hand edit, recorded in PROVENANCE.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leak_gate as lg  # noqa: E402  (the sibling script in this repository)

MARKER_NAME = ".sanitized"
OPERATOR_PLACEHOLDERS = frozenset({"user", "_operator_", "__user__"})
SID_FULL_RE = re.compile(r"S-1-5-21-([0-9]+(?:-[0-9]+)*)(-?)")
SID_BINARY_RE = lg.SID_BINARY_RE
INVENTORY_ARRAY_RE = re.compile(r'("appcontainer_mappings"\s*:\s*)\[(.*?)\]', re.DOTALL)
HOME_WIN_RE = re.compile(r"(?:\\\\+\?\\+)?[A-Za-z]:(\\+|/+)Users\1(?!(?:Public|Default|All Users)(?![A-Za-z0-9_.$-]))([A-Za-z0-9_.$-]+)",
                         re.IGNORECASE)
HOME_WSL_RE = re.compile(r"/mnt/[A-Za-z]/Users/(?!(?:Public|Default)(?![A-Za-z0-9_.$-]))([A-Za-z0-9_.$-]+)", re.IGNORECASE)
TRACKER_FIELD_RE = re.compile(r"(\"" + lg.TRACKER_WORD + r"\"\s*:\s*)(\"[^\"]*\"|-?[0-9]+|null)")
TRACKER_ASSIGN_RE = re.compile(r"(?<![A-Za-z0-9_\"'])(" + lg.TRACKER_WORD + r"\s*=\s*)'[^'\n]*'", re.IGNORECASE)
TRACKER_REF_RE = re.compile(
    r"(?<![\w/.#-])#[0-9]{3,5}(?![0-9])(?:[ \t]+c\.[0-9]+(?:[ \t]+and[ \t]+c\.[0-9]+)?)?"
    r"|(?<![\w.])c\.[0-9]{3,5}\b(?:[ \t]+and[ \t]+c\.[0-9]{3,5}\b)?"
)
# A tracker number inside a name: "-1NNN" between a letter or digit and a separator, or "1NNN-" right after a path
# separator. GUIDs are skipped (their groups can look like this).
# A build-lab stamp (yymmdd-hhmm, as in a Windows build string) is not a tracker number.
TRACKER_NAME_RE = re.compile(
    r"(?<=[A-Za-z0-9])(?<![0-9]{6})[-_]1[0-9]{3}(?=[-_.][A-Za-z0-9])|(?<=[/\\])1[0-9]{3}[-_](?=[A-Za-z0-9])"
    r"|(?<=[a-z])[-_]1[0-9]{3}(?![0-9A-Za-z])"
)
SESSION_RE = re.compile(r"(?<![A-Za-z0-9])S[0-9]{4,5}-")
FIXTURE_RE = re.compile(r"(?<![A-Za-z0-9])p[0-9]{4,5}-run([0-9]+)", re.IGNORECASE)
FIXTURE_PREFIX_RE = re.compile(r"(?<![A-Za-z0-9])p[0-9]{4,5}([-_])", re.IGNORECASE)


def _keep_case(original: str, new: str) -> str:
    """Spell the placeholder in the letter case of what it replaces (the case probes compare spellings)."""
    letters = [c for c in original if c.isalpha()]
    if letters and all(c.isupper() for c in letters):
        return new.upper()
    if original[:1].isupper():
        return "-".join(part[:1].upper() + part[1:] for part in new.split("-"))
    return new
RULES = ("host", "user", "sid", "sid-binary", "inventory", "ipv6", "ticks", "home", "tracker", "fixture", "guid", "local")


class SanitizeError(Exception):
    pass


def _letter(i: int) -> str:
    letters = "XYZWVUTSRQPONMLKJIHGFEDCBA"
    return letters[i] if i < len(letters) else f"D{i}"


class Sanitizer:
    def __init__(self, names: list[str], allowed_guids: frozenset[str], replacements: list[tuple[str, str]],
                 sid_firsts: list[int], guid_order: list[str], ipv6_order: list[str]) -> None:
        host, user = names
        self.host_re = re.compile(re.escape(host), re.IGNORECASE)
        self.user_re = lg._name_re(user)
        self.user = user.lower()
        self.allowed_guids = allowed_guids
        freq = Counter(sid_firsts)
        self.sid_letter = {n: _letter(i) for i, n in enumerate(sorted(freq, key=lambda k: (-freq[k], k)))}
        self.guid_num = {g: i + 1 for i, g in enumerate(guid_order)}
        self.ipv6_num = {a: i + 1 for i, a in enumerate(ipv6_order)}
        self.local = [(re.compile(r"(?<![A-Za-z0-9_])" + re.escape(a) + r"(?![A-Za-z0-9_])"), b) for a, b in replacements]

    @staticmethod
    def _remove_refs(text: str, counts: Counter[str]) -> str:
        """Remove each bare tracker reference. A reference that is the whole content of a parenthesis takes the
        parenthesis (and one space before it) with it; otherwise one adjacent list separator goes with it."""
        out: list[str] = []
        pos = 0
        for m in TRACKER_REF_RE.finditer(text):
            a, b = m.span()
            counts["tracker"] += 1
            before, after = text[pos:a], text[b:]
            open_m, close_m = re.search(r"[ \t]?\([ \t]*$", before), re.match(r"[ \t]*\)", after)
            sep_after, sep_before = re.match(r"[,;][ \t]?", after), re.search(r"[,;][ \t]?$", before)
            if open_m and close_m:
                before = before[:open_m.start()]
                b += close_m.end()
            elif sep_after:
                b += sep_after.end()
            elif sep_before:
                before = before[:sep_before.start()]
            elif before.endswith((" ", "\t")) and after[:1] in (" ", "\t"):
                b += 1
            out.append(before)
            pos = b
        out.append(text[pos:])
        return "".join(out)

    @staticmethod
    def _outside_guids(text: str, rx: re.Pattern[str], repl: str, rule: str, counts: Counter[str]) -> str:
        spans = [m.span() for m in lg.GUID_RE.finditer(text)]

        def f(m: re.Match[str]) -> str:
            if any(a <= m.start() < b for a, b in spans):
                return m.group()
            counts[rule] += 1
            return repl

        return rx.sub(f, text)

    @staticmethod
    def _blob_pair(m: re.Match[str], counts: Counter[str]) -> str:
        """A data blob that holds a domain SID is rewritten and its text rendering recomputed from the new bytes."""
        blob, n = SID_BINARY_RE.subn(lambda x: x.group()[:24] + "00000000" * 3 + x.group()[48:], m.group(1))
        if not n:
            return m.group()
        counts["sid-binary"] += n
        return f"<data>{blob}</data>{m.group(2)}<asString>{lg.render_as_string(blob)}</asString>"

    def _ipv6(self, m: re.Match[str], counts: Counter[str]) -> str:
        addr = lg.ipv6_interface_address(m.group())
        if addr is None:
            return m.group()
        counts["ipv6"] += 1
        return f"ipv6-interface-{self.ipv6_num[addr]}"

    @staticmethod
    def drop_inventory(text: str, counts: Counter[str] | None = None) -> str:
        """Remove the installed-package entries from every `appcontainer_mappings` array, keeping its layout."""
        def one(m: re.Match[str]) -> str:
            body = m.group(2)
            try:
                items = json.loads("[" + body + "]")
            except ValueError:
                raise SanitizeError("an appcontainer_mappings array that is not JSON: nothing is written for it")
            kept = [x for x in items if not (isinstance(x, str) and lg.INVENTORY_ENTRY_RE.match(x))]
            if len(kept) == len(items):
                return m.group()
            if counts is not None:
                counts["inventory"] += len(items) - len(kept)
            if not kept:
                return m.group(1) + "[]"
            if "\n" not in body:
                return m.group(1) + "[" + ", ".join(json.dumps(x) for x in kept) + "]"
            lines = body.split("\n")
            indent = re.match(r"[ \t]*", lines[1]).group()
            closing = re.match(r"[ \t]*", lines[-1]).group()
            return m.group(1) + "[\n" + ",\n".join(indent + json.dumps(x) for x in kept) + "\n" + closing + "]"

        return INVENTORY_ARRAY_RE.sub(one, text)

    def _home_name(self, name: str) -> str:
        return "~" if name.lower() in OPERATOR_PLACEHOLDERS or name.lower() == self.user else "~" + name

    def apply(self, text: str, counts: Counter[str]) -> str:
        def sub(rule: str, rx: re.Pattern[str], repl, s: str) -> str:
            out, n = rx.subn(repl, s)
            counts[rule] += n
            return out

        text = self.drop_inventory(text, counts)
        text = sub("host", self.host_re, "HOST", text)
        text = sub("user", self.user_re, "USER", text)

        def sid(m: re.Match[str]) -> str:
            parts = m.group(1).split("-")
            letter = self.sid_letter[int(parts[0])]
            domain, rid = (parts[:3], parts[3:]) if len(parts) >= 4 else (parts, [])
            return "S-1-5-21-" + "-".join([letter] * len(domain) + rid) + m.group(2)

        text = sub("sid", SID_FULL_RE, sid, text)
        text = lg.ASSTRING_PAIR_RE.sub(lambda m: self._blob_pair(m, counts), text)
        text = sub("sid-binary", SID_BINARY_RE, lambda m: m.group()[:24] + "00000000" * 3 + m.group()[48:], text)
        text = sub("ticks", lg.TICKS_PROVIDER_RE, "TICKS", text)
        text = lg.IPV6_CANDIDATE_RE.sub(lambda m: self._ipv6(m, counts), text)
        text = sub("home", HOME_WIN_RE, lambda m: self._home_name(m.group(2)), text)
        text = sub("home", HOME_WSL_RE, lambda m: self._home_name(m.group(1)), text)
        text = sub("home", re.compile(re.escape(lg.HOME_ENV), re.IGNORECASE), "~", text)
        for rx, b in self.local:  # before the reference rule: a listed bare upstream number becomes owner/repo form first
            text = sub("local", rx, b, text)
        text = sub("tracker", TRACKER_FIELD_RE, lambda m: m.group(1) + "\"\"", text)
        text = sub("tracker", TRACKER_ASSIGN_RE, lambda m: m.group(1) + "''", text)
        text = self._remove_refs(text, counts)
        text = self._outside_guids(text, TRACKER_NAME_RE, "", "tracker", counts)
        text = sub("tracker", SESSION_RE, "SXXXX-", text)
        text = sub("fixture", FIXTURE_RE,
                   lambda m: _keep_case(m.group(), "fx-" + chr(ord("a") + int(m.group(1)) - 1)), text)
        text = sub("fixture", FIXTURE_PREFIX_RE, lambda m: _keep_case(m.group()[:1], "fx") + m.group(1), text)

        def guid(m: re.Match[str]) -> str:
            g = m.group().lower()
            if g in self.allowed_guids:
                return m.group()
            counts["guid"] += 1
            return f"GUID-{self.guid_num[g]:04d}"

        text = lg.GUID_RE.sub(guid, text)
        return text


def _read_text(path: Path) -> tuple[str, bool]:
    data = path.read_bytes()
    bom = data.startswith(b"\xef\xbb\xbf")
    try:
        return data[3 if bom else 0:].decode("utf-8"), bom
    except UnicodeDecodeError as exc:
        raise SanitizeError(f"not UTF-8 text, nothing written for it: {path} ({exc})") from exc


def sanitize_tree(src: Path, dst: Path, allowed_guids: frozenset[str], names: list[str],
                  replacements: list[tuple[str, str]] | None = None) -> dict[str, dict[str, int]]:
    if dst.exists():
        raise SanitizeError(f"output directory already exists: {dst}")
    files = sorted(p for p in src.rglob("*") if p.is_file())
    texts = {p: _read_text(p) for p in files}
    scan = [Sanitizer.drop_inventory(t) for t, _ in texts.values()]  # what is dropped claims no number below
    sid_firsts = [int(m.group(1).split("-")[0]) for t, _ in texts.values() for m in SID_FULL_RE.finditer(t)]
    guid_order: list[str] = []
    for t in scan:
        for m in lg.GUID_RE.finditer(t):
            g = m.group().lower()
            if g not in allowed_guids and g not in guid_order:
                guid_order.append(g)
    ipv6_order: list[str] = []
    for t in scan:
        for m in lg.IPV6_CANDIDATE_RE.finditer(t):
            a = lg.ipv6_interface_address(m.group())
            if a and a not in ipv6_order:
                ipv6_order.append(a)
    s = Sanitizer(names, allowed_guids, replacements or [], sid_firsts, guid_order, ipv6_order)
    report: dict[str, dict[str, int]] = {}
    for p in files:
        text, bom = texts[p]
        counts: Counter[str] = Counter()
        out = s.apply(text, counts)
        rel = p.relative_to(src)
        rel_out = Path(s.apply(rel.as_posix(), Counter()))
        target = dst / rel_out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((b"\xef\xbb\xbf" if bom else b"") + out.encode("utf-8"))
        report[rel_out.as_posix()] = {r: counts[r] for r in RULES if counts[r]}
    totals = Counter()
    for c in report.values():
        totals.update(c)
    marker = {
        "what": "replacement counts per file and rule, written by tools/sanitize.py; original values are not recorded",
        "rules_in_order": list(RULES),
        "totals": {r: totals[r] for r in RULES if totals[r]},
        "files": report,
    }
    dst.mkdir(parents=True, exist_ok=True)
    (dst / MARKER_NAME).write_text(json.dumps(marker, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Copy raw results to a new directory with identifiers replaced.")
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ap.add_argument("--local", type=Path, default=lg.ROOT / lg.LOCAL_FILE_NAME)
    args = ap.parse_args(argv)
    try:
        lg.load_local(args.local)  # the same precondition as the gate: no local file, no run
        data = json.loads(args.local.read_text(encoding="utf-8"))
        pairs = data.get("replacements", [])
        if not isinstance(pairs, list) or not all(isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) for x in p) for p in pairs):
            raise SanitizeError("'replacements' in the local file must be a list of [from, to] pairs")
        report = sanitize_tree(args.src, args.dst, lg.load_allowed_guids(), lg.live_names(), [tuple(p) for p in pairs])
    except (lg.GateCannotRun, SanitizeError) as exc:
        print(f"sanitize: CANNOT RUN: {exc}", file=sys.stderr)
        return 2
    totals = Counter()
    for c in report.values():
        totals.update(c)
    print(f"sanitize: {len(report)} file(s) written to {args.dst}; replacements: {dict(totals)}")
    print("next: python tools/leak_gate.py --tree " + str(args.dst))
    return 0


if __name__ == "__main__":
    sys.exit(main())
