#!/usr/bin/env python3
"""Recount every figure the README of this folder states, from the run records, logs and WFP filter dumps of one
batch folder, and print them as `name = value` lines. Standard library only.

  python recount.py <batch-folder>                     print the figures
  python recount.py <raw-folder> <sanitised-folder>    print both and the differences (exit 1 on any difference)

The figures are read from the run records (`run-<arm>-<state>-r<n>-<time>.json`), not from `batch-summary.json`; the
summary's own verdicts are read separately and printed beside them. A raw folder may hold files the sanitised folder
omits (the WFP `*-state.xml` dumps, `staging/cfg`, `staging/payload`); only the files the sanitised folder keeps are
read. Filter-key identity is compared inside one folder only (the sanitiser renames keys, consistently within a
folder), never between a raw and a sanitised one: between the two only counts are compared.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LOG_PREFIX_RE = re.compile(r"\[[0-9]+\]")
# The launcher log carries timestamp prefixes and stray spaces inside a line; the line is compared with all white space removed.
PSEC_LINE = "processsecurityenvironmentspecbuilt(PSEC1.1,432bytes)"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _filters(path: Path) -> dict[str, dict]:
    """filterKey -> {name, layer, action, package_sids}, from the `filters` section of one `netsh wfp show filters` dump."""
    root = ET.fromstring(path.read_bytes())
    out: dict[str, dict] = {}
    for item in root.findall("./filters/item"):
        key = (item.findtext("filterKey") or "").strip()
        sids = [
            (c.findtext("./conditionValue/sid") or "").strip()
            for c in item.findall("./filterCondition/item")
            if (c.findtext("fieldKey") or "").strip() == "FWPM_CONDITION_ALE_PACKAGE_ID"
        ]
        out[key] = {
            "name": re.sub(r"\{[^}]*\}", "{GUID}", (item.findtext("./displayData/name") or "").strip()),
            "layer": (item.findtext("layerKey") or "").strip(),
            "action": (item.findtext("./action/type") or "").strip(),
            "package_sids": sids,
        }
    return out


def recount(folder: Path) -> dict[str, object]:
    fig: dict[str, object] = {}
    runs = sorted(folder.glob("run-*-r*-*.json"))
    fig["run_records"] = len(runs)
    ctl = _load(folder / "control-b5.json")
    for k in ("b5a", "b5b", "b5c"):
        fig[f"control.{k}.connected"] = bool(ctl[k].get("connected"))
    fig["control.judgement"] = json.dumps(ctl.get("judgement"), sort_keys=True)
    summary = _load(folder / "batch-summary.json")
    fig["summary.controls_ok"] = summary["controls"]["ok"]
    for grp, g in sorted(summary["groups"].items()):
        fig[f"summary.{grp}.verdict"] = g["verdict"]
        fig[f"summary.{grp}.runs"] = g["runs"]
    header = _load(folder / "batch-header.json")
    fig["header.token_mode"] = header.get("token_mode")
    fig["header.unreadable_under_this_token"] = json.dumps(header.get("unreadable_under_this_token"))
    for arm in ("A", "B"):
        rs = [_load(p) for p in runs if p.name.startswith(f"run-{arm}-")]
        fig[f"{arm}.runs"] = len(rs)
        pre = f"{arm}."
        fig[pre + "dry_run_rc0"] = sum(r["dry_run"]["rc"] == 0 for r in rs)
        fig[pre + "dry_run_stderr_empty"] = sum(r["dry_run"]["stderr"] == "" for r in rs)
        fig[pre + "launch_exit0"] = sum(r["launch"]["exit_code"] == 0 for r in rs)
        fig[pre + "b2_container_200"] = sum(s == 200 for r in rs for s in [b.get("status") for b in r["payload"]["b2"]])
        fig[pre + "b2_proxy_log_forwarded"] = sum(r["verdict"]["b2"]["proxy_log"] for r in rs)
        fig[pre + "b2_second_listener_marker"] = sum(r["verdict"]["b2"]["second_listener_log"] for r in rs)
        for b in ("b3", "b4i", "b4ii"):
            fig[pre + f"{b}_refused_10013"] = sum(
                (r["payload"][b].get("connected") is False and r["payload"][b].get("winerror") == 10013) for r in rs
            )
        fig[pre + "b3_listener_hits"] = sum(r["verdict"]["b3_listener_hits"] for r in rs)
        for when in ("unfenced_pre", "unfenced_post"):
            fig[pre + f"{when}.c_connected"] = sum(bool(r[when]["c"]["connected"]) for r in rs)
            fig[pre + f"{when}.gw_connected"] = sum(bool(r[when]["gw"]["connected"]) for r in rs)
        fig[pre + "state_changed_runs"] = sum(bool(r["state_changed_by_run"]) for r in rs)
        fig[pre + "verdict_HOLD"] = sum(r["verdict"]["verdict"] == "HOLD" for r in rs)
        fig[pre + "launch_wall_secs"] = " / ".join(f"{r['launch']['wall_secs']:.3f}" for r in rs)
        fig[pre + "container_is_appcontainer"] = sum(bool(r["payload"]["token"].get("is_appcontainer")) for r in rs)
        fig[pre + "container_integrity_low_S-1-16-4096"] = sum(r["payload"]["token"].get("integrity_sid") == "S-1-16-4096" for r in rs)
        fig[pre + "container_elevated_true"] = sum(bool(r["payload"]["token"].get("elevated")) for r in rs)
        fig[pre + "launcher_token_mode_standard"] = sum(r["token"].get("mode") == "standard" for r in rs)
        fig[pre + "launcher_integrity"] = ",".join(sorted({r["token"].get("integrity_sid", "") for r in rs}))
        fig[pre + "bitdefender_processes"] = ",".join(str(r["machine"]["bitdefender_processes"]) for r in rs)
        logs = sorted((folder / "staging" / "logs").glob(f"{arm}-*.log"))
        texts = [LOG_PREFIX_RE.sub("", p.read_text(encoding="utf-8", errors="replace")) for p in logs]
        fig[pre + "logs"] = len(logs)
        fig[pre + "log_psec_1_1_432_bytes"] = sum(PSEC_LINE in re.sub(r"\s+", "", t) for t in texts)
        fig[pre + "log_firewall_rules_created_0"] = sum(bool(re.search(r'"firewall_rules_created"\s*:\s*0\b', t)) for t in texts)
        fig[pre + "log_firewall_applied_false"] = sum(bool(re.search(r'"firewall_applied"\s*:\s*false', t)) for t in texts)
        fig[pre + "log_enforcement_mode_capabilities"] = sum(bool(re.search(r'"enforcement_mode"\s*:\s*"capabilities"', t)) for t in texts)
        if (folder / "wfp").is_dir():
            capture = [r["wfp"] for r in rs]
            fig[pre + "wfp.capture_during_container_alive"] = sum(bool(w["capture_during_container_alive"]) for w in capture)
            fig[pre + "wfp.record_counts_before/during/after"] = " | ".join(
                "{}/{}/{}".format(*(w["filter_counts"][k] for k in ("before", "during", "after"))) for w in capture
            )
            fig[pre + "wfp.record_delta_count"] = ",".join(str(w["wfp_delta_count"]) for w in capture)
            xml_counts, xml_delta, xml_after_eq, names, pkg6, perm, blk = [], [], [], [], [], [], []
            for r in rs:
                tag = r["tag"]
                b, d, a = (_filters(folder / "wfp" / f"{tag}-{k}-filters.xml") for k in ("before", "during", "after"))
                xml_counts.append(f"{len(b)}/{len(d)}/{len(a)}")
                new = {k: v for k, v in d.items() if k not in b}
                xml_delta.append(len(new))
                xml_after_eq.append(set(a) == set(b))
                names.append(";".join(sorted(f"{n}x{sum(v['name'] == n for v in new.values())}" for n in {v["name"] for v in new.values()})))
                sid = r["wfp"]["container_sid"]
                pkg6.append(sum(sid in v["package_sids"] for v in new.values()))
                perm.append(sum(v["action"] == "FWP_ACTION_PERMIT" for v in new.values()))
                blk.append(sum(v["action"] == "FWP_ACTION_BLOCK" for v in new.values()))
            fig[pre + "xml.filters_before/during/after"] = " | ".join(xml_counts)
            fig[pre + "xml.new_during_not_in_before"] = ",".join(map(str, xml_delta))
            fig[pre + "xml.after_keys_equal_before_keys"] = sum(xml_after_eq)
            fig[pre + "xml.new_filter_names"] = " | ".join(names)
            fig[pre + "xml.new_filters_keyed_to_run_package_sid"] = ",".join(map(str, pkg6))
            fig[pre + "xml.new_filters_PERMIT"] = ",".join(map(str, perm))
            fig[pre + "xml.new_filters_BLOCK"] = ",".join(map(str, blk))
    if (folder / "wfp").is_dir():
        v4 = summary["variant4_wfp"]
        fig["summary.variant4_wfp.verdict"] = v4["verdict"]
        fig["summary.variant4_wfp.runs"] = v4["runs"]
        fig["summary.variant4_wfp.FILTERS-PRESENT_readings"] = sum(x == "FILTERS-PRESENT" for x in v4["run_readings"].values())
        wc = _load(folder / "wfp-control.json")
        for k in ("created", "removed_verified", "absent_after_removal", "ok"):
            fig[f"wfp_control.{k}"] = wc[k]
        fig["wfp_control.found_filters"] = len(wc["found_filters"])
        fig["wfp_dump_files.filters"] = len(list((folder / "wfp").glob("*-filters.xml")))
    return fig


def main(argv: list[str]) -> int:
    if len(argv) == 1:
        for k, v in recount(Path(argv[0])).items():
            print(f"{k} = {v}")
        return 0
    if len(argv) == 2:
        a, b = recount(Path(argv[0])), recount(Path(argv[1]))
        diffs = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
        print(f"{len(a)} figures in the first folder, {len(b)} in the second, {len(diffs)} difference(s)")
        for k in diffs:
            print(f"DIFF {k}: {a.get(k)!r} != {b.get(k)!r}")
        return 1 if diffs else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
