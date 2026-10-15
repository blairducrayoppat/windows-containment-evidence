# NEP-0005 half-set matrix (run 2026-10-13)

Half-installed Windows Filtering Platform (WFP) filter sets for one test account, and what sandbox-runtime's Windows
helper (`srt-win`) reports for each: whether the account is in fact blocked or open, and whether the helper's status,
verify and install commands see the difference. Candidate fixes are included as patches and were measured too.

The claims, with their conditions and what was not tested, are rows C12 to C26 of the claims table in
`../2026-10-05-wfp-sid-block/account-level-containment-evidence.md` (one table for both folders, kept whole).

| Path | What it holds |
|---|---|
| `SPEC.md` | The build contract: fixed constants (test account, test sublayers, pinned srt-win source), the states R0 to R7 and O1 to O6, safety rules |
| `runs/AS_RUN.md` | What ran, when, from which code, and the hashes the run's rollback proof recorded |
| `runs/*.json` | The run records (`taskcheck-*`, `halfset-*`, `ours-*`, `n1-*`) and the derived `results-summary.json`, `srtcli-results-summary.json` |
| `scripts/` | The matrix scripts as they ran, and `README.md` with the run order and the restore rules |
| `harness/` | The Rust harness the matrix drives, its build script and its refusal tests |
| `srtcli/` | The driver for srt-win's own CLI on each half-set, its deploy and summary scripts |
| `srtcli/fix/` | The candidate fixes (`*.patch`, `pr/`), a fake srt-win for offline tests, and the verify runner |

Tabular export: Hugging Face `blairducrayoppat/openvino-arc140v-lunarlake`, commit `d215aed0`, `containment/nep0005_halfset/`.
The run records are sanitised copies; see `.sanitized` here and `../../PROVENANCE.md`.
