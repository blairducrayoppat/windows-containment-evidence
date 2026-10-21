# windows-containment-evidence

A public record of measurements of Windows process and network containment for AI agents on real machines: what held,
what did not, under what conditions, with counts and the list of what was not tested. Data under CC BY 4.0, code under
Apache-2.0. It began as research inside a private project and is published here so that others (the nono project's
NEP-0005 discussion, Anthropic's sandbox-runtime, Microsoft's MXC) can cite and re-run it. It makes no product claim.

## Layout

| Path | What it holds |
|---|---|
| `evidence/<date>-<topic>/` | One folder per measurement: its write-up, the run records, the scripts as they ran, and a `.sanitized` file with the replacement counts |
| `evidence/2026-10-05-wfp-sid-block/` | A raw Windows Filtering Platform (WFP) block keyed to one account's SID under a third-party security product; account-level file access; a confined account serving a local model; persistent filter sets across a restart. The claims table (rows C1 to C26) for this folder and the next one is `account-level-containment-evidence.md` |
| `evidence/2026-10-13-nep0005-halfset/` | Half-installed WFP filter sets ("half-sets") and how sandbox-runtime's Windows helper (`srt-win`) reports them; candidate fixes as patches |
| `evidence/2026-10-14-nono-9p-control/` | Whether nono's Landlock sandbox on the WSL 9P mount lets a process do what its own command line does not grant (360 runs) |
| `evidence/2026-10-20-nep0005-case4-nco/` | Whether a member of the local group Network Configuration Operators can add and delete a WFP filter, under the filtered token of an ordinary launch and under a token with the group enabled (a scheduled task's batch logon); two sittings, with administrator and standard-token controls. Claim C27 is carried in this folder's README, not in the claims table above (which holds C1 to C26) |
| `tools/probes/` | Probe scripts that are not already beside their evidence, with a header for each |
| `tools/sanitize.py` | Copies raw results to a new folder with machine, person and internal-tracker identifiers replaced |
| `tools/leak_gate.py` | Refuses any file or commit message that still carries one; `tools/allowed_guids.txt` lists the GUIDs it allows and why |
| `.githooks/` | `pre-commit` runs the gate over staged files; `commit-msg` runs it over the message |
| `docs/reviews/` | Reviews of the data in this repository (a review of the data is data) |
| `PROVENANCE.md` | Where each folder was first published, what was changed on the way in, and what was left out |
| `LICENSE` / `LICENSE-DATA` | Apache-2.0 for code, scripts and patches; CC BY 4.0 for results, tables and records |

## How to cite

Cite a file at a commit, never at `main`, so the text you cite cannot change under the link:

    https://github.com/blairducrayoppat/windows-containment-evidence/blob/<commit>/evidence/<folder>/<file>

Name the folder, the claim row or table you rely on, and its stated conditions. Each write-up lists what was not
measured; a citation that drops those limits overstates the record.

## How to re-run

Each evidence folder's README (or its `runs/AS_RUN.md`) gives the run order, the conditions and the self-test commands.
Self-tests and dry runs change nothing on the machine. Live runs create accounts, ACLs, scheduled tasks, WFP objects or
WSL fixtures; each script states what it changes and how it undoes it, and most require an elevated shell. Run them on a
machine you can afford to change.

The scripts here are sanitised copies: names of machines, accounts, fixtures and internal records were replaced (see
each `.sanitized` file and `PROVENANCE.md`). Where a run record holds the SHA-256 of the script that ran, that hash
belongs to the original bytes, not to the copy here.

## The identity rule

Nothing in this repository identifies a machine, a person or a private tracker. Results enter only through
`tools/sanitize.py`, on a branch, reviewed, then merged. The leak gate enforces it at commit time:

    git config core.hooksPath .githooks      # once per clone

The gate reads this machine's host and account names at run time and keeps the remaining private patterns in a local
file, `.leakgate.local.json`, which is never committed (shape in `tools/leak_gate.py`). Without that file the gate
refuses to run, and the commit is refused with it. Check the whole tree with `python tools/leak_gate.py --tracked`, and
the gate itself with `python tools/leak_gate.py --self-test`.
