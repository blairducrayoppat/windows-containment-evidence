# Outside scan after the switch to public, 2026-10-15

The repository was made public on 2026-10-15 at 18:08:46 UTC (14:08:46 -04:00), after the pre-push review recorded in
`2026-10-15-pre-push.md` passed in round 5 with zero open findings.

What was scanned: the public tree of `main` at commit `25c705b2e568e028d5e56a977491dc05078af367` (git tree
`792ab832560cc9ba0c4d98e062f52a3a4eb277ff`), fetched without credentials as the code host's tarball
(`codeload.github.com/.../tar.gz/<commit>`, HTTP 200, sha256 of the tarball
`932565f1679df6357c4e4047978237736dd44048f490bfd81424f3dfb5b30efd`), extracted into an empty folder outside every clone.
The repository's metadata was readable without credentials (HTTP 200 from the public API).

| Check | Result |
|---|---|
| `python tools/leak_gate.py --tree <extracted tree>` with the local pattern file | `leak_gate: 152 file(s) checked, 0 hit(s)` |
| Files in the tarball | 152, the same count as `git ls-files` at that commit |
| Case-insensitive search for the two old host-name stems the private project has used and for an `S-1-5-21-` SID with digits | 0 files |
| `Users\` followed by a name | only `Users\Public`, `Users\Default`, a wildcard `Users\*` and a `<user>` placeholder |
| Author and committer e-mail of every public commit (8) | the code host's no-reply address for the account, in every commit |

Result: zero hits.
