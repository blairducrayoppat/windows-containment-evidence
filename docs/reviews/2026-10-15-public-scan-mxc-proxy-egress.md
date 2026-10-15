# Outside scan of the public tree at 0c9b1a0 (2026-10-15)

- Fetched without credentials: `https://codeload.github.com/blairducrayoppat/windows-containment-evidence/tar.gz/0c9b1a08b982c5a563be53dd641fbe21fc385050`, sha256 `1c498779f4ad7676c0df4e608bf567d7b72aa01d946f74003a49cc1584e30fda`, 195 files.
- Searched every text file for: the operator's account name, the host name, `DESKTOP-`, `S-1-5-21-<digit>`, Windows and WSL home paths, the private address ranges `10.0.10.` and `192.168.`, `#` followed by a four-digit number starting with 1, and numbered fixture prefixes.
- Result: one hit, `microsoft/mxc#1406` in `evidence/2026-10-15-mxc-proxy-egress/README.md` line 82, an upstream pull request reference in the allowlisted form. No identifying hit.
- `evidence/2026-10-15-mxc-proxy-egress/README.md` at that commit returns HTTP 200 from the public site.
