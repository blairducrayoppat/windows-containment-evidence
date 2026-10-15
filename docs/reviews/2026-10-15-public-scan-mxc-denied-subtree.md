# Outside scan of the public tree at 9fa86af (2026-10-15)

- Fetched without credentials: `https://codeload.github.com/blairducrayoppat/windows-containment-evidence/tar.gz/9fa86af24f8f990964ad3f34ae3f4e188187d6f6`, sha256 `6c2e6ee66e17aa453a419992d81c1ec06eed39e209f174d2f7d70db93faabb2d`, 218 files.
- Searched every text file for: the operator's account name, the host name, `DESKTOP-`, `S-1-5-21-<digit>`, Windows and WSL home paths, the private address ranges `10.0.10.` and `192.168.`, `#` followed by a four-digit number starting with 1, and numbered fixture prefixes.
- Result: no identifying hit. The only matches were the previous scan record (`docs/reviews/2026-10-15-public-scan-mxc-proxy-egress.md`), which names the search patterns and the allowlisted upstream reference, and that reference itself, `microsoft/mxc#1406` in `evidence/2026-10-15-mxc-proxy-egress/README.md` line 82, an upstream pull request in the allowlisted form.
- `evidence/2026-10-15-mxc-denied-subtree/README.md` at that commit returns HTTP 200 from the public site.
