# srt-win: the SMB redirector connects to a loopback port the WFP fence blocks for the fenced user, 2026-10-17

Subject: `srt-win`, the Windows helper of anthropics/sandbox-runtime. WFP is the Windows Filtering Platform; SMB is Server
Message Block, the Windows file-sharing protocol. One physical host (Windows 11, OS build 26200.9711) and one clean virtual
machine (OS build 26300.9457), loopback (127.0.0.1) only, on an alternate SMB port.

## Reported to Anthropic first

This result was reported privately to Anthropic through their disclosure programme on 2026-10-18, before any public
mention, because the fence is theirs. The evidence they received is the content of this folder (see "What is in the
folder" for the one path renamed since). Anthropic closed the report on 2026-10-20 as Informative: "a known and accepted
limitation of the identity-scoped design", "a documentation and defense-in-depth hardening area rather than a bypass of
a defended boundary". They noted an earlier report on the same root cause, closed the same way, and forwarded to the
maintainers the suggestion that the Windows known-limitations list name SMB. They asked to see the public write-up first,
and it was sent to them on 2026-10-20 before publication.

## Question

srt-win fences a dedicated `srt-sandbox` account with WFP filters keyed to that account's user SID. A process running as
that account cannot open a TCP connection to a loopback port outside the permit. Can it have the Windows SMB redirector
open one for it, by naming the blocked port in a UNC path?

## Result in one paragraph

Yes, on both machines. The fenced user's own TCP connects to the blocked loopback port were refused with WinError 10013
every time they were tried, before and after each test (50 of 50 on the host, 12 of 12 in the virtual machine), with no
listener record. When the same fenced user ran `net use \\127.0.0.1\<share> /TCPPORT:<blocked port> /TRANSPORT:TCP`, a
log-only listener on that blocked port received new TCP connections, each carrying a 73-byte SMB1 NEGOTIATE, in 24 of 25
passes on the host (versions 1-3 of the proof of concept) and 6 of 6 in the virtual machine. Every one of those client
sockets whose owner was recorded is owned by PID 4 (System), the kernel SMB redirector: 70 of 70 on the host and 12 of 12
in the virtual machine. A larger harness, with the fence checked directly before and after the SMB state, agreed (12 of 12
passes over 4 runs, 20 of 20 attributed sockets owned by PID 4). The WebDAV client did not reach the blocked port while
fenced (2 runs, both fenced identities). So a process confined by the fence can have the SMB redirector open TCP
connections to a loopback port the fence blocks for the process itself, on a port the process names. Which filter
permitted those connections was not captured. This is a finding about one srt-win build on two Windows installations,
loopback only; port 445, another address and another machine were not tested.

Probable mechanism, an inference from srt-win's source and not observed: the design comment in
`vendor/srt-win-src/src/wfp.rs` lines 20-24 (upstream commit `626a59671ee2be556d70a290a8036224be996193`) says the BLOCK
filter "matches only tokens whose user SID is `<srt-sandbox SID>`. Everyone else (the broker, services, SYSTEM, the real
user) carries a different user SID → no match → falls through to default-permit." A connection made by System would then
not match. The README of sandbox-runtime says running under a distinct user SID "structurally closes the surrogate-spawn
class of escape". Its Known limitations list names DNS through `Dnscache` but not network shares.

Attribution scope. In the proof-of-concept runs, the same TCP-table lookup attributed the fenced user's own permitted
connect to the fenced process's PID (25 of 25 passes across versions 1-3 on the host, 6 of 6 in the virtual machine), and
the blocked-port SMB connections to PID 4. In harness runs 5-7 the SMB connections were attributed to PID 4, and the
fenced WebDAV opens on the permitted port (U2p, U2pt) to one other process per run, not PID 4; every fenced user-mode
connect to a blocked port in those runs was refused, so none was there to attribute.

## Conditions

| Item | Value |
|---|---|
| Host Windows | Windows 11 Pro, 25H2, OS build 26200.9711 (October 13, 2026 cumulative update KB5127648). The registry ProductName reads "Windows 10 Pro", as it does on Windows 11 |
| Virtual machine | Hyper-V Generation 2, fresh Windows 11 Pro from Microsoft's installation image, 26H2, OS build 26300.9457 (`winver.json`), restored from a checkpoint taken before any other software was installed, and restored to it again afterwards |
| srt-win installed | `srt-win install` (elevated, once), default permit range 60080-60089. Host: filters installed by a binary with sha256 `620ccb98...e6de`, built 2026-10-13 from the upstream tarball at `24eb39e9`. Virtual machine: the proof-of-concept binary below (4 filters, `srt-win-install.json`) |
| srt-win in the proof of concept | unmodified upstream main `626a59671ee2be556d70a290a8036224be996193` (release v0.0.80), built 2026-10-17 with rustc 1.98.1 and upstream CI's command, sha256 `a7aa8c600cba330c896785e78889fdfada1f3cbbcc242d4c2b224a3e5cd3c66b`, `srt-win 0.0.1` |
| srt-win in harness runs 4-9 | the `620ccb98...e6de` binary (recorded in the `wfp-before.json` and `wfp-after.json` of runs 4-7; no file of runs 8-9 records the binary; that they used the same one is stated, not recorded here). It is code-identical to the main build: the same size, with 28 bytes different, all in build timestamps and the PDB (program database) GUID. With those zeroed, both hash to `5d7e1822b4a2f3ab2cf1a3ceead877de96ecc34bdcaeaa338043a1fcc02d8946`. `vendor/srt-win-src` has the same tree hash (`e7f889b4`) at `24eb39e9` and `626a5967` |
| Fenced account | `srt-sandbox`, the standard local account created by `srt-win install` |
| Launch | Proof of concept: a one-shot Scheduled Task with RunLevel Limited, so the caller's token was Medium integrity with Administrators deny-only (`poc-runs/*/console.txt`). Harness runs 4-9: a non-elevated launch, with pre-registered tasks for the harness's elevated helpers. Virtual machine: a Scheduled Task with RunLevel Limited in the interactive desktop session of the virtual machine's own local account, Medium integrity with Administrators deny-only (`whoami-groups.txt`) |
| Security products | Host: during every proof-of-concept run, Security Center listed Windows Defender, McAfee and Bitdefender Antivirus, plus the Bitdefender and McAfee firewalls; runs 4-9 detected Bitdefender (antivirus, firewall, 9 services). Virtual machine: Windows Defender only (product state 397568, real-time protection on, engine 4.18.25080.5, signatures 1.437.1.0); the firewall and antispyware product lists were empty (`security_center.json`, and `security_products` in each `result.json`) |
| Other load | another test process was running on the host during the proof-of-concept runs. During v3-run-1 it made SMB connections to 127.0.0.1 on other alternate ports, the likely cause of that run's two error-67 passes (Windows SMB client log, read elevated) |
| SMB alternate port | `net use ... /TCPPORT:` is documented for Windows 11 24H2 and later. The host's own SMB server holds port 445, so the test uses an alternate port |
| Times (UTC) | Proof of concept on the host: version 1, 19:04-19:08; version 2, 19:28-19:33; version 3, 19:42-19:46, all on 2026-10-17; version 4, 19:10-19:13 on 2026-10-18. Virtual machine: 2026-10-18, 18:50-18:53 |

## Method

### Stand-alone proof of concept (`poc/q2_smb_redirector_poc.ps1`)

Stock Windows PowerShell 5.1 plus srt-win. No other tools and no installation. The script refuses an elevated token.
Each pass runs four steps as the fenced user, through `srt-win exec --quiet -- powershell.exe ...`:

| Step | What runs as `srt-sandbox` | Expected | Purpose |
|---|---|---|---|
| C1 | plain TCP connect to `127.0.0.1:61795` (outside the permit) | refused with 10013; the listener gets nothing | positive control: the fence is in force for the user's own sockets |
| C2 | plain TCP connect to `127.0.0.1:60088` (inside the 60080-60089 permit) | connects; the listener records it; owner = the fenced PowerShell's PID | negative control: the payload runs, the listener witnesses, and owner attribution separates a user socket from a kernel one |
| T | `net.exe use \\127.0.0.1\poc /TCPPORT:61795 /TRANSPORT:TCP` | (the test) | does the blocked port receive connections, and who owns them? |
| C3 | same as C1 | refused with 10013; the listener gets nothing | positive control after the test |

Before the passes: srt-win's own readiness check `srt-win wfp verify --target 127.0.0.1:61795` must report
`"egress_probe":"blocked"`; and the declared permit range is checked against the installed fence by behaviour (a
non-elevated caller cannot read the installed filters: `srt-win status` and `srt-win wfp status` both report
`"state":"cannot-read"`), so with a listener on each port `wfp verify` must read blocked at PermitLow-1, connected at
PermitLow, connected at PermitHigh and blocked at PermitHigh+1; a mismatch is INCOMPLETE. Before each T, the TCP table
must show no open client socket to the blocked port, so a reused connection cannot be counted.

The listener is log-only and in-process, on 127.0.0.1. For each accepted connection it records the measurement window
it arrived in (taken first, at accept), the client's source port, the owner of the client socket from the TCP table
(`Get-NetTCPConnection`, no elevation), and the first bytes. It never answers, so no SMB session setup, credentials,
share name or file data can cross. Each payload reports the account it ran as; the script compares it in memory to the
`srt-sandbox` SID and records only a boolean, the short name and the RID.

Outcomes, all fail-loud: `run_status` is COMPLETE, INCOMPLETE or BLIND. INCOMPLETE means a precondition failed, a payload
did not run as `srt-sandbox`, C1 or C3 was not refused with 10013, a socket to the blocked port was already open before
T, a record reached the blocked port outside every measured window, or an unexpected error occurred. BLIND means C2 was
not witnessed, or was not attributed to the fenced PID. `result` is REPRODUCED only when every pass's T delivered at
least one connection and every such client socket is owned by PID 4. Exit codes: 10 COMPLETE+REPRODUCED, 11
COMPLETE+NOT-REPRODUCED, 12 COMPLETE+MIXED, 3 INCOMPLETE, 4 BLIND. Every outcome writes `result.json` and prints a final
`run_status=... result=... exit=...` line.

Script versions (each `result.json` from version 2 on records the script's sha256):

- Version 1 crashed under StrictMode when C1 or C3 was not refused, instead of reading INCOMPLETE. Its runs record no
  script hash and the file is not in this folder; version 2 differs from it only in failure handling.
- Version 2 (`poc/previous/q2_smb_redirector_poc-v2.ps1`, sha256
  `de77515c647a2835ed46a34ce2380a13b0e731bb34c26aaed9cf6e3d801cba04`, as recorded in each v2 `result.json`): every
  payload record carries every key, an unexpected error is trapped into INCOMPLETE, and the script's sha256 is
  recorded. The two `toggle-copy.diff` files apply to it.
- Version 3 (`poc/previous/q2_smb_redirector_poc-v3.ps1`, sha256
  `7045b2c8837418528c64a4ee9f2b24528d2a610a05e04f679c076aad9a01eb26`) adds the behavioural permit-range check.
- Version 4 (`poc/q2_smb_redirector_poc.ps1`, sha256
  `7e3ba27fbf69e3909ad1cc2eb53563a9cb7d9b0061a9854a14f415b58f1267d4`) adds one record to version 3 and changes nothing
  else: immediately before and after each T it records, per pass as `foreign_smb_during_T`, every connection owned by
  PID 4 with remote address 127.0.0.1 and a remote port other than the blocked port (other SMB activity on loopback).
  The record never changes `run_status` or `result`. Checked with the PowerShell parser (Windows PowerShell 5.1 and
  PowerShell 7) and run twice on the host, non-elevated, on 2026-10-18.

### Larger test harness (runs 4-9)

A larger instrument ran the same SMB attempt (state U1: fenced `srt-sandbox`, `net use \\127.0.0.1\fx-a
/TCPPORT:61781 /TRANSPORT:TCP`), with the fence checked directly before and after (two direct connects refused with
10013, plus `srt-win wfp verify` blocked), a permitted-port control (U1p, port 60082) and an elevated `wfp verify`
before and after the batch. The harness stops on the first FAIL by design. Run 4 had no owner field. Runs 5-7 (harness
version B) added the TCP-table owner lookup at accept and a per-pass connection ledger, measured beforehand
(`evidence/owner-attribution-20261017/`): a user-mode connect was attributed to its own PID in 3 of 3 cases, and the SMB
redirector's connects from an unfenced account to PID 4 System in 8 of 8. Runs 8-9 measured only the harness's WebDAV
fixture (fx-b): Windows' WebDAV client opening `\\127.0.0.2@<port>\DavWWWRoot\fx-b.txt`, served by the harness listener
on 127.0.0.2, for both fenced identities (`srt-sandbox` and `<test-account>`).

## Results

### Proof of concept on the host, non-elevated

| Run | Script | Passes | C1 (before) | C2 (permitted) | T: connections to 61795 | T: owner | T: SMB header | C3 (after) | run_status / result |
|---|---|---|---|---|---|---|---|---|---|
| v1-run-1 | v1 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | 10013 ×3, 0 records | COMPLETE / REPRODUCED |
| v1-run-2 | v1 | 3 | same | same | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | same | COMPLETE / REPRODUCED |
| v1-run-3 | v1 | 3 | same | same | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | same | COMPLETE / REPRODUCED |
| v1-run-4-1pass | v1 | 1 | 10013, 0 records | connected, owner = fenced PID | 3 | PID 4 System, 3 of 3 | 3 of 3 | 10013, 0 records | COMPLETE / REPRODUCED |
| v2-run-1 | v2 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | 10013 ×3, 0 records | COMPLETE / REPRODUCED |
| v2-run-2 | v2 | 3 | same | same | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | same | COMPLETE / REPRODUCED |
| v3-run-1 | v3 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 1 / 0 / 3 | PID 4 System, 4 of 4 | 4 of 4 | 10013 ×3, 0 records | COMPLETE / MIXED |
| v3-run-2 | v3 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | 10013 ×3, 0 records | COMPLETE / REPRODUCED |
| v3-run-3 | v3 | 3 | same | same | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | same | COMPLETE / REPRODUCED |
| v4-run-1 | v4 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 3 / 3 / 3 | PID 4 System, 9 of 9 | 9 of 9 | 10013 ×3, 0 records | COMPLETE / REPRODUCED |

Versions 1-3 (the first nine rows: 9 runs, 25 passes): 9 of 9 COMPLETE, 8 REPRODUCED and 1 MIXED. SMB reached the
blocked port in 24 of 25 passes; 70 of 70 of those connections were owned by PID 4 System; every payload ran as
`srt-sandbox` (100 of 100); C1 and C3 were refused with 10013, with no listener record, 50 of 50 times; C2 was seen and
owned by the fenced process 25 of 25 times; no record reached the blocked port outside a measured window. Every
connection's first bytes were `00000045 ff534d42 72...`: a 4-byte NetBIOS session header for 69 bytes, then an SMB1
header with command 0x72, NEGOTIATE. `net.exe` reported `System error 64` (the listener closes without answering) in 23
passes and `System error 67` in 2. Version 4 (`v4-run-1`) is the shipped script's own run and is counted separately:
`foreign_smb_during_T` read none in all three passes and `result.notes` is empty.

**v3-run-1 (MIXED).** In passes 1 and 2, `net.exe` reported `System error 67` ("The network name cannot be found") after
1.2 s and 1.8 s, with 1 and 0 connections reaching the blocked port. Pass 3 behaved like every other pass. The likely
cause is concurrent SMB activity to 127.0.0.1 on other alternate ports from another test process on the host (Windows
SMB client log, read elevated; the log is not in this folder). In that log, a connection to 127.0.0.1 on another
alternate port was refused at the moment pass 1's `net.exe` reported error 67. Pass 2 has no matching log line. No other
proof-of-concept T window shows SMB to any port except the run's own blocked port. Foreign loopback SMB alone did not
produce error 67: in `v4-toggle-foreign-smb-churn` another process's SMB connections to 127.0.0.1:61900 were open
around two passes, and both still delivered 3 connections with error 64.

### Checks that the controls fail loud

Version 3's failure handling is version 2's, so the banked checks of that handling were run on copies of version 2. On
version 3, a copy with two edits (the two wfp-verify problem lines removed and the blocked-port in-permit pre-check
disabled) gave C1 and C3 connected and INCOMPLETE, exit 3, with `result.json` written; that run is not banked here.
"Shipped script" means the unmodified script of the version named in the run's name.

| Run | Condition | Outcome |
|---|---|---|
| v1-toggle-elevated, v2-toggle-elevated | the shipped script started from an elevated shell | INCOMPLETE, exit 3, "run this NON-elevated"; nothing launched |
| v1/v2-toggle-blocked-port-actually-permitted | shipped script, non-elevated, `-BlockedPort 60089 -PermittedPort 60084 -PermitLow 60080 -PermitHigh 60085`: the declared permit is narrowed so that 60089, which the installed fence permits, passes the in-permit pre-check | INCOMPLETE, exit 3: `srt-win wfp verify` reported `"egress_probe":"connected"` and the listener recorded its connect; no pass ran |
| v2-toggle-C1-not-refused | a copy of the v2 script with only the two wfp-verify problem lines removed (`toggle-copy.diff`), StrictMode on, non-elevated, `-BlockedPort 60087 -PermittedPort 60084 -PermitLow 60080 -PermitHigh 60085` | C1 and C3 connected; INCOMPLETE, exit 3, `result.json` written, problems naming C1 and C3 |
| v2-toggle-unexpected-error | a copy of the v2 script with one injected `throw` after C2 (`toggle-copy.diff`), non-elevated | INCOMPLETE, exit 3, "unexpected error at line 272", `result.json` written |
| v3-toggle-declared-range-mismatch | shipped v3 script, non-elevated, `-PermitHigh 60088` (one less than the installed 60089) | INCOMPLETE, exit 3: `wfp verify` at 60089 read `connected`, expected `blocked`; no pass ran |
| v2-location-check-profile-folder | shipped script, non-elevated, the same srt-win binary (sha256 `a7aa8c60...`) run from a folder under the caller's profile | INCOMPLETE, exit 3: `CreateProcessWithLogonW(srt-sandbox): Access is denied. (0x80070005)` from `srt-win wfp verify` |
| v4-toggle-foreign-smb-churn | shipped v4 script, non-elevated, defaults, while a second process on the host repeatedly ran `net use \\127.0.0.1\foreignpoc /TCPPORT:61900 /TRANSPORT:TCP` and its `/delete`, against a listener on 127.0.0.1:61900 that accepted each connection and held it for 0.8 s | `foreign_smb_during_T` read `ports 61900` in passes 1 and 2 and none in pass 3, with a `NOTE:` line naming passes 1 and 2. The verdict did not change: COMPLETE / REPRODUCED, exit 10, 3 connections per pass, 9 of 9 PID 4, `net.exe` error 64 in every T |

### Proof of concept in the virtual machine (no third-party security software)

Two runs of the unmodified version 3 script (sha256 `7045b2c8...`), `poc-runs/v3-vm-suite-absent/`:

| Run | Script | Passes | C1 (before) | C2 (permitted) | T: connections to 61795 | T: owner | T: SMB header | C3 (after) | run_status / result |
|---|---|---|---|---|---|---|---|---|---|
| vm run-1 | v3 | 3 | 10013 ×3, 0 records | connected ×3, owner = fenced PID ×3 | 2 / 2 / 2 | PID 4 System, 6 of 6 | 6 of 6 | 10013 ×3, 0 records | COMPLETE / REPRODUCED |
| vm run-2 | v3 | 3 | same | same | 2 / 2 / 2 | PID 4 System, 6 of 6 | 6 of 6 | same | COMPLETE / REPRODUCED |

Before the passes, `srt-win wfp verify` read blocked at 61795, and the permit-range check read blocked, connected,
connected and blocked at 60079, 60080, 60089 and 60090. In every T, `net.exe` reported `System error 64`. Every payload
ran as `srt-sandbox` (24 of 24). Every connection was the same 73-byte SMB1 NEGOTIATE as on the host. No record reached
the blocked port outside a measured window, and no socket to the blocked port was open before any T. Each T delivered 2
connections here and 3 on the host; the records give no reason for the difference.

A first attempt on the clean installation stopped at `srt-win install`, which exited with 0xC0000135
(STATUS_DLL_NOT_FOUND): srt-win needs the Visual C++ 2015-2022 runtime, and a clean install lacks it. Placing
`vcruntime140.dll` beside the executable is enough. The copy used was signed by Microsoft, file version 14.50.35719.0
(`vcruntime140-provenance.txt`).

### Harness, runs 4-7: SMB (security suite present)

| Run | Harness version | U1 passes with SMB on 61781 | Listener records (connect + bytes) | New TCP connections | Owners | Fence before / after U1 | WebDAV fixture |
|---|---|---|---|---|---|---|---|
| run-20261017-4 | A | 3 of 3 | 6 / 4 / 4 | 3 / 2 / 2 | not recorded (no owner field) | held / held | BLIND (unfenced control not run) |
| run-20261017-5 | B | 3 of 3 | 6 / 4 / 4 | 3 / 2 / 2 | PID 4 System ×7 | held / held | BLIND (unfenced control not run) |
| run-20261017-6 | B | 3 of 3 | 6 / 4 / 2 | 3 / 2 / 1 | PID 4 System ×6 | held / held | BLIND (unfenced control not run) |
| run-20261017-7 | B | 3 of 3 | 6 / 4 / 4 | 3 / 2 / 2 | PID 4 System ×7 | held / held | BLIND (unfenced control not run) |

Harness verdict FAIL in 4 of 4 (SMB reached the blocked port in 12 of 12 passes). Owners in runs 5-7: 20 of 20 PID 4
System, 20 of 20 new TCP connections, none reused. In every run, U0 (the fenced user's direct connects to blocked ports
61780 and 61781) was refused with 10013. The U1p control (fenced SMB to the permitted port 60082) delivered in every
run, also owned by PID 4 in runs 5-7. `net.exe` reported `System error 64` on every SMB pass, and every rollback was
proven. The fenced WebDAV states ran in all four runs, for both identities, and the permitted-port WebDAV records
precede every SMB record: the opens on the blocked port failed (error 53 in run 4; errors 3 and 53 in runs 5-7) with no listener record, and the opens on the
permitted port delivered. The fixture reads BLIND because the harness stopped at the SMB FAIL before its unfenced
control (U3) ran; runs 8-9 measured it alone.

### Harness, runs 8-9: WebDAV, for comparison (security suite present)

Same host, same srt-win binary (as stated above; not recorded in these runs' files) and same launch as runs 4-7. The SMB fixture was not selected, and nothing reached its
ports.

| State | What runs | Passes per identity, per run | Outcome in both runs, both identities |
|---|---|---|---|
| U0 | fenced direct TCP connect to blocked ports 61780 (127.0.0.2) and 61781 (127.0.0.1) | 6 | refused, 10013; no listener record |
| U2a | fenced WebDAV open on blocked port 61780, WebClient service stopped | 3 | failed, error 3; no listener record |
| U2b | fenced WebDAV open on blocked port 61780, WebClient service running | 3 | failed, error 53; no listener record |
| U2p | fenced WebDAV open on permitted port 60081 (positive control) | 3 | opened every pass; per run, 11 listener records (5 new connections) for `srt-sandbox` and 8 (4) for `<test-account>` |
| U3b | the same open on blocked port 61780 without the fence: the caller's own account, and `<test-account>` unfenced (control) | 1 | opened; per run, 7 records (3 new connections) and 2 (1) |

The fence was checked directly before and after every fenced WebDAV state and held each time; every rollback was
proven. The harness verdict in both runs is HOLD for fx-b; fx-a is NOT-SELECTED. The U2p client sockets were owned, in
each run, by one process shared by both identities, not PID 4; its name was not readable without elevation. The
packet-monitor counts in `counts.json` read 0 in every state, including the controls that delivered, so they are not a
witness in these runs; the listener is. On this evidence the behaviour is specific to the SMB redirector: the WebDAV
client did not reach the blocked port while fenced.

## What the counts are

Repeats on one host and one virtual machine, minutes apart, not a distribution. The C2 control (the listener sees the
fenced user's own permitted connect and attributes it to the fenced process) is what lets a T connection owned by PID 4
be read as the redirector's and not the payload's, and the C1/C3 refusals on either side of every T are what show the
fence in force for the user's own sockets throughout. The virtual machine is the suite-absent condition: it is a
different Windows build and a different machine, so it shows the result does not depend on Bitdefender or McAfee being
present, not that the two installations differ only in the suites. The 2-versus-3 connections per T between the two
machines is unexplained by the records.

## Not measured

- **Which filter permitted the connection.** The owner comes from the TCP table. No WFP net-event or Security-log 5156
  capture (both need elevation) was run, so the mechanism above is inferred from the owner (PID 4) and srt-win's design
  comment.
- **Port 445, a non-loopback address, another machine.** Only 127.0.0.1 with an alternate port was tested. The fence's
  BLOCK covers every address and its permit is loopback-only. The off-host case has not been measured.
- **What a responding SMB server would receive.** The listener never answers. Only the TCP connection and the NEGOTIATE
  were observed. Whether a session setup (with the fenced account's NTLM exchange) or a tree connect carrying a path the
  fenced process chose would follow is unmeasured.
- **WebDAV beyond runs 8-9.** BLIND in runs 4-7 (the harness stops on the first FAIL, so the WebDAV fixture's unfenced
  control never ran). Runs 8-9 measured it alone, on the host only, over HTTP (not `@SSL`), with the security suite
  present and on loopback only. The proof of concept does not test WebDAV, and WebDAV was not run in the virtual machine.
- **The host without its third-party security suites.** The host itself was not measured with Bitdefender and McAfee
  removed; the virtual machine is the suite-absent condition.
- **Other machines and builds.** One physical host (OS build 26200.9711) and one clean virtual machine (OS build
  26300.9457). No second physical machine.
- **The harness's second fenced identity** (`<test-account>`) did not reach its blocked-port SMB state in runs 4-7,
  because the harness stops at the first FAIL; it ran its direct connects to the blocked ports (U0t), the fenced
  WebDAV states and the permitted-port SMB control (U1pt).
- **Variance** beyond the runs listed.

## What is in the folder

| Path | What |
|---|---|
| `poc/q2_smb_redirector_poc.ps1` | the proof of concept, version 4 (`v4-run-1` and `v4-toggle-foreign-smb-churn` used it) |
| `poc/previous/` | versions 2 and 3, byte-identical to the files the banked runs used |
| `poc-runs/<run>/` | `result.json` and `console.txt` of every banked run and control check named above, plus `toggle-copy.diff` where a modified copy was used |
| `poc-runs/v3-vm-suite-absent/` | the virtual-machine runs (`run-1/`, `run-2/`) and five support files: `security_center.json`, `winver.json`, `whoami-groups.txt`, `srt-win-install.json`, `vcruntime140-provenance.txt`. The console and whoami files were converted from UTF-16 to UTF-8 with their text unchanged |
| `evidence/run-20261017-4/` to `-7/` | the SMB harness records: `verdict.json` (verdict text, codes, fence checks, security-suite detection), `listener.jsonl` (every record, with tag, port, source port, owner and the first 32 bytes), `session-extract-U0-U1p-U1.json` (per-pass payload results and the fence checks around U1), `wfp-before.json` and `wfp-after.json` (srt-win `wfp verify` from the elevated helper), `counts.json`, `header.txt` |
| `evidence/run-20261017-8/`, `-9/` | the WebDAV-only harness records: `verdict.json`, `counts.json` (per-pass records and the connection ledger), `header.txt`, `listener.jsonl` |
| `evidence/owner-attribution-20261017/` | the measurement that validated the TCP-table owner lookup, and its script |
| `evidence/confirmation-console/` | console output of runs 5-7 and the sequence log |
| `.sanitized` | replacement counts per file and rule (never an original value) |
| `SHA256SUMS` | the sha256 of every record and script file, equal to the file index of the pack as reported |
| `recount.py`, `RECOUNT.md` | the script that re-counts the measured figures of this README from the records (counts, codes, owners, first bytes, script and binary hashes, run times, the virtual machine's build and security products), and its output. Statements about builds, installation, the disclosure and the upstream source come from outside these records and are not re-counted |

**Placeholders**, as in the evidence Anthropic received: `<probe-dir>` (the harness's install folder), `<helper>` (a
harness helper script name), `<task-folder>` (its Scheduled Task folder), `<test-account>` (the harness's second test
account; its JSON key reads `test-account`), `__MACHINE__` (the machine part of local SIDs), `__VM__` (the same, in the
virtual machine), `<folder>` (the folder srt-win was copied to). Account and host names are removed.

**One path renamed.** The virtual-machine folder was `poc-runs/v3-vm-suite-absent-26300.9457/` in the evidence
Anthropic received; here it is `poc-runs/v3-vm-suite-absent/`, so that no four-digit number sits in a path name. The OS
build is unchanged inside `winver.json` and is stated above. No file's content differs from that evidence: `SHA256SUMS`
lists the sha256 of each of the 96 record and script files (check with `sha256sum -c SHA256SUMS` in this folder), and
every value equals the one in the file index of the pack Anthropic received. The pack's own README and index are not
included; this README replaces the README.

**Corrections to the pack's README.** Re-counting from the records (`RECOUNT.md` holds the figures) found three
statements in the README Anthropic received that the records do not support; this README states them as the records do. (1) The sha256
`de77515c...` is version 2's, recorded by version 2 about itself; the pack gave it to version 1, whose runs record no
hash. (2) In harness runs 5-7 the pack said only the SMB connections were attributed; the permitted-port WebDAV
connections were attributed too, to a process that is not PID 4. (3) The pack's runs 4-7 table read the WebDAV fixture
as "not reached"; its fenced states ran, and it is BLIND because its unfenced control did not. No figure of the result
changes. One statement is not re-derivable from the records: that in the two `toggle-blocked-port-actually-permitted`
runs the listener recorded the `wfp verify` connect (their `result.json` holds no listener records; the script's
problem line, "srt-win wfp verify reached the blocked port", is the record).

**Not included.** The host's Windows SMB client log, read elevated for the v3-run-1 note, and the harness itself (only
its records are here).

## How to re-run

srt-win needs the Visual C++ 2015-2022 runtime. A clean Windows installation lacks it, and `srt-win install` then exits
with 0xC0000135; placing `vcruntime140.dll` beside `srt-win.exe` is enough.

Once, from an **elevated** prompt (srt-win's normal installation, the only elevated step):

```
srt-win install
```

Then, from a **non-elevated** prompt. `srt-win.exe` must sit in a folder the `srt-sandbox` account can read and execute
(for example `C:\ProgramData\<folder>\srt-win.exe`), because srt-win starts its runner as that account; from a folder
under the caller's profile it fails with Access is denied (`v2-location-check-profile-folder`).

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File q2_smb_redirector_poc.ps1 -SrtWin C:\ProgramData\<folder>\srt-win.exe -OutDir .\out
```

Options: `-BlockedPort` (default 61795; must be outside the permit), `-PermittedPort` (default 60088; must be inside the
permit), `-PermitLow` / `-PermitHigh` (default 60080 / 60089; pass the range given to `srt-win install`; the script
checks the declared range at its edges by behaviour and refuses a mismatch), `-Passes` (default 3). The last line
printed is `run_status=... result=... exit=...`; `result.json` in the output folder holds every payload result and every
listener record. A run takes about one minute. Clean-up: none beyond deleting the output folder (the script deletes its
`net use` mapping attempt); `srt-win uninstall` (elevated) removes srt-win.

`python recount.py .` re-counts the figures of this README from the records in this folder (standard library only).
