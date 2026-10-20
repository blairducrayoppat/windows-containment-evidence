<#
.SYNOPSIS
  Proof of concept: a process fenced by srt-win's per-user WFP egress fence can make the Windows SMB client
  (the kernel SMB redirector, PID 4 "System") open TCP connections to a loopback port the fence blocks for it.

.DESCRIPTION
  Stock Windows PowerShell 5.1 plus srt-win. Run NON-ELEVATED (the script refuses an elevated token).
  Prerequisite (one-time, ELEVATED, not done by this script):  srt-win install
  (creates the srt-sandbox account and the 4-filter WFP set: block everything for the srt-sandbox user SID,
  permit loopback 127.0.0.0/8 to ports 60080-60089).

  For each pass the script runs, as the fenced srt-sandbox user via `srt-win exec`:
    C1  positive control, before: a plain TCP connect to 127.0.0.1:<BlockedPort>. Expected: refused, WinError 10013,
        and the listener receives nothing. Proves the fence is in force for this user's own sockets.
    C2  negative control: a plain TCP connect to 127.0.0.1:<PermittedPort> (inside the fence's loopback permit).
        Expected: connected, the listener receives it, and the TCP table attributes the client socket to the fenced
        PowerShell's own PID (not PID 4). Proves the payload runs, the listener witnesses, and owner attribution
        distinguishes a user-mode socket from a kernel one.
    T   test: net.exe use \\127.0.0.1\poc /TCPPORT:<BlockedPort> /TRANSPORT:TCP (the SMB client's alternate-port
        support, Windows 11 24H2 / build 26100 or later). The question: does the listener on the blocked port receive
        connections, and which process owns their client sockets?
    C3  positive control, after: the same as C1.
  The listener is log-only: it reads the first bytes, looks up the client socket's owner in the TCP table
  (Get-NetTCPConnection, no elevation needed), and closes. It never answers, so no SMB session setup,
  credentials, share name or file data can cross.

  Output: run_status COMPLETE / INCOMPLETE / BLIND and result REPRODUCED / NOT-REPRODUCED / MIXED / NONE, printed as
  the last line and written to result.json in -OutDir. Nothing is a silent pass:
    INCOMPLETE  a precondition failed, a payload did not run as srt-sandbox, a positive control was not refused with
                10013, the blocked port had an open connection before T, a record reached the blocked port outside
                any measured window, or any unexpected error occurred.
    BLIND       the negative control was not witnessed or not attributed to the fenced process, so the listener or the
                owner lookup cannot be trusted to see T.
    COMPLETE    every pass decided. result REPRODUCED only when every pass's T delivered at least one connection to
                the blocked port and every one of those client sockets is owned by PID 4 System.
  Exit codes: 10 COMPLETE+REPRODUCED, 11 COMPLETE+NOT-REPRODUCED, 12 COMPLETE+MIXED, 3 INCOMPLETE, 4 BLIND.

  Around each T (version 4 on) the script reads the TCP table immediately before T and immediately after T's window,
  and records, per pass as foreign_smb_during_T, every TCP connection owned by PID 4 with remote address 127.0.0.1
  and a remote port other than -BlockedPort, with its local and remote ends. Those are other SMB activity on loopback:
  the SMB client connecting for some other process to the same server name on another port, or the host SMB server's
  side of a loopback session. Concurrent SMB activity to 127.0.0.1 on other alternate ports was observed to coincide
  with System error 67 and with fewer or no connections to the blocked port; the Windows SMB client log that shows it
  needs elevation, so this record is the non-elevated signal. The record is informational only: it never changes run_status or result. A table that cannot be read is
  recorded as an error in the same field, never as "none".

  -PermitLow / -PermitHigh declare the permit range passed to `srt-win install`. A non-elevated caller cannot read the
  installed filters (`srt-win status` reports `wfp: cannot-read`; filter enumeration is admin-only), so the script
  checks the declared range against the installed fence by behaviour before any pass: with a listener on each port,
  `srt-win wfp verify` must read blocked at PermitLow-1 and PermitHigh+1 and connected at PermitLow and PermitHigh.
  A mismatch, or a boundary port that cannot be bound, is INCOMPLETE. The passes then check the blocked port (wfp
  verify, C1/C3 refused) and the permitted port (C2 connected).

  The script records no account name, host name or machine SID: identities are compared in memory and recorded as
  booleans plus the account's short name and RID.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File q2_smb_redirector_poc.ps1 -SrtWin C:\path\to\srt-win.exe -OutDir .\out
#>
param(
    [Parameter(Mandatory)][string]$SrtWin,
    [string]$OutDir = (Join-Path (Get-Location) ('poc-out-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$BlockedPort = 61795,
    [int]$PermittedPort = 60088,
    [int]$PermitLow = 60080,
    [int]$PermitHigh = 60089,
    [int]$Passes = 3
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$Sys = $env:SystemRoot
$PsExe = Join-Path $Sys 'System32\WindowsPowerShell\v1.0\powershell.exe'
$NetExe = Join-Path $Sys 'System32\net.exe'
$problems = New-Object System.Collections.ArrayList
$result = [ordered]@{ tool = 'q2_smb_redirector_poc'; version = 4; script_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLower(); started_utc = (Get-Date).ToUniversalTime().ToString('o') }

function Finish([string]$status, [string]$res, [int]$code) {
    $result.run_status = $status
    $result.result = $res
    $result.problems = @($problems)
    $result.finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    try {
        New-Item -ItemType Directory -Force $OutDir | Out-Null
        $result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $OutDir 'result.json')
    } catch { Write-Output ("could not write result.json: " + $_.Exception.Message) }
    foreach ($p in $problems) { Write-Output ("PROBLEM: " + $p) }
    Write-Output ("run_status=$status result=$res exit=$code")
    exit $code
}

# Any error not handled below ends the run INCOMPLETE with result.json and a run_status line, never a bare stack trace.
trap {
    [void]$problems.Add("unexpected error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)")
    try { $state.stop = $true } catch { }
    Finish 'INCOMPLETE' 'NONE' 3
}

# ---------------------------------------------------------------- preconditions
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $groups = (& (Join-Path $Sys 'System32\whoami.exe') /groups) -join "`n"
    $integrity = if ($groups -match 'High Mandatory Level') { 'High' } elseif ($groups -match 'Medium Mandatory Level') { 'Medium' } else { 'other' }
    $result.launch = [ordered]@{ elevated = $elevated; integrity = $integrity }
    if ($elevated -or $integrity -ne 'Medium') { [void]$problems.Add("run this NON-elevated (Medium integrity); this token is elevated=$elevated integrity=$integrity"); Finish 'INCOMPLETE' 'NONE' 3 }

    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os = [ordered]@{ product = $cv.ProductName; edition = $cv.EditionID; display_version = $cv.DisplayVersion; build = [int]$cv.CurrentBuild; ubr = [int]$cv.UBR }
    if ([int]$cv.CurrentBuild -lt 26100) { [void]$problems.Add("net use /TCPPORT needs Windows 11 24H2 (build 26100) or later; this is build $($cv.CurrentBuild)") }
    try {
        $result.security_products = [ordered]@{
            antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName })
            firewall  = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName })
        }
    } catch { $result.security_products = "unreadable: $($_.Exception.Message)" }

    foreach ($f in @($SrtWin, $PsExe, $NetExe)) { if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { [void]$problems.Add("missing file: $(Split-Path -Leaf $f)") } }
    if ($problems.Count) { Finish 'INCOMPLETE' 'NONE' 3 }
    $SrtWin = (Resolve-Path -LiteralPath $SrtWin).Path
    $ErrorActionPreference = 'Continue'; $ver = (& $SrtWin --version 2>&1 | Out-String).Trim(); $ErrorActionPreference = 'Stop'
    $result.srt_win = [ordered]@{ file = (Split-Path -Leaf $SrtWin); sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SrtWin).Hash.ToLower(); version = $ver }

    if ($BlockedPort -ge $PermitLow -and $BlockedPort -le $PermitHigh) { [void]$problems.Add("BlockedPort $BlockedPort is inside the fence's loopback permit $PermitLow-$PermitHigh") }
    if ($PermittedPort -lt $PermitLow -or $PermittedPort -gt $PermitHigh) { [void]$problems.Add("PermittedPort $PermittedPort is outside the fence's loopback permit $PermitLow-$PermitHigh") }

    try {
        $sandboxSid = (New-Object Security.Principal.NTAccount('srt-sandbox')).Translate([Security.Principal.SecurityIdentifier]).Value
        $result.sandbox_account = [ordered]@{ name = 'srt-sandbox'; rid = ($sandboxSid -split '-')[-1]; machine_local = $sandboxSid.StartsWith('S-1-5-21-') }
    } catch { [void]$problems.Add("the srt-sandbox account does not resolve (run the elevated 'srt-win install' first): $($_.Exception.Message)") }
    if ($problems.Count) { Finish 'INCOMPLETE' 'NONE' 3 }
} catch { [void]$problems.Add("precondition error: $($_.Exception.Message)"); Finish 'INCOMPLETE' 'NONE' 3 }

$result.ports = [ordered]@{ blocked = $BlockedPort; permitted = $PermittedPort; permit_range_assumed = "$PermitLow-$PermitHigh" }

# ---------------------------------------------------------------- fenced payloads
function ConnectPayload([int]$port) {
@"
`$ErrorActionPreference='Stop'
`$id=[Security.Principal.WindowsIdentity]::GetCurrent()
`$o=[ordered]@{op='connect';user=`$id.Name;sid=`$id.User.Value;pid=`$PID;port=$port}
try{`$c=New-Object Net.Sockets.TcpClient;`$c.Connect('127.0.0.1',$port);`$o.result='connected';`$o.local_port=`$c.Client.LocalEndPoint.Port;Start-Sleep -Milliseconds 1500;`$c.Close()}
catch{`$e=`$_.Exception;while(`$e.InnerException){`$e=`$e.InnerException};if(`$e -is [Net.Sockets.SocketException]){`$o.result='refused';`$o.winerror=`$e.ErrorCode}else{`$o.result='error';`$o.error=`$e.Message}}
'RESULT '+(`$o|ConvertTo-Json -Compress)
"@
}
function SmbPayload([int]$port) {
@"
`$ErrorActionPreference='Continue'
`$id=[Security.Principal.WindowsIdentity]::GetCurrent()
`$o=[ordered]@{op='smb';user=`$id.Name;sid=`$id.User.Value;pid=`$PID;port=$port}
try{`$t=(& '$NetExe' use '\\127.0.0.1\poc' /TCPPORT:$port /TRANSPORT:TCP 2>&1|ForEach-Object{"`$_"}|Out-String).Trim();`$o.exit=`$LASTEXITCODE;`$o.text=`$t.Substring(0,[Math]::Min(200,`$t.Length))
if(`$t -match 'System error (\d+)'){`$o.result='failed';`$o.win32=[int]`$Matches[1]}elseif(`$t -match 'completed successfully'){`$o.result='mapped';`$o.win32=0}else{`$o.result='other'}}
catch{`$o.result='error';`$o.error=`$_.Exception.Message}
finally{& '$NetExe' use '\\127.0.0.1\poc' /delete /y 2>&1|Out-Null}
'RESULT '+(`$o|ConvertTo-Json -Compress)
"@
}

# Every payload record carries every key, so a check on a key the payload did not report reads $null, not a StrictMode error.
function New-PayloadRecord {
    [ordered]@{ ran = $false; why = $null; srt_exit = $null; seconds = $null; stderr_head = $null; identity_ok = $false; user = $null; pid = $null
                result = $null; winerror = $null; local_port = $null; exit = $null; win32 = $null; text = $null; error = $null }
}

function Invoke-Fenced([string]$payload, [int]$timeoutSec = 120) {
    $r = New-PayloadRecord
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $SrtWin
    $psi.Arguments = 'exec --quiet -- "' + $PsExe + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $enc
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $Sys   # srt-win refuses some working folders (exit 16 mapped_drive_cwd); SystemRoot is accepted
    $t0 = Get-Date
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($timeoutSec * 1000)) { try { $p.Kill() } catch {}; $r.why = "timeout after $timeoutSec s"; return $r }
    $p.WaitForExit()
    $out = $so.Result; $err = $se.Result
    $r.srt_exit = $p.ExitCode; $r.seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    $line = @($out -split "`r?`n" | Where-Object { $_.StartsWith('RESULT ') }) | Select-Object -Last 1
    if (-not $line) { $r.why = 'no RESULT line'; $r.stderr_head = $err.Substring(0, [Math]::Min(300, $err.Length)); return $r }
    $j = $line.Substring(7) | ConvertFrom-Json
    $r.ran = $true
    # identity: compared in memory, recorded without the machine SID or host name
    $r.identity_ok = ($j.sid -eq $sandboxSid) -and ($j.user -match '\\srt-sandbox$')
    $r.user = ($j.user -split '\\')[-1]
    $r.pid = $j.pid
    foreach ($k in 'result', 'winerror', 'local_port', 'exit', 'win32', 'text', 'error') { if ($j.PSObject.Properties[$k]) { $r[$k] = $j.$k } }
    if ($r.text) { $r.text = ($r.text -replace '\s+', ' ') }
    return $r
}

# ---------------------------------------------------------------- log-only listener (runspace)
$state = [hashtable]::Synchronized(@{ phase = 'idle'; stop = $false; ready = $false; error = $null })
$log = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
$listenerCode = {
    param($ports, $state, $log)
    try {
        $null = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1   # pre-load the module
        $ls = @(foreach ($pt in $ports) { $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $pt); $l.Start(); $l })
        $state.ready = $true
        while (-not $state.stop) {
            $any = $false
            foreach ($l in $ls) {
                if (-not $l.Pending()) { continue }
                $any = $true
                $c = $l.AcceptTcpClient()
                $rec = [ordered]@{ ts = (Get-Date).ToUniversalTime().ToString('o'); phase = $state.phase }   # phase taken first, at accept
                $rec.lport = $null; $rec.peer_port = $null; $rec.owner = [ordered]@{ found = $false; pid = $null; process = $null; why = 'not looked up' }
                $rec.nbytes = 0; $rec.head = ''; $rec.smb = $false
                $lp = $l.LocalEndpoint.Port; $pp = $c.Client.RemoteEndPoint.Port
                $rec.lport = $lp; $rec.peer_port = $pp
                try {
                    $rows = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $pp -RemoteAddress 127.0.0.1 -RemotePort $lp -ErrorAction SilentlyContinue)
                    $pids = @($rows | ForEach-Object { [int]$_.OwningProcess } | Where-Object { $_ -ne 0 } | Sort-Object -Unique)
                    if ($pids.Count -eq 1) {
                        $pn = 'unreadable'
                        try { $pn = (Get-Process -Id $pids[0] -ErrorAction Stop).ProcessName } catch { }
                        $rec.owner = [ordered]@{ found = $true; pid = $pids[0]; process = $pn; why = $null }
                    } elseif ($pids.Count -gt 1) { $rec.owner = [ordered]@{ found = $false; pid = $null; process = $null; why = "ambiguous: $($pids -join ',')" } }
                    else { $rec.owner = [ordered]@{ found = $false; pid = $null; process = $null; why = "no owned row ($($rows.Count) rows)" } }
                } catch { $rec.owner = [ordered]@{ found = $false; pid = $null; process = $null; why = "lookup failed: $($_.Exception.Message)" } }
                try {
                    $c.ReceiveTimeout = 2000
                    $buf = New-Object byte[] 256
                    $n = 0
                    try { $n = $c.GetStream().Read($buf, 0, 256) } catch { $n = 0 }
                    $rec.nbytes = $n
                    $rec.head = (($buf[0..([Math]::Max(0, [Math]::Min($n, 32) - 1))] | ForEach-Object { $_.ToString('x2') }) -join '')
                    if ($n -eq 0) { $rec.head = '' }
                    $rec.smb = ($n -ge 8) -and ($buf[5] -eq 0x53) -and ($buf[6] -eq 0x4d) -and ($buf[7] -eq 0x42) -and ($buf[4] -eq 0xff -or $buf[4] -eq 0xfe)
                } finally { $c.Close() }
                [void]$log.Add($rec)
            }
            if (-not $any) { Start-Sleep -Milliseconds 15 }
        }
        foreach ($l in $ls) { $l.Stop() }
    } catch { $state.error = $_.Exception.Message; $state.ready = $true }
}
$rs = [runspacefactory]::CreateRunspace(); $rs.Open()
$ps = [powershell]::Create(); $ps.Runspace = $rs
# (port, expected) pairs; a list, not a dictionary: an [ordered] dictionary indexed by an int reads by position, not by key
$RangePorts = @(@(($PermitLow - 1), 'blocked'), @($PermitLow, 'connected'), @($PermitHigh, 'connected'), @(($PermitHigh + 1), 'blocked'))
$ListenPorts = @(@($BlockedPort, $PermittedPort) + @($RangePorts | ForEach-Object { $_[0] }) | Sort-Object -Unique)
[void]$ps.AddScript($listenerCode).AddArgument($ListenPorts).AddArgument($state).AddArgument($log)
$handle = $ps.BeginInvoke()
$deadline = (Get-Date).AddSeconds(30)
while (-not $state.ready -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
if (-not $state.ready -or $state.error) {
    [void]$problems.Add("listener did not start: $($state.error)"); $state.stop = $true; Finish 'INCOMPLETE' 'NONE' 3
}

function Stop-Listener { $state.stop = $true; try { [void]$ps.EndInvoke($handle) } catch {}; $ps.Dispose(); $rs.Close() }
function RecsIn([string]$phase, [int]$port) { @($log.ToArray() | Where-Object { $_.phase -eq $phase -and $_.lport -eq $port }) }
function Run-Phase([string]$name, [string]$payload) {
    $state.phase = $name
    $r = Invoke-Fenced $payload
    Start-Sleep -Seconds 3        # late accepts still land in this window
    $state.phase = 'idle'
    return $r
}
# PID 4 connections with remote address 127.0.0.1 and a remote port other than the blocked port: other SMB activity on
# loopback (the SMB client for another process, or the host SMB server's side of a loopback session). Informational only. The whole table is read and then filtered, so an
# unreadable table is recorded as an error instead of reading as an empty result.
function Get-ForeignSmb {
    try {
        $rows = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { [int]$_.OwningProcess -eq 4 -and $_.RemoteAddress -eq '127.0.0.1' -and [int]$_.RemotePort -ne $BlockedPort })
        return [ordered]@{
            remote_ports = @($rows | ForEach-Object { [int]$_.RemotePort } | Sort-Object -Unique)
            connections  = @($rows | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) $($_.State)" })
            error        = $null
        }
    } catch { return [ordered]@{ remote_ports = @(); connections = @(); error = $_.Exception.Message } }
}

# ---------------------------------------------------------------- srt-win's own readiness check
try {
    $state.phase = 'wfp-verify'
    $ErrorActionPreference = 'Continue'   # under 'Stop', native stderr through 2>&1 throws and the exit code is lost
    Push-Location $Sys
    try { $vo = (& $SrtWin wfp verify --target "127.0.0.1:$BlockedPort" 2>&1 | ForEach-Object { "$_" } | Out-String).Trim(); $vx = $LASTEXITCODE } finally { Pop-Location; $ErrorActionPreference = 'Stop' }
    $result.wfp_verify = [ordered]@{ exit = $vx; text = ($vo -replace '\s+', ' ') }
    Start-Sleep -Seconds 1
    $state.phase = 'idle'
    if ($vx -ne 0 -or $vo -notmatch '"egress_probe":"blocked"') { [void]$problems.Add("srt-win wfp verify did not report the fence in force (exit $($result.wfp_verify.exit)): $($result.wfp_verify.text)") }
    if (@(RecsIn 'wfp-verify' $BlockedPort).Count) { [void]$problems.Add('srt-win wfp verify reached the blocked port: the fence is not in force') }
} catch { [void]$problems.Add("srt-win wfp verify failed to run: $($_.Exception.Message)") }
if ($problems.Count) { Stop-Listener; Finish 'INCOMPLETE' 'NONE' 3 }

# ---------------------------------------------------------------- declared permit range vs the installed fence (behavioural)
$result.permit_range_check = @()
foreach ($pair in $RangePorts) {
    $rp = [int]$pair[0]; $want = [string]$pair[1]
    $state.phase = "range-$rp"
    $ErrorActionPreference = 'Continue'
    Push-Location $Sys
    try { $ro = (& $SrtWin wfp verify --target "127.0.0.1:$rp" 2>&1 | ForEach-Object { "$_" } | Out-String).Trim(); $rx = $LASTEXITCODE } finally { Pop-Location; $ErrorActionPreference = 'Stop' }
    Start-Sleep -Milliseconds 500
    $state.phase = 'idle'
    $got = if ($ro -match '"egress_probe":"([a-z-]+)"') { $Matches[1] } else { 'unparsed' }
    $result.permit_range_check += [ordered]@{ port = $rp; expected = $want; egress_probe = $got; exit = $rx; listener_records = @(RecsIn "range-$rp" $rp).Count }
    if ($got -ne $want) { [void]$problems.Add("declared permit $PermitLow-$PermitHigh does not match the installed fence: wfp verify at port $rp read '$got', expected '$want' (pass the range given to 'srt-win install')") }
}
if ($problems.Count) { Stop-Listener; Finish 'INCOMPLETE' 'NONE' 3 }

# ---------------------------------------------------------------- passes
$passResults = @()
for ($i = 1; $i -le $Passes; $i++) {
    $pr = [ordered]@{ pass = $i; problems = @() }
    $c1 = Run-Phase "p$i-C1" (ConnectPayload $BlockedPort)
    $c2 = Run-Phase "p$i-C2" (ConnectPayload $PermittedPort)
    $open = @(Get-NetTCPConnection -RemoteAddress 127.0.0.1 -RemotePort $BlockedPort -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -ne 0 })
    $pr.open_client_sockets_to_blocked_port_before_T = $open.Count
    $fsBefore = Get-ForeignSmb
    $t = Run-Phase "p$i-T" (SmbPayload $BlockedPort)
    $fsAfter = Get-ForeignSmb
    $pr.foreign_smb_during_T = [ordered]@{ remote_ports = @(@($fsBefore.remote_ports) + @($fsAfter.remote_ports) | Sort-Object -Unique); before = $fsBefore; after = $fsAfter }
    $fsText = if ($fsBefore.error -or $fsAfter.error) { 'unreadable' } elseif (@($pr.foreign_smb_during_T.remote_ports).Count) { 'ports ' + (@($pr.foreign_smb_during_T.remote_ports) -join ',') } else { 'none' }
    $c3 = Run-Phase "p$i-C3" (ConnectPayload $BlockedPort)

    $r1 = @(RecsIn "p$i-C1" $BlockedPort); $r2 = @(RecsIn "p$i-C2" $PermittedPort); $rt = @(RecsIn "p$i-T" $BlockedPort); $r3 = @(RecsIn "p$i-C3" $BlockedPort)
    $pr.C1 = $c1; $pr.C1_listener_records = $r1.Count
    $pr.C2 = $c2; $pr.C2_listener_records = $r2.Count
    $pr.T = $t;   $pr.T_listener_records = $rt
    $pr.C3 = $c3; $pr.C3_listener_records = $r3.Count

    $status = 'decided'
    foreach ($pair in @(@('C1', $c1, $r1), @('C3', $c3, $r3))) {
        $n = $pair[0]; $c = $pair[1]; $rr = $pair[2]
        if (-not $c.ran) { $pr.problems += "$n did not run: $($c.why)"; $status = 'INCOMPLETE'; continue }
        if (-not $c.identity_ok) { $pr.problems += "$n did not run as srt-sandbox"; $status = 'INCOMPLETE' }
        if ($c.result -ne 'refused' -or $c.winerror -ne 10013) { $pr.problems += "$n (positive control) was not refused with 10013: result=$($c.result) winerror=$($c.winerror)"; $status = 'INCOMPLETE' }
        if ($rr.Count) { $pr.problems += "$n reached the blocked port ($($rr.Count) records): the fence did not block this user's own socket"; $status = 'INCOMPLETE' }
    }
    if (-not $t.ran) { $pr.problems += "T did not run: $($t.why)"; $status = 'INCOMPLETE' }
    elseif (-not $t.identity_ok) { $pr.problems += 'T did not run as srt-sandbox'; $status = 'INCOMPLETE' }
    if ($open.Count) { $pr.problems += "an open client socket to the blocked port existed before T ($($open.Count))"; $status = 'INCOMPLETE' }
    if ($status -eq 'decided') {
        if (-not $c2.ran -or -not $c2.identity_ok -or $c2.result -ne 'connected') { $pr.problems += "C2 (negative control) did not connect as srt-sandbox: ran=$($c2.ran) result=$($c2.result) winerror=$($c2.winerror)"; $status = 'BLIND' }
        elseif ($r2.Count -lt 1) { $pr.problems += 'C2 connected but the listener recorded nothing: the witness is blind'; $status = 'BLIND' }
        elseif (-not @($r2 | Where-Object { $_.owner.found -and $_.owner.pid -eq $c2.pid -and $_.peer_port -eq $c2.local_port }).Count) { $pr.problems += "C2's socket was not attributed to the fenced process (pid $($c2.pid)): owner attribution unproven"; $status = 'BLIND' }
    }
    if ($status -eq 'decided') {
        $owners = @($rt | ForEach-Object { if ($_.owner.found) { "pid $($_.owner.pid) $($_.owner.process)" } else { "not found: $($_.owner.why)" } })
        $pr.T_owners = $owners
        $pr.T_new_connections = $rt.Count
        $pr.T_smb_headers = @($rt | Where-Object { $_.smb }).Count
        $allSystem = ($rt.Count -gt 0) -and (@($rt | Where-Object { -not ($_.owner.found -and $_.owner.pid -eq 4) }).Count -eq 0)
        $pr.T_all_owned_by_pid4 = $allSystem
        $pr.outcome = if ($rt.Count -eq 0) { 'NOT-REPRODUCED' } elseif ($allSystem) { 'REPRODUCED' } else { 'REACHED-OTHER-OWNER' }
    } else { $pr.outcome = $status }
    $passResults += $pr
    Write-Output ("pass $i : C1=$($c1.result)/$($c1.winerror) C2=$($c2.result) (records $($r2.Count)) T=$($t.result)/$($t.win32) records_on_blocked_port=$($rt.Count) C3=$($c3.result)/$($c3.winerror) foreign_smb_during_T=$fsText -> $($pr.outcome)")
}
Stop-Listener
$result.passes = $passResults
# Informational notes; they never change run_status or result.
$result.notes = @()
$fsSeen = @($passResults | Where-Object { @($_.foreign_smb_during_T.remote_ports).Count } | ForEach-Object { $_.pass })
$fsUnread = @($passResults | Where-Object { $_.foreign_smb_during_T.before.error -or $_.foreign_smb_during_T.after.error } | ForEach-Object { $_.pass })
if ($fsSeen.Count) { $result.notes += "other connections owned by pid 4 with remote address 127.0.0.1 (not the blocked port) were open around T in pass(es) $($fsSeen -join ','); a pass with System error 67 or fewer connections may be explained by them" }
if ($fsUnread.Count) { $result.notes += "the TCP table could not be read around T in pass(es) $($fsUnread -join ','); foreign_smb_during_T is unknown there" }
foreach ($nt in $result.notes) { Write-Output ("NOTE: " + $nt) }
$unphased = @($log.ToArray() | Where-Object { $_.lport -eq $BlockedPort -and $_.phase -eq 'idle' })
$result.unphased_records_on_blocked_port = $unphased
$result.all_listener_records = $log.ToArray()
if ($unphased.Count) { [void]$problems.Add("$($unphased.Count) record(s) reached the blocked port outside any measured window") }

$outcomes = @($passResults | ForEach-Object { $_.outcome })
foreach ($pr in $passResults) { foreach ($q in $pr.problems) { [void]$problems.Add("pass $($pr.pass): $q") } }
if ($unphased.Count -or ($outcomes -contains 'INCOMPLETE')) { Finish 'INCOMPLETE' 'NONE' 3 }
if ($outcomes -contains 'BLIND') { Finish 'BLIND' 'NONE' 4 }
$tot = ($passResults | ForEach-Object { $_.T_new_connections } | Measure-Object -Sum).Sum
$sys = ($passResults | ForEach-Object { @($_.T_owners | Where-Object { $_ -like 'pid 4 *' }).Count } | Measure-Object -Sum).Sum
$result.summary = "T delivered $tot connection(s) to blocked port $BlockedPort over $Passes pass(es); $sys of $tot client sockets owned by pid 4 System"
Write-Output $result.summary
if (@($outcomes | Where-Object { $_ -ne 'REPRODUCED' }).Count -eq 0) { Finish 'COMPLETE' 'REPRODUCED' 10 }
if (@($outcomes | Where-Object { $_ -ne 'NOT-REPRODUCED' }).Count -eq 0) { Finish 'COMPLETE' 'NOT-REPRODUCED' 11 }
Finish 'COMPLETE' 'MIXED' 12
