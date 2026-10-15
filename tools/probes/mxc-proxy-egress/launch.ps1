<#
Hash-bound launcher for the MXC loopback-proxy egress probe.

What this measures: nothing itself. It starts run_probe.py only if run_probe.py, net_payload.py, proxy.py and
summarise.py each match a line `<sha256>  <filename>` in the approved-hash file; any missing file, missing
line or mismatch REFUSES to start (exit 1) and names the cause.
Elevation: a live run is refused unless this process is elevated; `--dry-run-only` is allowed without it.
  -SelfTestElevation (elevated|standard) overrides the detection for the self-test only.
How to run: double-click launch.cmd, or `pwsh -File launch.ps1 [-ApprovedFile PATH] [-VerifyOnly] [probe args]`.
  Probe args pass through to run_probe.py (for example `--arms A` or `--dry-run-only`).
Approved-hash file default: ~\blarai-research-data\mxc-proxy-egress\APPROVED_SHA256.txt
What it writes: nothing; it passes its own sha256 to run_probe.py, which records it in the batch header
  (record only: launch.ps1 cannot verify itself). run_probe.py writes its raw records under its own output folder.
  -VerifyOnly checks the hashes, prints the verdict and stops (no probe is started).

NOT MEASURED: any build other than the one(s) run; behaviour on a host whose --probe reports host-loopback
ingress unsupported (the earlier 26200.9457 condition); an identity-scoped proxy (allowedProxyPeer); the session-isolation backend; UDP, ICMP or DNS egress under the proxy policy;
host-to-container ingress (the doc's own open limitation); nono under MXC; anything about the fork or any
other sandbox.
#>
param(
    [string]$ApprovedFile = (Join-Path $env:USERPROFILE 'blarai-research-data\mxc-proxy-egress\APPROVED_SHA256.txt'),
    [switch]$VerifyOnly,
    [ValidateSet('', 'elevated', 'standard')][string]$SelfTestElevation = '',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ProbeArgs
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$required = @('run_probe.py', 'net_payload.py', 'proxy.py', 'summarise.py')
$problems = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path -LiteralPath $ApprovedFile -PathType Leaf)) {
    $problems.Add("approved-hash file missing: $ApprovedFile")
    $approved = @{}
} else {
    $approved = @{}
    foreach ($line in Get-Content -LiteralPath $ApprovedFile) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -notmatch '^([0-9A-Fa-f]{64})\s+\*?(\S+)$') { $problems.Add("unparseable line in approved file: $t"); continue }
        $name = $Matches[2]; $hash = $Matches[1].ToLowerInvariant()
        if ($approved.ContainsKey($name) -and $approved[$name] -ne $hash) { $problems.Add("conflicting approved hashes for $name") }
        $approved[$name] = $hash
    }
}
foreach ($f in $required) {
    $path = Join-Path $here $f
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $problems.Add("file missing: $f"); continue }
    if (-not $approved.ContainsKey($f)) { $problems.Add("no approved hash listed for $f"); continue }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $approved[$f]) { $problems.Add("hash mismatch for ${f}: file $actual, approved $($approved[$f])") }
}
if ($problems.Count -gt 0) {
    Write-Host 'REFUSED: the probe files do not match the approved hashes.'
    foreach ($p in $problems) { Write-Host "  - $p" }
    exit 1
}
Write-Host 'VERIFIED: all probe files match the approved hashes.'
if ($VerifyOnly) { exit 0 }

$isDry = $ProbeArgs -contains '--dry-run-only'
if ($SelfTestElevation -ne '') { $elevated = ($SelfTestElevation -eq 'elevated') }
else { $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not $elevated -and -not $isDry) {
    Write-Host 'REFUSED: a live run must be launched elevated (the filter writes the containment needs are privileged, and the earlier record of this question was elevated).'
    Write-Host '  Right-click launch.cmd and choose Run as administrator. The --dry-run-only mode may run without elevation.'
    exit 1
}
$py = $env:BLARAI_PROBE_PYTHON
if (-not $py) { $cmd = Get-Command python -ErrorAction SilentlyContinue; if ($cmd) { $py = $cmd.Source } }
if (-not $py) { Write-Host 'REFUSED: no python found (set BLARAI_PROBE_PYTHON).'; exit 1 }
$self = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash.ToLowerInvariant()
& $py -I (Join-Path $here 'run_probe.py') --launch-sha256 $self @ProbeArgs
exit $LASTEXITCODE
