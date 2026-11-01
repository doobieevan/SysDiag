<#
.SYNOPSIS
    SysDiag engine - a general Windows health-check / snapshot tool.
.DESCRIPTION
    Collects OS / CPU / RAM / disk / network listeners / services /
    persistence (startup, registry autoruns, scheduled tasks) / firewall /
    running processes, and writes a clean, timestamped report. Produces
    Markdown plus styled HTML and a registry autorun export (.reg).

    Section selection is driven by environment variables (SYSDIAG_*) so a GUI
    can steer each run without argument parsing. The report is a plain, parseable
    log; heuristic analysis and "suggested issues" live in the Python GUI layer.

    Designed to be general (not hardcoded to any machine) and deterministic.
.PARAMETER OutDir
    Output directory (env SYSDIAG_OUTDIR overrides).
#>
[CmdletBinding()]
param(
    [string]$OutDir
)

# ---------- configuration (script scope; env overrides) ----------
if (-not $OutDir) { $OutDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:USERPROFILE } }
if ($env:SYSDIAG_OUTDIR) { $OutDir = $env:SYSDIAG_OUTDIR }

# Normalize a bash/MSYS absolute path (/c/Users/x -> C:\Users\x).
function Normalize-WindowsPath {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    if ($Path.Contains(':')) { return $Path }
    if ($Path.StartsWith('/')) {
        $Drive = $Path.Substring(1, 1).ToUpper()
        $Rest  = $Path.Substring(2).TrimStart('/')
        $Sep   = [System.IO.Path]::DirectorySeparatorChar
        return "$($Drive):$Sep" + ($Rest.Replace('/', $Sep))
    }
    return $Path
}

$OutDir   = Normalize-WindowsPath $OutDir
$OutDir   = if ($OutDir) { $OutDir } else { $env:USERPROFILE }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$ReportBase = if ($env:SYSDIAG_REPORTNAME) { $env:SYSDIAG_REPORTNAME }
              else { "sysdiag_" + [DateTime]::Now.ToString("yyyyMMdd_HHmm") }
$Report     = Join-Path $OutDir "$ReportBase.md"

# ---------- small config ----------
$Env = "SYSDIAG_OS", "SYSDIAG_NETWORK", "SYSDIAG_SERVICES", "SYSDIAG_TASKS",
       "SYSDIAG_STARTUP", "SYSDIAG_REGISTRY", "SYSDIAG_FIREWALL",
       "SYSDIAG_PROCESSES", "SYSDIAG_TOOLS"
$Sec = [ordered]@{ os=0; network=0; services=0; tasks=0; startup=0; registry=0; firewall=0; processes=0; tools=0 }
$Def = @{ os=1; network=1; services=1; tasks=1; startup=1; registry=1; firewall=1; processes=1; tools=1 }
foreach ($s in $Env) {
    $v = (Get-Item "Env:$($s)" -ErrorAction SilentlyContinue).Value
    if ($v -match '^[01]$') { $Sec[$s.Split('_')[1].ToLower()] = [bool][int]$v }
    else { $Sec[$s.Split('_')[1].ToLower()] = $Def[$s.Split('_')[1].ToLower()] }
}

$lines = New-Object System.Collections.Generic.List[string]
$wc    = New-Object System.Text.StringBuilder

function Add-Log  { param([string]$s); $lines.Add($s) | Out-Null }
function Add-HR   { param([string]$s); $lines.Add($s) | Out-Null }
function gb     { param([long]$b) [math]::Round([long]$b / 1073741824, 1) }
function Log-OK   { param([string]$n, [string]$x); Add-Log "  [OK]   $n   $x" }
function Log-WARN { param([string]$n, [string]$x); Add-Log "  [WARN] $n   $x" }
function Log-NOTE { param([string]$n, [string]$x); Add-Log "  [NOTE] $n   $x" }

# Trusted (system/program) directories for path triage.
$Trusted = @(
    "C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Windows\",
    "C:\Program Files\", "C:\Program Files (x86)\", "C:\ProgramData\"
)
function Test-TrustedPath {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    foreach ($r in $Trusted) {
        if ($Path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Resolve a process owner SID to a username.
function Get-UserFromSid {
    param([string]$Sid)
    if ([string]::IsNullOrEmpty($Sid)) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).ToString() } catch { return $Sid }
}

# Map a PID to its executable image path.
function Get-PathForPid {
    param([int]$ProcId)
    if ($ProcId -le 0) { return $null }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
    if ($p) {
        if ($p.ExecutablePath -and [string]::IsNullOrWhiteSpace($p.ExecutablePath) -eq $false) { return $p.ExecutablePath }
    }
    try {
        $g = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
        if ($g -and $g.Path) { return $g.Path }
    } catch { }
    return $null
}

# Resolve a port to a well-known service name (from embedded map; fallback empty).
function Get-ServiceForPort {
    param([int]$Port)
    if ($Port -le 0) { return $null }
    $p = $env:windir
    # small embedded map (top common services); extend as needed
    $map = @{
        21="ftp";22="ssh";23="telnet";25="smtp";53="dns";67="dhcp";68="bootps";69="tftp"
        80="http";110="pop3";111="sunrpc";113="auth";143="imap";161="snmp";194="irc"
        443="https";445="smb";587="smtps";993="imaps";995="pop3s";1433="ms-sql-s";1434="ms-sql-m"
        3389="rdp";5985="winrm";5986="winrm-ssl";8080="http-proxy";8443="https-alt"
        9389="adws";10000="amanda";1025="epmap";27015="game";27036="game";2375="docker"
        2376="docker";6112="game"
    }
    if ($map[$Port]) { return $map[$Port] }
    return $null
}

# ---- write the report + exports ----
function Write-Report {
    $md = ($lines | Out-String -Width 120).TrimEnd() + "`n"
    $md | Set-Content -Path $Report -Encoding UTF8 -Force
    Write-Host "[SysDiag] Markdown report: $Report" -ForegroundColor Cyan

    if ($env:SYSDIAG_FORMAT -eq 'html') {
        $esc = $md -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
        $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{font-family:'Segoe UI',system-ui,sans-serif;color:#111;max-width:980px;margin:0 auto;padding:20px;background:#f5f6f8}
h1{color:#0b5cad} h2{color:#0b5cad} h3{color:#333} hr{border:0;border-top:1px solid #ccc}
table{border-collapse:collapse;width:100%;background:#fff;margin:8px 0} td,th{border:1px solid #ddd;padding:6px 8px}
th{background:#e8eef4;text-align:left} pre{background:#f4f6f8;padding:10px 14px;border-radius:4px}
.ok{background:#e6f4ea;color:#1a7f37} .warn{background:#fff4e5;color:#b26a00} .note{background:#e8f0fe;color:#1a4fa5}
</style></head><body><h1>SysDiag report</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm (zzz)') &middot; $env:COMPUTERNAME / $env:USERNAME</p>
<hr/><pre class="markdown">$esc</pre></body></html>
"@
        $html | Set-Content -Path ($Report -replace '\.md$','.html') -Encoding UTF8 -Force
        Write-Host "[SysDiag] HTML report: $($Report -replace '\.md$','.html')" -ForegroundColor Cyan
    }

    # Export startup/registry autoruns to a .reg file.
    $reg = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"
    )
    $regOut = "Windows Registry Editor Version 5.00`n" +
              "; SysDiag - exported startup/launch entries`n" +
              "; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm (zzz)')`n`n"
    foreach ($k in $reg) {
        $base = if ($k -match '^HKCU:') { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
        $sub  = $k -replace '^HKCU:','' -replace '^HKLM:',''
        $rk = $base.OpenSubKey($sub)
        if ($rk) {
            foreach ($n in $rk.GetValueNames()) {
                $key = $n -replace '"','\"'
                $val = $rk.GetValue($n) -replace '"','\"'
                $regOut += "`"$key`"`=`"$val`"`n"
            }
            try { $rk.Close() } catch { }
        }
    }
    $regOut | Set-Content -Path ($Report -replace '\.md$','.reg') -Encoding UTF8 -Force
    Write-Host "[SysDiag] Registry export: $($Report -replace '\.md$','.reg')" -ForegroundColor Cyan
}

try {
    # 1. OS / Boot / HARDWARE
    if ($Sec['os']) {
        $os  = Get-CimInstance Win32_OperatingSystem
        $cp  = @(Get-CimInstance Win32_Processor)
        $disk= Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        Add-Log "=== 1. OS / Boot / Hardware ==="
        Add-Log "Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm (zzz)')"
        Add-Log "OS        : $($os.Caption) | Build $($os.Version)"
        Add-Log "Hostname  : $env:COMPUTERNAME | User: $env:USERNAME"
        Add-Log "Boot      : $($os.LastBootUpTime)  (uptime ~$((Get-Date) - $os.LastBootUpTime))"
        Add-Log "RAM       : $(gb ($os.TotalVisibleMemorySize * 1024)) GB total / $(gb ($os.FreePhysicalMemory * 1024)) GB free"
        $numCPU = if ($cp) { ($cp | Select-Object -First 1).NumberOfLogicalProcessors } else { 0 }
        Add-Log "CPU       : $numCPU logical processors"
        Add-Log "Disk (C:) : $(gb $disk.Size) GB total / $(gb $disk.FreeSpace) GB free"
    }

    # 2. NETWORK listeners
    if ($Sec['network']) {
        Add-Log ""
        Add-Log "=== 2. Network listeners ==="
        Add-Log "  TCP listening ports:"
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
        $tcpid     = @($listeners | Where-Object { $_.OwningProcess -gt 0 }).OwningProcess
        $tcpid     = @($listeners | ForEach-Object { $_.OwningProcess })  # raw list, keep order
        foreach ($l in $listeners) {
            $exe = Get-PathForPid $l.OwningProcess
            $svc = Get-ServiceForPort $l.LocalPort
            $desc = if ($exe) { Split-Path $exe -Leaf } elseif ($l.OwningProcess -eq 0) { "(kernel/system)" } else { "(no owner)" }
            Add-Log "    TCP  $($l.LocalAddress):$($l.LocalPort)  service='$($svc)'  pid=$($l.OwningProcess)  $desc"
        }
        $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
        $udpCount = @($udp).Count
        if ($udpCount -gt 0) {
            Add-Log "  UDP endpoints ($udpCount):"
            foreach ($u in $udp[0..10]) {
                $exe = Get-PathForPid $u.OwningPid
                $desc = if ($exe) { Split-Path $exe -Leaf } else { "(no owner)" }
                Add-Log "    UDP  $($u.LocalAddress):$($u.LocalPort)  pid=$($u.OwningPid)  $desc"
            }
        } else {
            Add-Log "  UDP endpoints: (none)"
        }
        Add-Log "  Interfaces:"
        Get-CimInstance Win32_NetworkAdapterConfiguration | Where { $_.IPEnabled } |
            Select-Object Description, IPAddress | Format-Table -AutoSize |
            Out-String | ForEach-Object { Add-Log "    $_" }
    }

    # 3. SERVICES — only auto-start services that are stopped are meaningful.
    if ($Sec['services']) {
        Add-Log ""
        Add-Log "=== 3. Services ==="
        $svc = @(Get-CimInstance Win32_Service)
        $running = @($svc | Where-Object { $_.State -eq 'Running' })
        $stopped = @($svc | Where-Object { $_.State -ne 'Running' })
        Add-Log "  Running : $($running.Count) of $($svc.Count)"
        $autoStopped = @($stopped | Where-Object { $_.StartMode -eq 'Auto' })
        if ($autoStopped.Count -eq 0) {
            Add-Log "  Stopped : (none of the auto-start services are stopped)"
        } else {
            Add-Log "  Stopped : $($autoStopped.Count) auto-start service(s) stopped (see flag column)"
            foreach ($s in $autoStopped) {
                Add-Log "    [WARN] $($s.Name)  displayname=' $($s.DisplayName)'  state='Stop'  startmode='Auto'"
            }
        }
    }

    # 4. SCHEDULED TASKS (logon-triggered flag)
    if ($Sec['tasks']) {
        Add-Log ""
        Add-Log "=== 4. Scheduled tasks ==="
        try {
            $tasks = @(Get-ScheduledTask -ErrorAction Stop)
            Add-Log "  Count: $($tasks.Count)"
            foreach ($t in $tasks) {
                $path = if ($t.TaskPath) { $t.TaskPath } else { "" }
                $atLogon = @($t.Principals) | Where-Object { $_.RunLevel -eq 'Highest' } | ForEach-Object { $_.LogonType } | Select-Object -First 1
                if ($atLogon -match 'InteractiveToken' -or $t.Settings.RunOnlyIfLoggedIn -eq $true) {
                    Add-Log "    [NOTE] $($t.TaskName)  path='$path'  (logon-triggered)"
                } else {
                    Add-Log "    $t.TaskName  path='$path'"
                }
            }
        } catch { Add-Log "  Could not enumerate scheduled tasks: $Error[0]" }
    }

    # 5. PERSISTENCE (startup folders + registry autoruns + logon tasks)
    if ($Sec['startup'] -or $Sec['registry']) {
        Add-Log ""
        Add-Log "=== 5. Persistence ==="
        if ($Sec['startup']) {
            Add-Log "  Startup folders:"
            $userStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            $allStartup  = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
            foreach ($d in $userStartup, $allStartup) {
                if (Test-Path $d) {
                    Get-ChildItem $d -ErrorAction SilentlyContinue |
                        Select-Object Name, LastWriteTime | Format-Table -AutoSize |
                        Out-String | ForEach-Object { Add-Log "    $_" }
                } else { Add-Log "    ($d - empty)" }
            }
        }
        if ($Sec['registry']) {
            Add-Log "  Registry autoruns:"
            $regKeys = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"
            )
            foreach ($k in $regKeys) {
                $base = if ($k -match '^HKCU:') { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
                $sub  = $k -replace '^HKCU:','' -replace '^HKLM:',''
                $rk = $base.OpenSubKey($sub)
                if ($rk) {
                    $names = $rk.GetValueNames()
                    if ($names.Count -eq 0) { Add-Log "    [$k] (empty)" }
                    else {
                        foreach ($n in $names) {
                            $val = $rk.GetValue($n)
                            $flag = ""
                            if ($val -and $n -match '\.exe') {
                                $exe = $val
                                if ($exe -match '^\s*"(?<p>[^"]+\.exe)' -and $Matches.p -notmatch 'C:\\Windows|\\Program Files|C:\\ProgramData') {
                                    $flag = "  [NOTE] unusual location"
                                }
                            }
                            Add-Log "    [$k] $n = $val$flag"
                        }
                    }
                    $rk.Close()
                } else { Add-Log "    [$k] (empty)" }
            }
        }
    }

    # 6. FIREWALL
    if ($Sec['firewall']) {
        Add-Log ""
        Add-Log "=== 6. Firewall (profiles) ==="
        try {
            Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
                Format-Table -AutoSize | Out-String | ForEach-Object { Add-Log "    $_" }
        } catch { Add-Log "    Could not read firewall: $Error[0]" }
    }

    # 7. PROCESSES (full, with owner, memory, risk)
    if ($Sec['processes']) {
        Add-Log ""
        Add-Log "=== 7. Processes (review) ==="
        Add-Log "  PID   Name                 User               Session  Memory(MB)  ImagePath"
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        if ($procs.Count -eq 0) { Add-Log "  (none)" }
        foreach ($p in $procs | Sort-Object ProcessId) {
            $procId = [int]$p.ProcessId
            $pidStr = $procId.ToString().PadRight(7)
            $name   = if ($p.Name) { $p.Name } else { "(unknown)" }
            $path   = Get-PathForPid $procId
            $exe    = if ($path) { Split-Path $path -Leaf } else { "(no path)" }
            $user   = Get-UserFromSid $p.OwnerSID
            # memory in MB via the .NET Process API (single scalar, safe)
            $memMB  = 0
            try {
                $po = [System.Diagnostics.Process]::GetProcessById($procId)
                if ($po -ne $null) { $memMB = [int]($po.WorkingSet64 / 1048576) }
            } catch { $memMB = 0 }
            $flag = ""
            if ($path -and -not (Test-TrustedPath $path)) {
                $flag = "  [NOTE] unusual location"
            } elseif ($name -in @("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","scrcons.exe","control.exe") -and $path) {
                $base = Split-Path $path -Leaf
                if (-not (Test-TrustedPath $path) -or $base -notin @("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","scrcons.exe","control.exe")) {
                    $flag = "  [NOTE] common persistence name"
                }
            }
            Add-Log "  $pidStr $(if ($name) { $name.PadRight(20) })$(if ($user) { $user.PadRight(18) })$(if ($path) { $exe.PadRight(14) })$memMB$flag"
        }
        Add-Log "  Review total: see flag column (note: [NOTE] = reason shown per row)"
    }

    # 8. TOOL-SPECIFIC status
    if ($Sec['tools']) {
        Add-Log ""
        Add-Log "=== 8. Tool-specific status ==="
        try {
            $c = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/version" -UseBasicParsing -ErrorAction Stop
            Log-OK "Ollama" "API ok ($( $c.Content.Trim() ))"
        } catch { Log-WARN "Ollama" "API not reached: $Error[0]" }
        $wsl = wsl.exe -l -v 2>$null
        if ($wsl -match "Running") { Log-OK "WSL2 (distros)" "(host running)" }
        else { Log-WARN "WSL2 (distros)" "host running; no Running distro" }
        $ds = Get-Service "com.docker.service" -ErrorAction SilentlyContinue
        if ($ds) { if ($ds.Status -eq 'Running') { Log-OK "Docker engine" "Service: $($ds.Status)" } else { Log-WARN "Docker engine" "Service: $($ds.Status)" } }
        else { Log-WARN "Docker engine" "service not found / stopped" }
        try {
            $l = Get-NetTCPConnection -LocalPort 2121 -ErrorAction Stop
            $exe = Get-PathForPid $l.OwningProcess
            $desc = if ($exe) { Split-Path $exe -Leaf } else { "(unknown)" }
            Log-OK "lanfile-tool" "port 2121 -> $desc"
        } catch { Log-WARN "lanfile-tool" "port 2121 not listening" }
        try {
            $t = Get-ScheduledTask -TaskName "Hermes_Gateway" -ErrorAction Stop
            Log-OK "Hermes gateway task" "state $($t.State)"
        } catch { Log-WARN "Hermes gateway task" "scheduled task not found" }
    }

    # 9. FINDINGS / analysis (delegated to the Python GUI layer).
    #     This engine writes a clean raw report; the Python layer parses it and
    #     adds Suggested Issues. The engine itself stays deterministic and fast.
    Add-Log ""
    Add-Log "=== 9. End of report ==="
    Add-Log "  Generated by SysDiag engine. Analysis layer: sysdiag_gui.py."
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack: $($_.Exception.ToString())" -ForegroundColor Red
    $lines | Out-String -Width 120 | ForEach-Object { $wc.Append($_) | Out-Null }
    $wc.ToString() | Set-Content -Path $Report -Encoding UTF8 -Force
    Write-Host "[SysDiag] Report (partial) written to: $Report" -ForegroundColor Cyan
} Finally {
    Write-Report
}
