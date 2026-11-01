# SysDiag — Windows system health-check tool

A self-contained, one-shot Windows diagnostics tool: a **PowerShell engine**
(`sysdiag.ps1`) that snapshots OS / CPU / RAM / disk / network / services /
persistence (startup, registry autoruns, scheduled tasks) / firewall /
running processes, plus a **Python + Tkinter GUI** (`sysdiag_gui.py`) that runs
the engine, inspects the results, and flags possible issues / malware.

Written for internal dev use only. No public distribution.

---

## Folder contents

| File | Role |
|---|---|
| `sysdiag.ps1` | The engine. Runs the diagnostics and writes reports. |
| `sysdiag_gui.py` | The GUI front-end (Python + Tkinter, stdlib only). |
| `references/ports.json` | TCP/UDP port → well-known service map (used for port analysis). |
| `references/baselines.json` | Clean-Windows-11 reference data: normal ports, services, suspicious ports, startup entries, common persistence names. |
| `gen_ports.py` | (Old generator) used to build ports.json. Can be deleted if you do not need to regenerate. |
| `README.md` | This file. |

---

## How to run

### 1. From PowerShell (engine only)

```powershell
# One full scan -> Markdown + HTML + .reg export into a report folder
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\path\to\Sysset\sysdiag.ps1

# Limit to specific sections (all others skipped)
SYSDIAG_OS=1 SYSDIAG_NETWORK=1 SYSDIAG_SERVICES=1 SYSDIAG_TASKS=0 SYSDIAG_REGISTRY=0 powershell.exe -File C:\path\to\Sysset\sysdiag.ps1

# Choose output format/folder/report name
SYSDIAG_OUTDIR=C:\temp\reports SYSDIAG_FORMAT=html SYSDIAG_REPORTNAME=20261031 powershell.exe -File C:\path\to\Sysset\sysdiag.ps1
```

### 2. From the GUI (graphical, easy use)

```cmd
python C:\path\to\Sysset\sysdiag_gui.py
```

or (if Python is not on `PATH`):

```cmd
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\Sysset\sysdiag_gui.py"
```

The window shows:
- **Run** button, one checkbox per diagnostic section (OS, Network, Services,
  Tasks, Startup, Registry, Firewall, Processes, Tool-status).
- Output format selector (Markdown / Plain text / HTML).
- Output folder + report-name fields.
- **Compare with last scan** (diff the two most recent scans).
- **Save Copy…**, **Open report folder**, **Open last scan**.
- A report viewer (the scan results).
- A **Suggested Issues** panel (analysis layer — see below).
- A status bar.

---

## Features

- **Section gating** — run only what you need. The GUI checkboxes correspond to
  `SYSDIAG_<SECTION>`.
- **Three output formats** — Markdown (default), plain text (`txt`), HTML.
- **Registry autorun export** — saves `HKCU/HKLM\...\Run`, `RunOnce`, `RunServices`
  to a `.reg` file (useful for auditing startup entries).
- **Process review** — shows PID, process name, image path, owner, session and
  working-set size for every running process; flags unusual image locations and
  common persistence names (cmd.exe, powershell.exe, rundll32.exe, regsvr32.exe,
  etc.).
- **Port analysis** — maps every listening port to a well-known service, flags
  unrecognized high-port listeners and ports in the suspicious list.
- **Service review** — flags auto-start services that are stopped.
- **Persistence review** — startup folders plus registry `Run`/`RunOnce`/
  `RunServices` entries, with unusual-location flags.
- **Snapshot comparison** — the **Compare** button diffs the two most recent scans
  for new/removed TCP listeners, service-count changes and process-review changes.
- **Suggested Issues (analysis layer)** — after a scan, the tool parses the report
  against `references/baselines.json` and lists suggested issues:
  - suspicious ports (known-malware port list),
  - unknown-service high-port listeners,
  - unusual process locations,
  - persistence-name processes (cmd.exe, powershell.exe, rundll32.exe, regsvr32.exe…),
  - auto-start services that are stopped,
  - unusual registry autorun entries.
- **Timestamped report history** — each run writes a new
  `sysdiag_YYYYMMDD_HHMM.md` (+`.html`, `+.reg`).
- **Path normalization** — accepts bash/MSYS paths (`/c/Users/x`) and converts
  them to native `C:\Users\x`.

## Security findings format

The analysis layer reports findings with a severity level so the report reads
like a security briefing instead of a log dump:

- **HIGH** — likely malicious or an immediate action item.
  (`Malware often listens on port 4444 to receive commands. A clean Windows 11
  does not use this port. Check what program is running on it.`)
- **MEDIUM** — worth reviewing (may be legitimate but verify).
  (`Service "X" is set to start automatically but is stopped. A protection
  service that should launch at boot is not running — check if it was disabled.`)
- **LOW** — informational; normal for many environments.
  (`Program "X" runs from an unusual location. Normal Windows apps are in
  C:\Windows\System32 or C:\Program Files. This may be malware or a developer
  tool — check it is legitimate.`)

Every finding is written as a short, plain-language sentence so a user who does
not know PIDs or services can still understand what was found and why.

## Reference baseline (`references/baselines.json`)

The analysis layer compares the current scan against this "clean Windows 11"
reference so a fresh install gives a known-good starting point. It records the
ports, services, startup entries and persistence names that are normal for a
typical Windows 11 PC, plus the suspicious ports and names to watch for:

- `expected_ports` — TCP/UDP ports considered normal for a fresh Windows 11
  (443, 445, 135, 389, 5985, 5986, DNS, SMB, RDP, WinRM, etc.).
- `normal_services` — service names expected to run (auto / domain).
- `suspicious_ports` — ports commonly used by malware / tunnelling
  (4444, 5555, 6667, 7777, 31337, 27015/27036, etc.).
- `normal_startup` — common legitimate startup entries.
- `suspicious_exes` — executable names frequently used for persistence
  (cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, regsvr32.exe,
  rundll32.exe, certutil.exe, scrcons.exe, forfiles.exe, …).

Keep this file up to date as the user's environment changes; new legitimate apps
can be added to `normal_startup`.

- Section gating is driven by environment variables (`SYSDIAG_*`), so the GUI
  can steer the engine without touching argument parsing.
- The engine uses `Microsoft.Win32.Registry` (not `reg query`, which prints
  `ERROR: Invalid key name` for missing keys), with `Test-Path` guards.
- `$pid`/`$PID` are never reassigned (read-only built-ins); helper variables use
  `$procId` / `$procIdStr`.
- No `param()` defaults that depend on `$MyInvocation` / `$PSScriptRoot` under
  `-File`; defaults fall back to `$PSScriptRoot` then `$env:USERPROFILE`.
- HTML is produced by escaping `&`, `<`, `>` before embedding.
- The `.reg` export encodes key/value names and values with escaped quotes.
- Only the stdlib is required on the GUI side (Python 3.7+, Tkinter). The engine
  itself is pure PowerShell (5.1+) with no third-party modules.

## Portability

- **Engine**: Windows-only. It relies on native Windows APIs (CIM/WMI,
  `Microsoft.Win32.Registry`, `Get-NetTCPConnection`, `Get-Service`,
  `Get-ScheduledTask`, `netstat`, `wsl.exe`). Runs on Windows 10 and 11 with
  PowerShell 5.1+ preinstalled.
- **GUI**: cross-platform (Python + Tkinter). Runs on Windows, macOS, or Linux,
  but the engine will raise for the actual diagnostics on non-Windows.
- The tool stores no secrets and no machine-specific constants. The default
  report folder is `%LOCALAPPDATA%\sysdiag_reports` (configurable; the GUI
  remembers it). Nothing is hardcoded to this machine.

## Reference baseline (`references/baselines.json`)

The analysis layer compares the current scan against this "clean Windows 11"
reference:

- `expected_ports` — ports considered normal for a typical Windows 11 PC.
- `normal_services` — service names expected to run (auto/domain).
- `suspicious_ports` — ports commonly associated with malware / tunnelling
  (4444, 5555, 6667, 7777, 31337, 27015/27036, etc.).
- `normal_startup` — common legitimate startup entries.
- `suspicious_exes` — executable names frequently used for persistence
  (cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, regsvr32.exe,
  rundll32.exe, scrcons.exe, control.exe, forfiles.exe, …).

Keep this file up to date as the user's environment changes; new legitimate apps
can be added to `normal_startup`.

## Troubleshooting

- **No `powershell.exe`** — use the full path shown above, or rely on
  `find_powershell()` in the GUI.
- **Engine reports nothing** — run with `-ExecutionPolicy Bypass` and `-File`
  (not by double-clicking the `.ps1`).
- **GUI window looks frozen during a scan** — normal; the engine runs in a
  thread. Wait a few seconds for the report to appear in the viewer and files.
- **HTML renders with lost markup** — the report is embedded in a `<pre>`; use
  the `.md` source for full fidelity, or open the `.html` in a browser for a
  styled view.
- **Too many "stopped service" warnings** — Windows separates system services
  into per-user hosts; most are `Manual` or `Disabled` by design. The
  Suggested-Issues layer only flags *auto-start* services that are stopped.
