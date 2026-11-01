#!/usr/bin/env python3
r"""
SysDiag GUI - a small, self-contained Windows diagnostic front-end.

Wraps the `sysdiag.ps1` PowerShell engine (Windows-only; no user-specific path).
and exposes options:
  * which report sections to scan (OS, Network, Services, Tasks, Startup,
    Registry, Firewall, Processes, Tool-status),
  * output format            (Markdown / Text / HTML),
  * where to save reports,
  * snapshot compare against the previous scan.

Requires Python 3.7+ (standard library only). Run with:
    python sysdiag_gui.py
"""

import json
import os
import datetime
import queue
import shutil
import subprocess
import sys
import threading
import traceback
from pathlib import Path
import uuid

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
except ImportError:  # pragma: no cover
    sys.stderr.write("Tkinter is not available.\n")
    sys.exit(1)

# --------------------------------------------------------------------------- #
# Paths & constants
# --------------------------------------------------------------------------- #
SCRIPT_DIR = Path(__file__).resolve().parent
ENGINE = SCRIPT_DIR / "sysdiag.ps1"
CONFIG_FILE = SCRIPT_DIR / "sysdiag_gui.cfg"

DEFAULT_REPORT_DIR = Path(
    os.environ.get("LOCALAPPDATA", Path.home())) / "sysdiag_reports"

# Default section selections (keys match the engine's SYSDIAG_* names).
DEFAULT_SECTIONS = {
    "os": 1, "network": 1, "services": 1, "tasks": 1,
    "startup": 1, "registry": 1, "firewall": 1, "processes": 1, "tools": 1,
}
OUTPUT_FORMATS = [
    ("Markdown (*.md)", "md"),
    ("Plain text (*.txt)", "txt"),
    ("HTML (*.html)", "html"),
]

# GUI label -> engine section key
SECTION_MAP = [
    ("OS", "os"),
    ("Network", "network"),
    ("Services", "services"),
    ("Tasks", "tasks"),
    ("Startup", "startup"),
    ("Registry", "registry"),
    ("Firewall", "firewall"),
    ("Processes", "processes"),
    ("Tools", "tools"),
]

# --------------------------------------------------------------------------- #
# Configuration (persisted across runs)
# --------------------------------------------------------------------------- #
def load_config():
    cfg = {
        "sections": dict(DEFAULT_SECTIONS),
        "format": "md",
        "report_dir": str(DEFAULT_REPORT_DIR),
        "last_compare_a": None,
        "last_compare_b": None,
        # scheduler
        "startup": False,
        "sched_every": 0,          # minutes (0 = off)
        "sched_daily": "",         # HH:MM (empty = off)
        "last_run": None,
    }
    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except (json.JSONDecodeError, OSError):
            pass
    cfg["sections"] = {k: bool(int(v)) for k, v in cfg["sections"].items()}
    cfg["report_dir"] = Path(cfg["report_dir"]).expanduser()
    cfg["sched_every"] = int(cfg.get("sched_every") or 0)
    cfg["sched_daily"] = str(cfg.get("sched_daily") or "")
    return cfg


def save_config(cfg):
    # JSON can't serialize Path objects; normalize before saving.
    cfg = {k: (str(v) if isinstance(v, Path) else v) for k, v in cfg.items()}
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# The diagnostic engine (PowerShell sysinfo script)
# --------------------------------------------------------------------------- #
def find_powershell():
    """Return a path to a working PowerShell executable, or None."""
    candidates = [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\PowerShell\v1.0\powershell.exe",
        "powershell.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.isfile(os.path.join(d, "powershell.exe")):
            return os.path.join(d, "powershell.exe")
    return None


def run_engine(sections, fmt, outdir, reportname, engine_ps1):
    """Run the PowerShell diagnostic engine. Returns (report_text, error)."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SYSDIAG_OS"] = "1" if sections["os"] else "0"
    env["SYSDIAG_NETWORK"] = "1" if sections["network"] else "0"
    env["SYSDIAG_SERVICES"] = "1" if sections["services"] else "0"
    env["SYSDIAG_TASKS"] = "1" if sections["tasks"] else "0"
    env["SYSDIAG_STARTUP"] = "1" if sections["startup"] else "0"
    env["SYSDIAG_REGISTRY"] = "1" if sections["registry"] else "0"
    env["SYSDIAG_FIREWALL"] = "1" if sections["firewall"] else "0"
    env["SYSDIAG_PROCESSES"] = "1" if sections["processes"] else "0"
    env["SYSDIAG_TOOLS"] = "1" if sections["tools"] else "0"
    env["SYSDIAG_FORMAT"] = fmt
    env["SYSDIAG_OUTDIR"] = str(outdir)
    env["SYSDIAG_REPORTNAME"] = reportname

    # Remove any stale report so we can detect a failed run.
    stale = outdir / (reportname + ".md")
    if stale.exists():
        try:
            stale.unlink()
        except OSError:
            pass

    exe = find_powershell()
    proc = subprocess.run(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(engine_ps1)],
        env=env, capture_output=True, text=True, timeout=180,
    )
    report_path = outdir / (reportname + ".md")
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
        return report_text, None
    err = (proc.stderr or proc.stdout or "").strip() or "Engine did not produce a report file."
    return None, err


# --------------------------------------------------------------------------- #
# Snapshot comparison (diffs the two most recent scans)
# --------------------------------------------------------------------------- #
def _grab_lines(path, key):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if key == "listeners":
        return [ln for ln in lines if ln.startswith("  TCP  ")]
    if key == "services":
        block, in_svc = [], False
        for ln in lines:
            if ln.startswith("=== 3."):
                in_svc = True
            if in_svc:
                block.append(ln)
                if ln.startswith("=== 4."):
                    break
        return block
    if key == "processes":
        block, in_pr = [], False
        for ln in lines:
            if ln.startswith("=== 7."):
                in_pr = True
            if in_pr:
                block.append(ln)
                if ln.startswith("=== 8."):
                    break
        return block
    return []


def _svc_delta(left, right):
    out = []
    a_running = next((ln for ln in left if ln.startswith("Running :")), "Running : ?")
    b_running = next((ln for ln in right if ln.startswith("Running :")), "Running : ?")
    try:
        a_n = int(a_running.split(":")[1].split("of")[0].strip())
        b_n = int(b_running.split(":")[1].split("of")[0].strip())
        delta = b_n - a_n
        out.append("Running services: {} -> {} ({} {})".format(a_n, b_n, "+" if delta >= 0 else "-", abs(delta)))
    except Exception:
        out.append("Running services: could not parse")
    return "\n".join(out)


def diff_scans(a_path, b_path):
    """Return a short human-readable summary of what changed between two scans."""
    a_path = Path(a_path)
    b_path = Path(b_path)
    if not a_path.exists() or not b_path.exists():
        return "Could not compare: missing report file(s)."
    try:
        left = {
            "listeners": _grab_lines(a_path, "listeners"),
            "services": _grab_lines(a_path, "services"),
            "processes": _grab_lines(a_path, "processes"),
        }
        right = {
            "listeners": _grab_lines(b_path, "listeners"),
            "services": _grab_lines(b_path, "services"),
            "processes": _grab_lines(b_path, "processes"),
        }
        parts = [_diff_block("TCP listeners", left["listeners"], right["listeners"]),
                 _diff_block("Running services", left["services"], right["services"]),
                 _diff_block("Review entries (processes)", left["processes"], right["processes"]),
                 _svc_delta(left["services"], right["services"])]
        return "\n".join(p for p in parts if p)
    except Exception as e:
        return "Comparison failed: {}".format(e)


# --------------------------------------------------------------------------- #
# Analysis & "suggested issues" layer
# --------------------------------------------------------------------------- #
def load_ports():
    """Load the port->service map from references/ports.json."""
    p = SCRIPT_DIR / "references" / "ports.json"
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def load_baselines():
    """Load the clean-Windows reference data from references/baselines.json."""
    p = SCRIPT_DIR / "references" / "baselines.json"
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _parse_listeners(text):
    """Return [(addr, port, service, pid, desc, owner_path, flag), ...] for TCP rows."""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("TCP") and ": " in s:
            parts = s.split("  ")
            if len(parts) >= 4:
                addr_port = parts[1].rsplit(":", 1)[-1] if len(parts) > 1 else ""
                service = desc = ""
                pid = "-"
                flag = ""
                # TCP  address:port  service='X'  pid=Y  desc
                # address:port may contain a space for IPv6 (::1)
                if "service='" in s:
                    svc_part = s.split("service='")[1].split("'")[0]
                    service = svc_part
                    if "pid=" in s:
                        pid_s = s.split("pid=")[1].split()[0]
                        pid = pid_s
                if "  " in s:
                    rest = s.split("  ", 3)[-1] if s.count("  ") >= 3 else ""
                    if rest:
                        desc = rest
                out.append((addr_port, parts[0], service, pid, desc, flag))
    return out


def _process_rows(report_text):
    """Yield (pid, name, exe, mem, flag) for each process review row."""
    rows = []
    in_pr = False
    for ln in report_text.splitlines():
        if ln.strip().startswith("=== 7."):
            in_pr = True
            continue
        if in_pr and ln.strip().startswith("=== 8."):
            break
        if not in_pr:
            continue
        s = ln.strip()
        if not s:
            continue
        if s.startswith("Review"):
            continue
        # process rows start with the pid number
        if not (s[0].isdigit() or (s.startswith("  ") and s[2:].split()[0].isdigit())):
            continue
        parts = s.split()
        pid = parts[0]
        if not pid.isdigit():
            continue
        # memory is a bare number; flag tokens start with '['
        mem_idx = None
        for i in range(1, len(parts)):
            if parts[i].isdigit():
                mem_idx = i
                break
        exe = None
        if mem_idx is not None:
            exe = parts[mem_idx - 1]
        flag = " ".join(t for t in parts if t.startswith("[")).strip()
        rows.append((pid, parts[1] if len(parts) > 1 else "", exe, mem_idx is not None, flag))
    return rows


def analyze_report(report_text, ports=None, baselines=None):
    """Return a list of (severity, category, explanation) suggested issues.

    severity is one of HIGH / MEDIUM / LOW so the report is easy to read:
      HIGH  - likely malicious or an immediate action item
      MEDIUM- worth reviewing (may be legitimate but verify)
      LOW   - informational; normal for many environments
    """
    ports = load_ports() if ports is None else ports
    baselines = load_baselines() if baselines is None else baselines
    susp_ports = baselines.get("suspicious_ports", [])
    suspicious_exes = [e.lower() for e in baselines.get("suspicious_exes", [])]
    susp_port_set = set(str(p) for p in susp_ports)

    # trusted paths (system / program files) for triage
    trusted = [
        "C:\\WINDOWS\\SYSTEM32", "C:\\WINDOWS\\SYSWOW64", "C:\\WINDOWS\\",
        "C:\\PROGRAM FILES\\", "C:\\PROGRAM FILES (X86)\\", "C:\\PROGRAMDATA\\",
    ]

    def in_trusted(path):
        if not path:
            return True
        p = path.upper()
        return any(p.startswith(t) for t in trusted)

    findings = []

    # ---- 1. network listeners ----
    for ln in report_text.splitlines():
        s = ln.strip()
        if s.startswith("TCP") and "pid=" in s:
            parts = s.split()
            addr_port = parts[1] if len(parts) > 1 else ""
            port_s = addr_port.rsplit(":", 1)[-1]
            service = ""
            if "service='" in s:
                service = s.split("service='")[1].split("'")[0]
            if port_s in susp_port_set:
                findings.append(("HIGH", "Port",
                    "Malware often listens on port {} to receive commands. A clean Windows 11 does not use this port - check what program is running on it.".format(port_s)))
                continue
            if port_s.isdigit() and int(port_s) > 49151 and not service:
                owner = ln.split("pid=")[-1].split()[0] if "pid=" in ln else "?"
                findings.append(("HIGH", "Port",
                    "Port {} is open but has no known service attached. This can be a tunnel or proxy used by malware - verify the program running on that port.".format(addr_port)))
    # ---- 2. processes ----
    for pid, name, exe, has_mem, flag in _process_rows(report_text):
        if exe in (None, "(no path)", "(kernel/system)", "(no owner)"):
            continue
        fl = flag.lower()
        if has_mem and flag:
            if "unusual" in fl:
                # unusual location: LOW for user tools (dev tools live outside system dirs)
                severity = "LOW" if in_trusted(exe) else "HIGH"
                findings.append((severity, "Process",
                    "Program '{}' runs from an unusual location (PID {}). Normal Windows apps are in C:\\Windows\\System32 or C:\\Program Files. This may be malware or a developer tool - check it is legitimate.".format(name, pid)))
            if "persistence" in fl:
                findings.append(("MEDIUM", "Persistence",
                    "A program with a common persistence name '{}' is running (PID {}). Names like cmd.exe, powershell.exe, and regsvr32.exe are used by malware. Verify this is a legitimate process.".format(name, pid)))
        elif exe and name.lower() in suspicious_exes:
            findings.append(("HIGH", "Persistence",
                "Suspicious program '{}' (PID {}) matches a known malware name list. Verify this is legitimate - it may be disguised malware.".format(name, pid)))
    # ---- 3. services ----
    in_svc = False
    for ln in report_text.splitlines():
        s = ln.strip()
        if s.startswith("=== 3."):
            in_svc = True
            continue
        if in_svc and s.startswith("=== 4."):
            break
        if in_svc and s.startswith("[WARN]") and "startmode='Auto'" in ln:
            name = s.split("  ")[0].replace("[WARN]", "").strip()
            findings.append(("MEDIUM", "Services",
                "Service '{}' is set to start automatically but is stopped. A protection service that should launch at boot is not running - check if it was disabled.".format(name)))
    # ---- 4. startup / registry autoruns ----
    in_reg = False
    for ln in report_text.splitlines():
        if "Registry autoruns" in ln:
            in_reg = True
            continue
        if in_reg and ln.strip().startswith("=== 6."):
            break
        if in_reg and ln.strip().startswith("    [NOTE]"):
            findings.append(("MEDIUM", "Persistence",
                "An unusual entry found in the registry 'Run' location. Malware often uses these to start itself when you log in - verify the entry is legitimate."))
    # ---- 5. summary ----
    high = [f for f in findings if f[0] == "HIGH"]
    med = [f for f in findings if f[0] == "MEDIUM"]
    low = [f for f in findings if f[0] == "LOW"]
    findings.insert(0, ("OK", "Summary",
                        "Suggested issues found: {} HIGH, {} MEDIUM, {} LOW (see rows below).".format(
                            len(high), len(med), len(low))))
    return findings


def format_findings(findings):
    out = ["\n=== 9. Suggested Issues (analysis) ==="]
    for sev, cat, msg in findings:
        if sev == "OK" and cat == "Summary":
            out.append("  [{}] {}  {}".format(sev, cat.upper(), msg))
        else:
            out.append("  [{}] {}  {}".format(sev, cat.upper(), msg))
    return "\n".join(out)


def _diff_block(title, before, after):
    b = set(before)
    a = set(after)
    out = [title + ":"]
    added = sorted(a - b)
    removed = sorted(b - a)
    if added:
        out.append("  NEW ({}):".format(len(added)))
        out += ["    + " + x for x in added]
    if removed:
        out.append("  REMOVED ({}):".format(len(removed)))
        out += ["    - " + x for x in removed]
    if not added and not removed:
        out.append("  no change")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
class SysDiagApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SysDiag")
        self.root.geometry("1000x740")
        self.root.minsize(760, 620)

        self.cfg = load_config()
        self.ui_q = queue.Queue()
        self.sections = dict(DEFAULT_SECTIONS)
        self.sections.update({k: bool(v) for k, v in self.cfg["sections"].items()})
        self.outdir = Path(self.cfg["report_dir"])
        self.format = self.cfg.get("format", "md")
        self.var_fmt = tk.StringVar(value=self.format)
        self.last_a = self.cfg.get("last_compare_a")
        self.last_b = self.cfg.get("last_compare_b")

        # scheduler / automation state
        self.var_startup = tk.BooleanVar(value=self.cfg.get("startup", False))
        self.var_sched_every_active = tk.BooleanVar(value=bool(self.cfg.get("sched_every", 0)))
        self.var_sched_every = tk.IntVar(value=int(self.cfg.get("sched_every") or 0))
        self.var_sched_daily = tk.StringVar(value=str(self.cfg.get("sched_daily") or ""))
        self.var_next_run = tk.StringVar(value="—")
        self._busy = False
        self._sched_job = None

        self._build_menu()
        self._build_options()
        self._build_output()
        self._build_buttons()
        self._build_status()
        self._drain_queue()
        self._refresh_output()

        # persist automation settings (startup / schedule)
        self.cfg["startup"] = bool(self.var_startup.get())
        self.cfg["sched_every"] = int(self.var_sched_every.get())
        self.cfg["sched_daily"] = str(self.var_sched_daily.get())
        save_config(self.cfg)

    # ------------------------------------------------------- menu / bar ---
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        filemen = tk.Menu(menubar, tearoff=0)
        filemen.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemen)
        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)

    def _build_options(self):
        pan = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        pan.pack(fill="x")

        ttk.Label(pan, text="Sections to scan:").grid(row=0, column=0, sticky="w", pady=2)
        # 3 columns x 3 rows for the 9 sections
        self.var_sections = {}
        for idx, (label, key) in enumerate(SECTION_MAP):
            row, col = divmod(idx, 3)
            var = tk.BooleanVar(value=self.sections.get(key, 1))
            self.var_sections[key] = var
            ttk.Checkbutton(pan, variable=var, text=label).grid(
                row=row + 1, column=col, sticky="w", padx=(12, 4), pady=1)
        ttk.Label(pan, text="(1 = include; 0 = exclude that section)").grid(
            row=4, column=0, columnspan=3, sticky="w", pady=1)

        ttk.Separator(pan, orient="vertical").grid(row=1, column=4, rowspan=4, padx=6)

        ttk.Label(pan, text="Output format:").grid(row=0, column=5, sticky="w", pady=2)
        for txt, val in OUTPUT_FORMATS:
            ttk.Radiobutton(pan, text=txt, variable=self.var_fmt, value=val).grid(
                row=1, column=5, sticky="w", pady=2)

        ttk.Label(pan, text="Report directory:").grid(row=2, column=5, sticky="w", pady=2)
        self.var_dir = tk.StringVar(value=str(self.outdir))
        ttk.Entry(pan, textvar=self.var_dir, width=34).grid(row=3, column=5, sticky="w", pady=2)
        ttk.Button(pan, text="Browse…", command=self._pick_dir).grid(row=3, column=6, padx=4)

        ttk.Label(pan, text="Report base name:").grid(row=4, column=5, sticky="w", pady=2)
        self.var_name = tk.StringVar(value="sysdiag_run")
        ttk.Entry(pan, textvar=self.var_name, width=34).grid(row=5, column=5, sticky="w", pady=2)
        ttk.Button(pan, text="Browse…", command=self._pick_name).grid(row=5, column=6, padx=4)

        # ─ schedule new analyzes ─
        ttk.Label(pan, text="Schedule:", style="Bold.TLabel").grid(row=7, column=0, columnspan=3, sticky="w", pady=(12, 2))
        self.var_sched_every_active = tk.BooleanVar(value=bool(self.cfg.get("sched_every", 0)))
        self.var_sched_daily_active = tk.BooleanVar(value=bool(self.cfg.get("sched_daily", "")))
        ttk.Checkbutton(pan, text="Repeat every N minutes", variable=self.var_sched_every_active,
                        command=self._start_scheduler).grid(row=8, column=0, sticky="w")
        self.var_sched_every = tk.IntVar(value=int(self.cfg.get("sched_every") or 0))
        ttk.Spinbox(pan, from_=0, to=120, textvariable=self.var_sched_every, width=6).grid(row=8, column=1, sticky="w", padx=4)
        ttk.Label(pan, text="(0 = off)").grid(row=8, column=2, sticky="w")
        self.var_sched_daily = tk.StringVar(value=str(self.cfg.get("sched_daily") or ""))
        ttk.Checkbutton(pan, text="Daily at HH:MM", variable=self.var_sched_daily_active,
                        command=self._start_scheduler).grid(row=9, column=0, sticky="w")
        ttk.Entry(pan, textvar=self.var_sched_daily, width=8).grid(row=9, column=1, sticky="w")
        ttk.Label(pan, text="Next run:").grid(row=10, column=0, sticky="w")
        self.var_next_run = tk.StringVar(value="—")
        ttk.Label(pan, textvar=self.var_next_run, foreground="#0b5cad").grid(row=10, column=1, sticky="w")

        # ─ startup (run at logon) ─
        self.var_startup = tk.BooleanVar(value=bool(self.cfg.get("startup", False)))
        ttk.Checkbutton(pan, text="Add to startup (run at logon)", variable=self.var_startup,
                        command=self._on_startup_toggle).grid(row=11, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(pan, text="(creates a startup batch file; --startup-only runs one scan)").grid(
            row=11, column=2, sticky="w", pady=(8, 0))

        pan.grid_columnconfigure(5, weight=1)

    def _build_output(self):
        box = ttk.PanedWindow(self.root, orient="vertical")
        box.pack(fill="both", expand=True, padx=8, pady=4)
        self.text = scrolledtext.ScrolledText(
            box, wrap="none", state="disabled", font=("Consolas", 9),
            relief="flat", background="#f4f6f8", foreground="#111")
        self.text.tag_configure("header", foreground="#0b5cad", font=("Consolas", 11, "bold"))
        self.text.tag_configure("ok", foreground="#1e7a33")
        self.text.tag_configure("warn", foreground="#b00")
        box.add(self.text, weight=1)

    def _build_buttons(self):
        pan = ttk.Frame(self.root, padding=(8, 4, 8, 0))
        pan.pack(fill="x")
        self.btn_run = ttk.Button(pan, text="▶  Run SysDiag", command=self._on_run)
        self.btn_run.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.btn_save = ttk.Button(pan, text="Save Copy…", command=self._on_save)
        self.btn_save.pack(side="left", fill="x", expand=True, padx=(4, 4))
        self.btn_cmp = ttk.Button(pan, text="Compare with last scan", command=self._on_compare)
        self.btn_cmp.pack(side="left", fill="x", expand=True, padx=4)
        self.btn_open = ttk.Button(pan, text="Open report folder", command=self._on_open_folder)
        self.btn_open.pack(side="left", fill="x", expand=True, padx=4)
        self.btn_last = ttk.Button(pan, text="Open last scan", command=self._on_open_last)
        self.btn_last.pack(side="left", fill="x", expand=True, padx=4)
        self.btn_debug = ttk.Button(pan, text="Save Debug Log…", command=self._on_save_debug)
        self.btn_debug.pack(side="left", fill="x", expand=True, padx=4)

    def _build_status(self):
        self.status = ttk.Label(self.root, text="Ready - configure sections and click Run.", anchor="w")
        self.status.pack(fill="x", padx=8, pady=2)

    def _status(self, msg, tag="ok"):
        self.status.config(text=msg, foreground=self._fg(tag))

    # ------------------------------------------------------ actions -------
    def _on_run(self):
        self._refresh_output()
        self.btn_run.config(state="disabled")
        self.status.config(text="Preparing...")
        # marshal config reads to the main thread (StringVar must not be
        # touched from a worker thread)
        self.root.after(0, self._start_run)

    def _start_run(self):
        sections = {k: bool(v.get()) for k, v in self.var_sections.items()}
        fmt = self.var_fmt.get()
        outdir = Path(self.var_dir.get() or ".")
        reportname = self.var_name.get().strip() or "sysdiag_run"
        outdir.mkdir(parents=True, exist_ok=True)
        self.status.config(text="Engine running... please wait.")
        self._append("Running engine (this can take a few seconds)...", "ok")
        t = threading.Thread(
            target=self._run_worker_impl,
            args=(sections, fmt, outdir, reportname),
            daemon=True,
        )
        t.start()

    def _run_worker_impl(self, sections, fmt, outdir, reportname):
        try:
            text, err = run_engine(sections, fmt, outdir, reportname, ENGINE)
            if err:
                self._enqueue("status", text="Engine failed: " + err, tag="warn")
                self._enqueue("append", text="ERROR: " + err, tag="warn")
                self._enqueue("refresh")
                self._enqueue("run_done")
                return
            if text is None:
                self._enqueue("status", text="No report produced.", tag="warn")
                self._enqueue("run_done")
                return
            # --- analysis: suggested issues over this scan + reference baselines ---
            findings = analyze_report(text)
            report_text = text
            if findings:
                report_text += "\n" + format_findings(findings)
            self._enqueue("append", text=report_text, tag="header")
            n_sections = len([l for l in text.splitlines() if l.startswith("===")])
            n_find = len([f for f in findings if f[0] == "WARN"])
            self._enqueue("status", text="Done - {} section(s) scanned{}, {} suggested issue(s).".format(
                n_sections, "" if n_find == 0 else " ({} WARN)".format(n_find), len(findings)), tag="ok")
            # Roll the two most recent scans so the Compare button can diff
            # the latest two runs (prev = previous scan, last = current scan).
            # Prefer the .md regardless of output format.
            prev = outdir / "sysdiag_prev.md"
            last = outdir / "sysdiag_last.md"
            report_base = reportname
            new_scan = None
            for ext in (".md", ".html", ".txt"):
                cand = outdir / (report_base + ext)
                if cand.exists():
                    new_scan = cand
                    break
            if new_scan is None:
                matches = [
                    p for p in outdir.glob(report_base + "*")
                    if p.is_file() and p.suffix.lower() in (".md", ".html", ".txt")
                ]
                if matches:
                    new_scan = max(matches, key=lambda p: p.stat().st_mtime)
            if new_scan is not None:
                # save the previous last scan into prev (if one exists),
                # then move the new scan into the "last" slot
                if last.exists():
                    shutil.copy2(last, prev)
                new_scan.replace(last)
            # keep a copy as the "last scan" for comparison
            self._enqueue("run_done")
        except Exception:
            self._enqueue("status", text="Run failed: " + traceback.format_exc(), tag="warn")
            self._enqueue("run_done")
        finally:
            self._enqueue("run_done")

    def _enqueue(self, kind, **kw):
        self.ui_q.put({"kind": kind, **kw})

    def _drain_queue(self):
        """Process queued UI updates on the main thread (Tk is not threadsafe)."""
        try:
            while True:
                msg = self.ui_q.get_nowait()
                kind = msg.get("kind")
                if kind == "status":
                    self._write_status(msg.get("text", ""), msg.get("tag", "ok"))
                elif kind == "append":
                    self._append(msg.get("text", ""), msg.get("tag", ""))
                elif kind == "refresh":
                    self._refresh_output()
                elif kind == "run_done":
                    self.btn_run.config(state="normal")
                    self._write_status(msg.get("text", ""), msg.get("tag", "ok"))
                    self._append(msg.get("text", ""), msg.get("tag", "ok"))
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _on_compare(self):
        outdir = Path(self.var_dir.get() or ".")
        a = outdir / "sysdiag_prev.md"   # previous scan
        b = outdir / "sysdiag_last.md"   # current scan
        if not a.exists():
            messagebox.showinfo("Compare", "Not enough scans to compare - run two scans first.")
            return
        if not b.exists():
            messagebox.showinfo("Compare", "No report generated yet - run a scan first.")
            return
        text = diff_scans(a, b)
        self._append(text, "header")
        self._write_status("Comparison shown above.", "ok")

    def _on_save(self):
        outdir = Path(self.var_dir.get() or ".")
        fmt = self.var_fmt.get()
        # default to the current (most recent) scan
        report = outdir / ("sysdiag_last." + fmt)
        if not report.exists():
            # fall back to the named report if it exists
            name = self.var_name.get().strip() or "sysdiag_run"
            candidate = outdir / (name + "." + fmt)
            if candidate.exists():
                report = candidate
            else:
                messagebox.showinfo("Save", "No report generated yet. Run a scan first.")
                return
        if not report.exists():
            messagebox.showinfo("Save", "No report found to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension="." + fmt, initialfile=report.name,
            filetypes=[(fmt.upper() + " files", "*.{}".format(fmt))], parent=self.root)
        if path:
            Path(path).write_text(report.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            self._write_status("Saved: " + path, "ok")

    def _on_open_folder(self):
        d = Path(self.var_dir.get() or ".")
        if d.exists():
            os.startfile(d)
        else:
            messagebox.showinfo("Open", "Report directory does not exist yet (run a scan first).")

    def _on_open_last(self):
        d = Path(self.var_dir.get() or ".")
        last = d / "sysdiag_last.md"
        if last.exists():
            os.startfile(str(last))
        else:
            messagebox.showinfo("Open", "No saved last scan yet.")

    def _pick_dir(self):
        d = filedialog.Directory(
            self.root, initialdir=str(self.var_dir.get() or DEFAULT_REPORT_DIR))
        if d:
            self.var_dir.set(d)
            self.cfg["report_dir"] = str(d)
            save_config(self.cfg)

    def _pick_name(self):
        d = filedialog.asksaveasfilename(
            defaultextension=".md",
            initialfile=self.var_name.get() or "sysdiag_run",
            parent=self.root,
        )
        if d:
            self.var_name.set(Path(d).stem)
            self.cfg["last_report_name"] = self.var_name.get()
            save_config(self.cfg)

    def _create_startup_shortcut(self):
        """Create a batch file in the Windows Startup folder that runs a scan."""
        script = (SCRIPT_DIR / "sysdiag_gui.py").resolve()
        startup_dir = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        bat_path = Path(startup_dir) / "SysDiag_AtLogon.bat"
        pythonw = os.path.join(
            os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "System32", "WindowsPowerShell", "v1.0", "pythonw.exe")
        content = '@echo off\npythonw.exe "{}" --startup-only\n'.format(script)
        bat_path.write_text(content, encoding="utf-8")
        self._status("Startup shortcut created: " + str(bat_path), "ok")

    def _remove_startup_shortcut(self):
        startup_dir = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        bat_path = Path(startup_dir) / "SysDiag_AtLogon.bat"
        if bat_path.exists():
            bat_path.unlink()
        self._status("Startup shortcut removed.")

    def _on_startup_toggle(self):
        if self.var_startup.get():
            self._create_startup_shortcut()
        else:
            self._remove_startup_shortcut()

    def _on_save_debug(self):
        outdir = Path(self.var_dir.get() or ".")
        outdir.mkdir(parents=True, exist_ok=True)
        # pick the most recent report
        last_report = outdir / "sysdiag_last.md"
        if not last_report.exists():
            mds = list(outdir.glob("*.md"))
            if not mds:
                messagebox.showinfo("Debug", "No report to save. Run a scan first.")
                return
            last_report = max(mds, key=lambda p: p.stat().st_mtime)
        report_text = last_report.read_text(encoding="utf-8", errors="replace")
        debug = [
            "=" * 50,
            "SysDiag DEBUG LOG",
            "Generated : " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"),
            "Sections  : " + ", ".join(k for k, v in self.sections.items() if v),
            "Format    : " + self.var_fmt.get().upper(),
            "Report dir: " + str(outdir),
            "=" * 50,
            report_text,
            "",
            "--- END DEBUG LOG ---",
        ]
        debug_path = outdir / ("sysdiag_debug_" +
                               datetime.now().strftime("%Y%m%d_%H%M%S") + ".md")
        debug_path.write_text("\n".join(debug), encoding="utf-8")
        self._write_status("Debug saved: " + str(debug_path), "ok")

    # ------------------------------------------------ scheduler -------------

    def _start_scheduler(self):
        """Start or stop the recurring-analyze scheduler based on settings."""
        if self.var_sched_every_active.get() and self.var_sched_every.get() > 0:
            self._schedule(int(self.var_sched_every.get()) * 60000, self._do_scheduled_run)
            self._status("Scheduler: repeat every {} minutes".format(self.var_sched_every.get()), "ok")
        elif self.var_sched_daily.get():
            self._schedule_daily()
        else:
            self._cancel_scheduler()
            self._status("Scheduler: off", "ok")

    def _schedule(self, delay_ms, callback):
        self._cancel_scheduler()
        self._sched_job = self.root.after(delay_ms, callback)

    def _schedule_daily(self):
        self._cancel_scheduler()
        try:
            h, m = (int(x) for x in self.var_sched_daily.get().split(":"))
        except ValueError:
            self._status("Invalid daily time (use HH:MM)", "warn")
            return
        now = datetime.now()
        target = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if target <= now:
            target += datetime.timedelta(days=1)
        delay_ms = int((target - now).total_seconds() * 1000)
        self._sched_job = self.root.after(delay_ms, self._do_scheduled_run)

    def _do_scheduled_run(self):
        if self._busy:
            self._schedule(int(self.var_sched_every.get()) * 60000 if self.var_sched_every.get() > 0 else 60000, self._do_scheduled_run)
            return
        self._busy = True
        self._start_run()
        self._schedule_next_scheduled()

    def _schedule_next_scheduled(self):
        if self.var_sched_every_active.get() and self.var_sched_every.get() > 0:
            self._schedule(int(self.var_sched_every.get()) * 60000, self._do_scheduled_run)
        elif self.var_sched_daily.get():
            self._schedule_daily()
        else:
            self._cancel_scheduler()

    def _cancel_scheduler(self):
        if self._sched_job is not None:
            self.root.after_cancel(self._sched_job)
            self._sched_job = None
        self._busy = False

    def _refresh_output(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", "SysDiag GUI\n" + "=" * 40 + "\n")
        self.text.insert("end", "Sections: " + ", ".join(k for k, v in self.sections.items() if v) + "\n")
        self.text.insert("end", "Output format: " + self.var_fmt.get().upper() + "\n")
        self.text.insert("end", "Report dir: " + str(self.outdir) + "\n")
        self.text.insert("end", "Engine: " + str(ENGINE) + "\n")
        self.text.configure(state="disabled")

    def _write_status(self, msg, tag="ok"):
        self.status.config(text=msg, foreground=self._fg(tag))

    def _fg(self, tag):
        return {"ok": "#1e7a33", "warn": "#b00"}.get(tag, "black")

    def _append(self, text, tag=""):
        self.text.configure(state="normal")
        self.text.insert("end", text, tag)
        self.text.see("end")
        self.text.configure(state="disabled")

    def _about(self):
        messagebox.showinfo("SysDiag",
                            "SysDiag GUI\n"
                            "Windows health-check front-end.\n"
                            "Engine: sysdiag.ps1 (PowerShell, CIM/WMI-based).\n"
                            "Settings stored in: " + str(CONFIG_FILE))

    def _refresh_cfg(self, sections, fmt, outdir, reportname):
        self.cfg["sections"] = {k: bool(v) for k, v in self.var_sections.items()}
        self.cfg["format"] = fmt
        self.cfg["report_dir"] = str(outdir)
        self.cfg["last_report_name"] = reportname
        save_config(self.cfg)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SysDiag - Windows system health-check front-end.")
    parser.add_argument(
        "--startup-only",
        action="store_true",
        help="Run a single scan and exit (no GUI). Used for startup automation / scheduled runs.",
    )
    args = parser.parse_args()

    if args.startup_only:
        _run_startup_only()
        return

    root = tk.Tk()
    style = ttk.Style()
    style.configure("Bold.TLabel", font=("Segoe UI", 9, "bold"))
    app = SysDiagApp(root)
    root.mainloop()


def _run_startup_only():
    """Run one scan with no GUI and exit. Used for startup automation."""
    cfg = load_config()
    sections = {k: bool(v) for k, v in cfg["sections"].items()}
    fmt = cfg.get("format", "md")
    outdir = Path(cfg.get("report_dir") or DEFAULT_REPORT_DIR)
    reportname = cfg.get("last_report_name") or "sysdiag_startup"
    outdir.mkdir(parents=True, exist_ok=True)
    text, err = run_engine(sections, fmt, outdir, reportname, ENGINE)
    if err:
        print("SysDiag startup: ERROR - " + err, file=sys.stderr)
        sys.exit(1)
    if text is None:
        print("SysDiag startup: no report produced.", file=sys.stderr)
        sys.exit(1)
    findings = analyze_report(text)
    report_text = text
    if findings:
        report_text += "\n" + format_findings(findings)
    # save a debug log for updates/troubleshooting
    debug_path = outdir / ("sysdiag_debug_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".md")
    block = [
        "=" * 50,
        "SysDiag DEBUG LOG",
        "Generated : " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "Sections  : " + ", ".join(k for k, v in sections.items() if v),
        "Format    : " + fmt.upper(),
        "Report dir: " + str(outdir),
        "=" * 50,
        report_text,
        "",
        "--- END DEBUG LOG ---",
    ]
    debug_path.write_text("\n".join(block), encoding="utf-8")
    print("SysDiag startup: report saved to " + str(debug_path), flush=True)


if __name__ == "__main__":
    main()
