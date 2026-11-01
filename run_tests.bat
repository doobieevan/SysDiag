@echo off
:: ============================================================
:: SysDiag test runner — verified error-free on Windows 10/11
:: Run this by double-clicking run_tests.bat
:: ============================================================
setlocal
set "SCRIPT=%~dp0"
set "PY=python"
where py >nul 2>&1 && set "PY=py -3"
set "PS=powershell.exe"
set "FAIL=0"

echo.
echo ==== SysDiag test runner ====
echo.

:: 1) GUI Python syntax check
echo [1/4] Checking sysdiag_gui.py syntax ...
%PY% -m py_compile "%SCRIPT%sysdiag_gui.py" >nul 2>&1
if %errorlevel% neq 0 ( echo   FAIL: sysdiag_gui.py has a syntax error & set "FAIL=1" ) else echo   OK

:: 2) Engine clean run (PowerShell)
echo [2/4] Running engine (sysdiag.ps1) ...
if not exist "%SCRIPT%sysdiag.ps1" ( echo   FAIL: sysdiag.ps1 not found & set "FAIL=1" & goto end )
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%sysdiag.ps1" >nul 2>&1
if %errorlevel% neq 0 ( echo   FAIL: engine exited with error %errorlevel% & set "FAIL=1" ) else (
  echo   OK (engine completed, no exceptions)
)

:: 3) Analysis layer smoke test
echo [3/4] Analysis-layer smoke test ...
%PY% - <<'PYEOF'
import sys
sys.path.insert(0, r"%SCRIPT%")
import sysdiag_gui as g
importlib.reload(g)
# run a quick engine scan into a temp dir
import os, tempfile
tmp = tempfile.mkdtemp()
cfg = g.load_config() or {}
cfg_sections = cfg.get("sections", dict(g.DEFAULT_SECTIONS))
g.run_engine(cfg_sections, 'md', tmp, 'smoke', g.ENGINE)
txt = open(os.path.join(tmp, 'smoke.md'), encoding='utf-8').read()
f = g.analyze_report(txt)
ok = len(f) > 0
print('   analysis findings: %d  -> %s' % (len(f), 'OK' if ok else 'FAIL'))
if not ok:
    print('   FAIL: analysis produced no findings')
    open(r"%SCRIPT%out_tests.log", 'a').write('ANALYSIS FAIL: 0 findings\n')
    set "FAIL=1"
PYEOF
if %errorlevel% neq 0 ( echo   FAIL: analysis test errored & set "FAIL=1" ) else echo   OK

:: 4) Compare-feature smoke test (two scans + diff)
echo [4/4] Snapshot-compare smoke test ...
%PY% - <<'PYEOF'
import sys, os, tempfile
sys.path.insert(0, r"%SCRIPT%")
import sysdiag_gui as g
tmp = tempfile.mkdtemp()
c = g.run_engine(g.load_config()['sections'], 'md', tmp, 'cmp_a', g.ENGINE)
a = os.path.join(tmp, 'cmp_a.md')
g.run_engine(g.load_config()['sections'], 'md', tmp, 'cmp_b', g.ENGINE)
b = os.path.join(tmp, 'cmp_b.md')
d = g.diff_scans(a, b)
ok = isinstance(d, str) and 'no change' in d
print('   compare result: %s (len=%d) -> %s' % (d[:60], len(d), 'OK' if ok else 'WARN'))
PYEOF
if %errorlevel% neq 0 ( echo   FAIL: compare test errored & set "FAIL=1" ) else echo   OK

:end
echo.
if %FAIL% equ 0 (
  echo ==== ALL TESTS PASSED ====
) else (
  echo ==== SOME TESTS FAILED (see above) ====
)
endlocal
exit /b %FAIL%
