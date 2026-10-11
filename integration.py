"""
Connection point between the QuantumTrace frontend and the QuantumTrace pipeline.

The welcome page saves the upload to a temp folder  <tmp>/quantumtrace_uploads/<timestamp>/data/...  and calls
run_analysis(data_dir). Each run is fully isolated in  <tmp>/quantumtrace_uploads/<timestamp>/output/ (deleted after the run) :

    network_analyzer.py  -> network_analyzer_output.json
    config_scanner.py    -> config_scanner_output.json
    code_scanner.py      -> code_scanner_output.json
    classifier.py        -> results.json   (merged + risk_tier + replacement)

The text of that results.json is returned to the report page. Saving to MongoDB is done by
classifier.py itself (via mongo_sync.py) when MONGODB_URI is configured.
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent   # project root (where the scanners live)
STEP_TIMEOUT = 900                       # seconds per step

# (script, folder inside the uploaded data/, output file name)
SCANNERS = [
    ("network_analyzer.py", "network-capture", "network_analyzer_output.json"),
    ("config_scanner.py", "cloud-posture", "config_scanner_output.json"),
    ("code_scanner.py", "sample-repos", "code_scanner_output.json"),
]


# pyshark 0.6 calls asyncio child-watcher functions that Python 3.14 removed. This launcher
# restores harmless stand-ins and then runs the unmodified scanner script as __main__.
_PYSHARK_SHIM = (
    "import asyncio, os, runpy, sys\n"
    "if not hasattr(asyncio, 'set_child_watcher'):\n"
    "    class _W:\n"
    "        def attach_loop(self, loop): pass\n"
    "    asyncio.set_child_watcher = lambda watcher: None\n"
    "    asyncio.get_child_watcher = lambda: _W()\n"
    "    asyncio.SafeChildWatcher = _W\n"
    "script = sys.argv[1]\n"
    "sys.argv = sys.argv[1:]\n"
    "sys.path.insert(0, os.path.dirname(os.path.abspath(script)))\n"
    "runpy.run_path(script, run_name='__main__')\n"
)


MONGO_KEYS = ("MONGODB_URI", "MONGODB_DB", "MONGODB_COLLECTION")


def _subprocess_env():
    """Environment for the scanner/classifier processes. mongo_sync.py (called by classifier.py)
    reads MONGODB_* from environment variables, so any value set as a Streamlit secret
    (.streamlit/secrets.toml or the host's Secrets) is passed on. Real env vars win."""
    env = dict(os.environ)
    try:
        import streamlit as st
        for key in MONGO_KEYS:
            if not env.get(key) and st.secrets.get(key):
                env[key] = str(st.secrets[key])
    except Exception:
        pass
    return env


class StepError(RuntimeError):
    """A scanner/classifier step failed. `.output` holds everything it printed."""
    def __init__(self, message, output=""):
        super().__init__(message)
        self.output = output


def _run(args):
    args = list(map(str, args))
    cmd = [sys.executable, "-c", _PYSHARK_SHIM, *args] if Path(args[0]).name == "network_analyzer.py" \
        else [sys.executable, *args]
    proc = subprocess.run(cmd, cwd=ROOT, env=_subprocess_env(),
                          capture_output=True, text=True, timeout=STEP_TIMEOUT)
    if proc.returncode != 0:
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        tail = (proc.stderr or proc.stdout or "").strip()[-700:]
        raise StepError(f"{Path(args[0]).name} failed:\n{tail}", output)


def _cleanup(run_dir: Path):
    """Delete a temporary upload folder (only ever inside .../quantumtrace_uploads/)."""
    if run_dir.parent.name == "quantumtrace_uploads":
        shutil.rmtree(run_dir, ignore_errors=True)


def _purge_old(root: Path, max_age_hours: int = 6):
    """Remove leftovers from runs that crashed before they could clean up."""
    if root.name != "quantumtrace_uploads" or not root.exists():
        return
    limit = time.time() - max_age_hours * 3600
    for d in root.iterdir():
        if d.is_dir() and d.stat().st_mtime < limit:
            shutil.rmtree(d, ignore_errors=True)


def run_analysis(data_dir: Path):
    data_dir = Path(data_dir).resolve()
    run_dir = data_dir.parent                 # <tmp>/quantumtrace_uploads/<timestamp>/
    out_dir = run_dir / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    _purge_old(run_dir.parent)
    try:
        ran, failures = [], []
        for script, folder, out_name in SCANNERS:
            src = data_dir / folder
            # Skip a scanner when nothing was uploaded for it (any single file type is enough).
            if not src.is_dir() or not any(p.is_file() for p in src.rglob("*")):
                continue
            if not (ROOT / script).exists():
                failures.append(f"{script}: scanner not found")
                continue
            try:
                _run([ROOT / script, src, out_dir / out_name])
                ran.append(script)
            except Exception as exc:          # one scanner failing must not block the others
                failures.append(str(exc))
                print(f"[QuantumTrace] {exc}", file=sys.stderr)
        if not ran:
            if failures:
                raise RuntimeError("No scanner could analyze the uploaded files:\n\n" + "\n\n".join(failures))
            raise RuntimeError("No supported files were found in the upload.")

        results_path = out_dir / "results.json"
        try:
            _run([ROOT / "classifier.py", out_dir, results_path])
        except StepError as exc:
            # classifier.py exits with an error when only the MongoDB sync failed, after it already
            # wrote results.json. The report is still valid, so show it and log the database problem.
            if results_path.exists() and "mongo" in exc.output.lower():
                print(f"[QuantumTrace] Report generated, but saving to MongoDB failed:\n{exc.output.strip()[-500:]}",
                      file=sys.stderr)
            else:
                raise
        if not results_path.exists():
            raise RuntimeError("The classifier finished but produced no results.json.")
        results_text = results_path.read_text(encoding="utf-8")
        return results_text
    finally:
        _cleanup(run_dir)                     # the user's uploaded files never stay on disk