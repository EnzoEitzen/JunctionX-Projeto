"""Shared finding format. Every scanner creates Finding objects and saves them with save_findings()."""
import json
import os
import tempfile
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    source: str                      # "network", "code" or "cloud"
    asset: str                       # what was scanned, e.g. "license_token.py"
    location: str                    # where, e.g. "line 6" or "TLS ServerHello"
    algorithm: str                   # e.g. "RSA", "SHA-1", "AES-GCM"
    key_length: int | None = None    # bits, or None if unknown
    library: str | None = None       # e.g. "cryptography 46.0.5"
    risk_tier: str = "Unclassified"  # filled in by the classifier: Critical / Medium / Safe
    replacement: str | None = None   # filled in by the classifier
    notes: str | None = None         # extra remarks, e.g. "hardcoded key in source"


def _read_entries(path):
    """Return the list of finding dicts stored in path.

    A missing or empty file means "no findings yet" and gives []. A file that
    holds something other than a JSON list of objects raises ValueError with a
    clear message, instead of a raw JSONDecodeError traceback. It is never
    overwritten automatically, because it might contain someone's data.
    """
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if not text.strip():
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON ({exc}). Fix or delete it, then run again.") from exc
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise ValueError(f"{path} must contain a JSON list of findings. Fix or delete it, then run again.")
    return data


def save_findings(findings, path="output/results.json"):
    """Write findings to path. Replaces earlier entries from the same source, so re-running a scanner never duplicates.

    An empty existing file is treated as having no entries. The new file is written to a temporary
    file first and then moved into place, so a crash mid-write can't leave a half-written results file.
    """
    sources = {f.source for f in findings}
    existing = [x for x in _read_entries(path) if x.get("source") not in sources]
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=folder, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(existing + [asdict(f) for f in findings], fh, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def load_findings(path="output/results.json"):
    """Read findings from path. An empty file gives []. A missing file raises FileNotFoundError."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Run the scanners first.")
    return [Finding(**x) for x in _read_entries(path)]
