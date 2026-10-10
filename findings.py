"""Shared finding format. Every scanner creates Finding objects and saves them with save_findings()."""
import json
import os
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


def save_findings(findings, path="output/results.json"):
    """Write findings to path. Replaces earlier entries from the same source, so re-running a scanner never duplicates."""
    sources = {f.source for f in findings}
    existing = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            existing = [x for x in json.load(fh) if x.get("source") not in sources]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(existing + [asdict(f) for f in findings], fh, indent=2)


def load_findings(path="output/results.json"):
    with open(path, encoding="utf-8") as fh:
        return [Finding(**x) for x in json.load(fh)]