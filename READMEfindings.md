# finding.py

The shared finding format for QuantumTrace. Every scanner (network, code, cloud) describes what it discovers as `Finding` objects and saves them to one file, `output/results.json`. The classifier, dashboard and CBOM export all read that same file, so they never need to know which scanner produced a result.

```
code_scanner.py ─────┐
network_analyzer.py ─┼─► Finding objects ─► save_findings() ─► output/results.json
config_scanner.py ───┘                                                │
                                      load_findings() ◄── classifier, dashboard, export_cbom
```

## What is in the file

| Name | What it is |
|---|---|
| `Finding` | A dataclass describing one cryptographic item that was found |
| `save_findings(findings, path)` | Writes a list of findings to JSON |
| `load_findings(path)` | Reads the JSON back into `Finding` objects |

The default path for both functions is `output/results.json`.

## The `Finding` fields

| Field | Type | Filled in by | Meaning |
|---|---|---|---|
| `source` | `str` | scanner | Which scanner found it: `"network"`, `"code"` or `"cloud"` |
| `asset` | `str` | scanner | What was scanned, e.g. `license_token.py`, `web01.lab:443`, `alias/licensing-jwt-signing` |
| `location` | `str` | scanner | Where in the asset, e.g. `line 6`, `TLS 1.2 ServerHello`, `KeySpec` |
| `algorithm` | `str` | scanner | The algorithm or primitive, e.g. `RSA`, `SHA-1`, `AES-GCM`, `Ed25519` |
| `key_length` | `int` or `None` | scanner | Key size in bits, or `None` if unknown or not applicable |
| `library` | `str` or `None` | scanner | Library or service involved, e.g. `cryptography 46.0.5`, `AWS KMS` |
| `risk_tier` | `str` | classifier | `"Critical"`, `"Medium"` or `"Safe"`. Scanners leave the default `"Unclassified"` |
| `replacement` | `str` or `None` | classifier | Recommended post-quantum replacement, e.g. `ML-DSA (FIPS 204)` |
| `notes` | `str` or `None` | scanner | Extra remarks, e.g. `hardcoded key in source` |

**Rule of thumb:** scanners fill in the first six fields and `notes`. The classifier fills in `risk_tier` and `replacement`. Scanners should not guess the risk tier.

## Using it in a scanner

```python
from finding import Finding, save_findings

findings = []

findings.append(Finding(
    source="code",
    asset="license_token.py",
    location="line 6",
    algorithm="RSA",
    key_length=1024,
    library="cryptography 46.0.5",
))

save_findings(findings, "output/results.json")
```

## Using it in the classifier, dashboard or export

```python
from finding import load_findings, save_findings

findings = load_findings("output/results.json")

for f in findings:
    if f.algorithm == "RSA":
        f.risk_tier = "Critical"
        f.replacement = "ML-DSA (FIPS 204)"

save_findings(findings, "output/results.json")
```

If the classifier saves every finding back, all sources are replaced with their classified versions, which is what you want.

## How saving works

`save_findings()` replaces older entries that came from the **same source** and keeps entries from other sources.

- Re-running `code_scanner.py` replaces the old code findings and leaves the network and cloud findings alone.
- Running a scanner twice never creates duplicates.
- The `output/` folder is created if it doesn't exist.

Because of this, the scanners can be run in any order.

## Example `results.json` entry

```json
{
  "source": "code",
  "asset": "report_export.py",
  "location": "line 11",
  "algorithm": "AES-ECB",
  "key_length": 128,
  "library": "cryptography 46.0.5",
  "risk_tier": "Unclassified",
  "replacement": null,
  "notes": "key size inferred from EXPORT_KEY; hardcoded key in source; ECB mode leaks patterns and is insecure regardless of quantum computers"
}
```

## Suggested conventions per scanner

These keep the data consistent so the classifier and dashboard can group findings.

| Source | `asset` | `location` | `algorithm` |
|---|---|---|---|
| `code` | Path relative to the scanned folder | `line N` | Algorithm name, with the mode where relevant (`AES-GCM`, `AES-ECB`) |
| `network` | `host:port` | `TLS 1.2 ServerHello`, `TLS 1.3 key_share` | One finding per part: key exchange, cipher and hash each get their own finding |
| `cloud` | Alias, certificate domain or load balancer name | File and field, e.g. `kms_key_inventory.json, KeySpec` | Normalized family: `RSA`, `ECDSA`, `AES-256` |

Use the same spelling for the same algorithm everywhere (`SHA-1`, not `sha1` or `SHA1`). The classifier looks algorithms up by name, so inconsistent spelling causes missed classifications.

## Changing the format

Everything depends on these field names, so:

1. Agree on any change with the whole team first, ideally in the first two hours.
2. Make the change in `finding.py` only.
3. If you add a field, give it a default value (like `None`) so existing scanners keep working.
4. Delete `output/results.json` and re-run the scanners after changing the format, so old entries don't cause errors.

The "Risk engine & CBOM" role owns this file.

## Known limits

- `load_findings()` fails if `results.json` contains a field that `Finding` doesn't have. This is one more reason to regenerate the file after any change.
- Findings are not de-duplicated within one scan. If the same algorithm is used on several lines, you get one finding per line. Group them by `asset` and `algorithm` in the dashboard or export.
- `risk_tier` is a plain string, so a typo like `"critical"` will not raise an error. Use the exact spellings `Critical`, `Medium` and `Safe`.