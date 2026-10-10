"""
classifier.py - quantum risk classifier and Quantum Risk Score.

Reads every .json file in a folder (the scanner outputs) except results.json,
merges their findings, fills in the two fields the scanners leave empty -
risk_tier and replacement - and writes everything to one results.json. It also
prints the Quantum Risk Score for the whole environment.

Usage:
    python classifier.py <folder> <results file>
    python classifier.py output/ output/results.json
    python classifier.py output/ output/results.json --json    # summary as JSON

Both arguments are optional (defaults: output/ and output/results.json).
results.json is rebuilt from scratch on every run, so it never goes stale.

Other modules can import it:
    from classifier import classify_findings, summarize

Tiers (from the challenge brief)
    Critical  asymmetric schemes broken by Shor's algorithm: RSA, DSA, DH,
              ECDSA, ECDH, and the elliptic-curve schemes x25519 / Ed25519
    Medium    symmetric ciphers / hashes weakened by Grover's algorithm:
              AES-128, 3DES, SHA-1 (and, because they are weaker still, MD5, DES, RC4)
    Safe      AES-256, SHA-256 and up, and recognised post-quantum schemes
              (ML-KEM, ML-DSA, SLH-DSA and hybrids such as X25519MLKEM768)

The tier says how exposed the primitive is to a quantum computer, nothing else.
Classical weaknesses (ECB mode, weak RNG, small RSA keys) are not tiered, but
they are mentioned in the notes / replacement fields.

Quantum Risk Score (0 = nothing at risk, 100 = everything Critical)
    Every unique (source, asset, algorithm, key length) counts once, so a
    primitive used on 20 lines of the same file is not counted 20 times.
    Critical = 100 points, Medium = 40, Safe = 0. The score is the average.
    Unclassified items are left out of the score and reported separately.
"""
import argparse
import glob
import json
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, fields

from findings import Finding

CRITICAL, MEDIUM, SAFE, UNCLASSIFIED = "Critical", "Medium", "Safe", "Unclassified"
TIER_ORDER = [CRITICAL, MEDIUM, SAFE, UNCLASSIFIED]
WEIGHTS = {CRITICAL: 100, MEDIUM: 40, SAFE: 0}
RATINGS = [(75, "Severe"), (50, "High"), (25, "Moderate"), (0, "Low")]

# Recommended replacements (NIST post-quantum standards)
KEM = "ML-KEM (FIPS 203)"
SIG = "ML-DSA (FIPS 204)"
SIG_LONG_LIVED = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"   # CA roots, code signing
SLH = "SLH-DSA (FIPS 205)"
BOTH = f"{KEM} for key exchange/encryption, {SIG} for signatures"
TLS_KEX = f"{KEM} via hybrid X25519MLKEM768 in TLS 1.3"
AES256 = "AES-256 (e.g. AES-256-GCM)"
HASH_FIX = "SHA-256 or stronger (SHA-384, SHA3-256)"
ELB_PQ_POLICY = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (hybrid ML-KEM, FIPS 203)"


@dataclass
class Verdict:
    tier: str
    replacement: str | None = None
    note: str | None = None      # only for judgement calls; appended to Finding.notes


def _key(name: str) -> str:
    """Canonical form used for matching: upper case, underscores as hyphens."""
    return re.sub(r"\s+", " ", name.strip().upper().replace("_", "-"))


# ---------------------------------------------------------------- asymmetric
KEX_NAMES = re.compile(r"^(ECDH|ECDHE|DH|DHE|DIFFIE-HELLMAN|XDH|X25519|X448|SECP|PRIME|CURVE|ELGAMAL)")
SIG_NAMES = re.compile(r"^(ECDSA$|DSA|ED25519|ED448|EDDSA|RSA-PSS)")
SIG_HINT = re.compile(r"(?<!de)(?<!as)(?<!con)sign|attest|cert|\bjwt\b|\bca\b|verif")
KEX_HINT = re.compile(r"decrypt|encrypt|key[ _-]?exchange|key[ _-]?agree|\bkex\b")
LONG_LIVED = re.compile(r"\b(ca|root)\b|code-?sign|firmware")


def _usage(f, name):
    """Is an asymmetric key used for key exchange / encryption ('kex'), signatures ('sig') or unknown (None)?"""
    if f.source == "network":
        return "kex"
    if KEX_NAMES.match(name):
        return "kex"
    if SIG_NAMES.match(name):
        return "sig"
    text = f"{f.asset} {f.location} {f.notes or ''}".lower()
    sig, kex = bool(SIG_HINT.search(text)), bool(KEX_HINT.search(text))
    if sig != kex:
        return "sig" if sig else "kex"
    return None


def _asymmetric(f, name, m):
    usage = _usage(f, name)
    if usage == "kex":
        replacement = TLS_KEX if f.source == "network" else KEM
    elif usage == "sig":
        long_lived = LONG_LIVED.search(f"{f.asset} {f.notes or ''}".lower())
        replacement = SIG_LONG_LIVED if long_lived else SIG
    else:
        replacement = BOTH
    note = None
    if f.key_length and f.key_length < 2048 and re.match(r"^(RSA|DSA|DH|DHE|DIFFIE)", name):
        note = f"{f.key_length}-bit key is also weak against classical attacks"
    return Verdict(CRITICAL, replacement, note)


# ---------------------------------------------------------------- post-quantum
PRE_STANDARD = {"KYBER": KEM, "DILITHIUM": SIG, "SPHINCS": SLH, "FALCON": "FN-DSA (FIPS 206, draft)"}


def _pqc(f, name, m):
    if "MLKEM" not in name:
        for old, new in PRE_STANDARD.items():
            if old in name:
                return Verdict(SAFE, f"Migrate to the final standard: {new}", "pre-standard (draft) variant")
    return Verdict(SAFE)


# ---------------------------------------------------------------- hashes and MACs
WEAK_HASH = re.compile(r"^(SHA-?1|SHA|MD[245]|SHA-?224|SHA-?3-?224)$")
STRONG_HASH = re.compile(r"^(SHA-?(256|384|512)(/\d+)?|SHA-?3-?(256|384|512))$")


def _hash(name):
    if WEAK_HASH.match(name):
        note = "classically broken (practical collisions)" if name.startswith("MD") else None
        return Verdict(MEDIUM, HASH_FIX, note)
    if STRONG_HASH.match(name):
        return Verdict(SAFE)
    return None


def _hash_rule(f, name, m):
    return _hash(name)


def _hmac(f, name, m):
    inner = _hash(m.group(1))
    if inner is None:
        return None
    if inner.tier == MEDIUM:
        return Verdict(MEDIUM, "HMAC-SHA-256 or stronger", inner.note)
    return Verdict(SAFE)


def _hmac_bare(f, name, m):
    """HMAC key without a named hash (AWS KMS HMAC_256 etc.): judged by key length."""
    if f.key_length is not None and f.key_length < 256:
        return Verdict(MEDIUM, "HMAC with a 256-bit or longer key")
    return Verdict(SAFE)


# ---------------------------------------------------------------- symmetric ciphers
def _aes(f, name, m):
    bits = f.key_length
    if bits is None:
        size = re.search(r"AES-?(128|192|256)(?![0-9])", name)
        bits = int(size.group(1)) if size else None
    ecb = "ECB" in name
    if bits is None:
        return Verdict(MEDIUM, AES256, "AES key size unknown; treated as below 256 bits until confirmed")
    if bits >= 256:
        return Verdict(SAFE, "AES-256-GCM (ECB mode is insecure)" if ecb else None)
    return Verdict(MEDIUM, "AES-256-GCM" if ecb else AES256)


def _chacha(f, name, m):
    return Verdict(SAFE)   # 256-bit key


def _3des(f, name, m):
    return Verdict(MEDIUM, AES256, "3DES is deprecated (64-bit blocks)")


def _old_cipher(f, name, m):
    return Verdict(MEDIUM, AES256, "classically broken cipher")


# ---------------------------------------------------------------- random number generators
RNG_FIX = {"RANDOM-MODULE": "secrets / os.urandom", "MATH/RAND": "crypto/rand",
           "JAVA.UTIL.RANDOM": "java.security.SecureRandom"}


def _rng(f, name, m):
    """Not a quantum issue, so Safe by the quantum tiers; the scanner note already explains."""
    fix = next((v for k, v in RNG_FIX.items() if name.startswith(k)), "a cryptographically secure RNG")
    return Verdict(SAFE, fix)


# ---------------------------------------------------------------- AWS load balancer TLS policies
# Policy name -> TLS versions it allows (AWS documentation).
ELB_POLICY_VERSIONS = {
    "ELBSecurityPolicy-2016-08": "TLS 1.0-1.2",
    "ELBSecurityPolicy-TLS-1-0-2015-04": "TLS 1.0-1.2",
    "ELBSecurityPolicy-2015-05": "TLS 1.0-1.2",
    "ELBSecurityPolicy-FS-2018-06": "TLS 1.0-1.2",
    "ELBSecurityPolicy-TLS-1-1-2017-01": "TLS 1.1-1.2",
    "ELBSecurityPolicy-FS-1-1-2019-08": "TLS 1.1-1.2",
    "ELBSecurityPolicy-TLS-1-2-2017-01": "TLS 1.2",
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06": "TLS 1.2",
    "ELBSecurityPolicy-FS-1-2-2019-08": "TLS 1.2",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08": "TLS 1.2",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10": "TLS 1.2",
    "ELBSecurityPolicy-TLS13-1-2-2021-06": "TLS 1.2-1.3",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06": "TLS 1.2-1.3",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06": "TLS 1.2-1.3",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06": "TLS 1.2-1.3",
    "ELBSecurityPolicy-TLS13-1-3-2021-06": "TLS 1.3",
}


def _tls_policy(f, name, m):
    found = re.search(r"SslPolicy:\s*([\w.-]+)", f.notes or "")
    if not found:
        return None
    policy = found.group(1)
    if "-PQ-" in policy:        # AWS post-quantum policies, e.g. ...-Res-PQ-2025-09
        return Verdict(SAFE, None, "hybrid ML-KEM key exchange (certificates are classical)")
    versions = ELB_POLICY_VERSIONS.get(policy)
    if versions is None:
        note = "policy not in lookup table; key exchange assumed classical"
    else:
        note = f"policy allows {versions}, classical key exchange only"
        if versions.startswith(("TLS 1.0", "TLS 1.1")):
            note += "; deprecated TLS 1.0/1.1 still enabled"
    return Verdict(CRITICAL, ELB_PQ_POLICY, note)


# ---------------------------------------------------------------- rule table (first match wins)
RULES = [
    (re.compile(r"MLKEM|ML-KEM|ML-DSA|SLH-DSA|FN-DSA|KYBER|DILITHIUM|SPHINCS|FALCON|PQC LIBRARY"), _pqc),
    (re.compile(r"^TLS POLICY$"), _tls_policy),
    (re.compile(r"RNG$"), _rng),
    (re.compile(r"^(?:PBKDF2-)?HMAC-(.+)$"), _hmac),
    (re.compile(r"^HMAC$"), _hmac_bare),
    (re.compile(r"^(?:(?:RSA|DSA|DH|DHE|ECDSA|ECDH|ECDHE|ECIES|EC|XDH|X25519|X448|ED25519|ED448|EDDSA"
                r"|ELGAMAL|DIFFIE-HELLMAN)(?![A-Z0-9])|SECP\d+[RK]1|PRIME\d+V1|BRAINPOOL|CURVE25519|CURVE448)"),
     _asymmetric),
    (re.compile(r"^AES"), _aes),
    (re.compile(r"^CHACHA20"), _chacha),
    (re.compile(r"^(3DES|DESEDE|TRIPLE-?DES|TDEA)"), _3des),
    (re.compile(r"^(DES(?![A-Z])|RC4|ARCFOUR|RC2|BLOWFISH)"), _old_cipher),
    (re.compile(r"^(SHA|MD)"), _hash_rule),
]


def classify(f):
    """Return a Verdict for one finding, or None if the algorithm is not recognised."""
    name = _key(f.algorithm)
    for pattern, handler in RULES:
        m = pattern.search(name)
        if m:
            verdict = handler(f, name, m)
            if verdict is not None:
                return verdict
    return None


def _strip_classifier_note(notes):
    """Remove a note added by an earlier run, so re-running never stacks duplicates."""
    cleaned = re.sub(r"\s*\[classifier:[^\]]*\]\s*$", "", notes or "")
    return cleaned or None


def classify_findings(findings):
    """Fill in risk_tier and replacement on every finding (in place). Returns a Counter of unrecognised algorithms."""
    unknown = Counter()
    for f in findings:
        f.notes = _strip_classifier_note(f.notes)
        verdict = classify(f)
        if verdict is None:
            f.risk_tier, f.replacement = UNCLASSIFIED, None
            unknown[f.algorithm] += 1
            continue
        f.risk_tier, f.replacement = verdict.tier, verdict.replacement
        if verdict.note:
            tag = f"[classifier: {verdict.note}]"
            f.notes = f"{f.notes} {tag}" if f.notes else tag
    return unknown


# ---------------------------------------------------------------- score
def _rating(score):
    return next(label for limit, label in RATINGS if score >= limit)


def _average(tiers):
    return round(sum(WEIGHTS[t] for t in tiers) / len(tiers), 1) if tiers else 0.0


def summarize(findings):
    """Quantum Risk Score plus breakdowns. The dashboard can call this directly."""
    items = {}   # unique (source, asset, algorithm, key_length) -> worst tier seen
    for f in findings:
        if f.risk_tier not in WEIGHTS:
            continue
        k = (f.source, f.asset, f.algorithm, f.key_length)
        if k not in items or WEIGHTS[f.risk_tier] > WEIGHTS[items[k]]:
            items[k] = f.risk_tier

    sources = sorted({k[0] for k in items})
    score = _average(list(items.values()))
    return {
        "score": score,
        "rating": _rating(score),
        "total_findings": len(findings),
        "unique_items": len(items),
        "by_tier": {t: sum(1 for v in items.values() if v == t) for t in (CRITICAL, MEDIUM, SAFE)},
        "unclassified_findings": sum(1 for f in findings if f.risk_tier not in WEIGHTS),
        "by_source": {
            s: {
                "score": _average([v for k, v in items.items() if k[0] == s]),
                "unique_items": sum(1 for k in items if k[0] == s),
                "by_tier": {t: sum(1 for k, v in items.items() if k[0] == s and v == t)
                            for t in (CRITICAL, MEDIUM, SAFE)},
            }
            for s in sources
        },
    }


def print_summary(summary, unknown):
    print(f"\nQuantum Risk Score: {summary['score']} / 100  ({summary['rating']})")
    print(f"{summary['unique_items']} unique cryptographic items from {summary['total_findings']} findings\n")
    print(f"{'':10} {'score':>6} {'items':>6} {'Critical':>9} {'Medium':>7} {'Safe':>5}")
    rows = [("ALL", summary["score"], summary["unique_items"], summary["by_tier"])]
    rows += [(s, d["score"], d["unique_items"], d["by_tier"]) for s, d in summary["by_source"].items()]
    for label, score, n, t in rows:
        print(f"{label:10} {score:>6} {n:>6} {t[CRITICAL]:>9} {t[MEDIUM]:>7} {t[SAFE]:>5}")
    if unknown:
        print(f"\n[WARN] {sum(unknown.values())} finding(s) left Unclassified (not in the rule table):")
        for name, count in unknown.most_common():
            print(f"       {name!r} x{count}")


RESULTS_NAME = "results.json"
FINDING_FIELDS = {f.name for f in fields(Finding)}
CLASSIFIER_FIELDS = {"risk_tier", "replacement"}   # re-derived on every run, so ignored when de-duplicating


def load_folder(folder, output_file):
    """Read every *.json in folder except results.json (and the output file). Returns the merged findings."""
    out_abs = os.path.abspath(output_file)
    findings, seen = [], set()
    paths = sorted(glob.glob(os.path.join(folder, "*.json")))
    for path in paths:
        if os.path.basename(path).lower() == RESULTS_NAME or os.path.abspath(path) == out_abs:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not read {path}, skipping: {exc}")
            continue
        if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
            print(f"[WARN] {path} is not a JSON list of findings, skipping")
            continue

        added = duplicates = bad = 0
        for entry in data:
            try:
                f = Finding(**{k: v for k, v in entry.items() if k in FINDING_FIELDS})
            except TypeError:       # a required field (source, asset, location, algorithm) is missing
                bad += 1
                continue
            key = json.dumps({k: v for k, v in asdict(f).items() if k not in CLASSIFIER_FIELDS}, sort_keys=True)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            findings.append(f)
            added += 1
        extra = f", {duplicates} duplicate(s) dropped" if duplicates else ""
        extra += f", {bad} malformed entr{'y' if bad == 1 else 'ies'} skipped" if bad else ""
        print(f"[OK] {os.path.basename(path)}: {added} findings{extra}")
    return findings


def write_results(findings, path):
    """Write the final results file (replacing any old one). Temp file + rename, so a crash can't leave half a file."""
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=folder, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Merge the scanner outputs in a folder, classify them by quantum risk and write results.json.")
    parser.add_argument("folder", nargs="?", default="output", help="folder with the scanner .json files (default: output)")
    parser.add_argument("results", nargs="?", default=os.path.join("output", RESULTS_NAME),
                        help="results file to write (default: output/results.json)")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON instead of a table")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print(f"[ERROR] Folder not found: {args.folder}")
        sys.exit(1)

    findings = load_folder(args.folder, args.results)
    if not findings:
        print(f"[ERROR] No findings found in {args.folder} (looked at every .json except {RESULTS_NAME}). Run the scanners first.")
        sys.exit(1)

    unknown = classify_findings(findings)
    write_results(findings, args.results)
    summary = summarize(findings)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_summary(summary, unknown)
        print(f"\nClassified findings saved to {args.results}")


if __name__ == "__main__":
    main()