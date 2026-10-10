"""Code scanner: finds cryptographic algorithm usage in source code and outputs Finding objects.

Usage:  python code_scanner.py data/code/ [output/results.json]

Only Python rules are filled in. To add Java or Go, write a list of Rule objects like PY_RULES
and register it in RULES at the bottom of the rules section.
"""
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from findings import Finding, save_findings

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "vendor"}
COMMENT_PREFIX = {".py": "#"}
LOOKAHEAD = 4  # how many following lines to search for a key size


@dataclass
class Rule:
    pattern: str                      # regex matched against one line
    algorithm: str                    # "{g1}" is replaced by the normalized first capture group
    library: str                      # library the call belongs to
    note: str | None = None
    size_pattern: str | None = None   # regex (one capture group) searched in this line + next lines
    infer_size: bool = False          # try to infer the AES key size from constants in the file
    stop: bool = False                # do not check further rules on this line after a match


HASH_NAMES = {
    "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "md5": "MD5", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
}


def norm(name: str) -> str:
    return HASH_NAMES.get(name.lower(), name.upper())


PY_RULES = [
    # --- combined calls first (stop=True so the generic hash/AES rules don't also fire) ---
    Rule(r"hmac\.new\(.*hashlib\.(\w+)", "HMAC-{g1}", "hmac", stop=True),
    Rule(r"PBKDF2HMAC\(.*hashes\.(\w+)\(", "PBKDF2-HMAC-{g1}", "cryptography",
         note="password-based key derivation", stop=True),
    Rule(r"algorithms\.AES\(.*modes\.(\w+)\(", "AES-{g1}", "cryptography", infer_size=True, stop=True),

    # --- public-key algorithms (broken by Shor's algorithm) ---
    Rule(r"rsa\.generate_private_key\(", "RSA", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"padding\.PKCS1v15\(", "RSA-PKCS1v15", "cryptography",
         note="RSA with legacy PKCS#1 v1.5 padding"),
    Rule(r"ec\.generate_private_key\(", "ECDSA/ECDH", "cryptography", size_pattern=r"ec\.SECP(\d+)R1"),
    Rule(r"dsa\.generate_private_key\(", "DSA", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"dh\.generate_parameters\(", "Diffie-Hellman", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"ed25519\.Ed25519(?:Private|Public)Key", "Ed25519", "cryptography"),
    Rule(r"x25519\.X25519(?:Private|Public)Key", "X25519", "cryptography"),

    # --- symmetric ciphers ---
    Rule(r"AESGCM\(", "AES-GCM", "cryptography", infer_size=True),
    Rule(r"algorithms\.AES\(", "AES", "cryptography", infer_size=True),

    # --- hashes ---
    Rule(r"hashlib\.(sha1|sha224|sha256|sha384|sha512|md5|sha3_\d+)\b", "{g1}", "hashlib"),
    Rule(r"hashes\.(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|SHA3_\d+)\(", "{g1}", "cryptography"),

    # --- post-quantum libraries (good news) ---
    Rule(r"(?:import|from)\s+(oqs|pqcrypto|kyber_py|dilithium_py)\b", "PQC library ({g1})", "{g1}"),

    # --- not a quantum issue, but worth reporting ---
    Rule(r"\brandom\.(?:getrandbits|randint|random|choice|randbytes)\(", "random-module RNG", "random",
         note="Non-cryptographic random generator. Use secrets or os.urandom. Not a quantum issue."),
]

RULES = {".py": PY_RULES}  # add ".java": JAVA_RULES, ".go": GO_RULES later


def infer_key_size(text: str):
    """Guess the AES key size from constants in the file. Returns (bits, note) or (None, note)."""
    found = {}  # bits -> note
    for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(\d+)\s*$", text, re.M):
        name, value = m.group(1), int(m.group(2))
        if re.search(r"KEY_(LEN|SIZE|BYTES)", name):
            found[value * 8] = f"key size inferred from {name}"
    for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*b?[\"'](.*)[\"']\s*$", text, re.M):
        name, literal = m.group(1), m.group(2)
        if "KEY" in name:
            found[len(literal) * 8] = f"key size inferred from {name}; hardcoded key in source"
    for m in re.finditer(r"bit_length\s*=\s*(\d+)", text):
        found[int(m.group(1))] = "key size from bit_length"
    if len(found) == 1:
        bits, note = next(iter(found.items()))
        return bits, note
    return None, "AES key size could not be determined" if not found else "several possible AES key sizes found"


def load_versions(root: Path) -> dict:
    """Read pinned library versions from requirements.txt files, e.g. cryptography==46.0.5."""
    versions = {}
    for req in root.rglob("requirements.txt"):
        for line in req.read_text(errors="ignore").splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([\w.]+)", line)
            if m:
                versions[m.group(1).lower()] = m.group(2)
    return versions


def scan_file(path: Path, root: Path, versions: dict) -> list:
    ext = path.suffix
    text = path.read_text(errors="ignore")
    lines = text.splitlines()
    asset = str(path.relative_to(root))
    findings = []

    for i, line in enumerate(lines):
        if line.strip().startswith(COMMENT_PREFIX[ext]):
            continue
        for rule in RULES[ext]:
            m = re.search(rule.pattern, line)
            if not m:
                continue
            g1 = norm(m.group(1)) if m.groups() else ""
            algorithm = rule.algorithm.replace("{g1}", g1)
            library = rule.library.replace("{g1}", g1)
            if library in versions:
                library = f"{library} {versions[library]}"

            notes = [rule.note] if rule.note else []
            key_length = None
            if rule.size_pattern:
                window = "\n".join(lines[i:i + 1 + LOOKAHEAD])
                sm = re.search(rule.size_pattern, window)
                if sm:
                    key_length = int(sm.group(1))
            if rule.infer_size:
                key_length, size_note = infer_key_size(text)
                notes.append(size_note)
            if algorithm.endswith("-ECB"):
                notes.append("ECB mode leaks patterns and is insecure regardless of quantum computers")

            findings.append(Finding(
                source="code", asset=asset, location=f"line {i + 1}", algorithm=algorithm,
                key_length=key_length, library=library, notes="; ".join(notes) or None,
            ))
            if rule.stop:
                break
    return findings


def scan_folder(root) -> list:
    root = Path(root)
    versions = load_versions(root)
    findings = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in RULES and not (set(path.parts) & SKIP_DIRS):
            findings += scan_file(path, root, versions)
    return findings


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "data/samples-repos"
    out = sys.argv[2] if len(sys.argv) > 2 else "output/code_scanner_output.json"
    results = scan_folder(folder)
    for f in results:
        size = f"-{f.key_length}" if f.key_length else ""
        print(f"{f.asset:26} {f.location:9} {f.algorithm}{size:8} [{f.library}]  {f.notes or ''}")
    save_findings(results, out)
    print(f"\n{len(results)} findings saved to {out}")