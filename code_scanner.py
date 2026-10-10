"""Code scanner: finds cryptographic algorithm usage in source code and outputs Finding objects.

Usage:  python code_scanner.py data/code/ [output/results.json]

Python (.py) and Go (.go) rules are filled in. To add Java, write a list of Rule objects like
PY_RULES and register it in RULES below.
"""
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from findings import Finding, save_findings

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "vendor"}
COMMENT_PREFIX = {".py": "#", ".go": "//"}
LOOKAHEAD = 4  # how many following lines to search for a key size

RNG_NOTE = "Non-cryptographic random generator. Use a cryptographic source instead. Not a quantum issue."


@dataclass
class Rule:
    pattern: str                      # regex matched against one line
    algorithm: str                    # "{g1}" is replaced by the normalized first capture group
    library: str                      # library the call belongs to
    note: str | None = None
    size_pattern: str | None = None   # regex (one capture group) searched in this line + next lines
    infer_size: bool = False          # try to infer the AES key size from constants in the file
    mode_from_file: bool = False      # work out the AES mode from the rest of the file (Go)
    stop: bool = False                # do not check further rules on this line after a match


HASH_NAMES = {
    "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "md5": "MD5", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
}


def norm(name: str) -> str:
    return HASH_NAMES.get(name.lower(), name.upper())


# ---------------------------------------------------------------- Python rules
PY_RULES = [
    # combined calls first (stop=True so the generic hash/AES rules don't also fire)
    Rule(r"hmac\.new\(.*hashlib\.(\w+)", "HMAC-{g1}", "hmac", stop=True),
    Rule(r"PBKDF2HMAC\(.*hashes\.(\w+)\(", "PBKDF2-HMAC-{g1}", "cryptography",
         note="password-based key derivation", stop=True),
    Rule(r"algorithms\.AES\(.*modes\.(\w+)\(", "AES-{g1}", "cryptography", infer_size=True, stop=True),

    # public-key algorithms (broken by Shor's algorithm)
    Rule(r"rsa\.generate_private_key\(", "RSA", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"padding\.PKCS1v15\(", "RSA-PKCS1v15", "cryptography", note="RSA with legacy PKCS#1 v1.5 padding"),
    Rule(r"ec\.generate_private_key\(", "ECDSA/ECDH", "cryptography", size_pattern=r"ec\.SECP(\d+)R1"),
    Rule(r"dsa\.generate_private_key\(", "DSA", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"dh\.generate_parameters\(", "Diffie-Hellman", "cryptography", size_pattern=r"key_size\s*=\s*(\d+)"),
    Rule(r"ed25519\.Ed25519(?:Private|Public)Key", "Ed25519", "cryptography"),
    Rule(r"x25519\.X25519(?:Private|Public)Key", "X25519", "cryptography"),

    # symmetric ciphers
    Rule(r"AESGCM\(", "AES-GCM", "cryptography", infer_size=True),
    Rule(r"algorithms\.AES\(", "AES", "cryptography", infer_size=True),

    # hashes
    Rule(r"hashlib\.(sha1|sha224|sha256|sha384|sha512|md5|sha3_\d+)\b", "{g1}", "hashlib"),
    Rule(r"hashes\.(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|SHA3_\d+)\(", "{g1}", "cryptography"),

    # post-quantum libraries (good news)
    Rule(r"(?:import|from)\s+(oqs|pqcrypto|kyber_py|dilithium_py)\b", "PQC library ({g1})", "{g1}"),

    # not a quantum issue, but worth reporting
    Rule(r"\brandom\.(?:getrandbits|randint|random|choice|randbytes)\(", "random-module RNG", "random", note=RNG_NOTE),
]

# ---------------------------------------------------------------- Go rules
GO_RULES = [
    # combined call first
    Rule(r"hmac\.New\(\s*(sha1|sha256|sha512|md5)\.New", "HMAC-{g1}", "crypto/hmac", stop=True),

    # public-key algorithms (broken by Shor's algorithm)
    Rule(r"rsa\.GenerateKey\(", "RSA", "crypto/rsa", size_pattern=r"rsa\.GenerateKey\([^,]*,\s*(\d+)"),
    Rule(r"rsa\.(?:Sign|Verify|Encrypt|Decrypt)PKCS1v15\(", "RSA-PKCS1v15", "crypto/rsa",
         note="RSA with legacy PKCS#1 v1.5 padding"),
    Rule(r"ecdsa\.(?:GenerateKey|Sign|Verify|SignASN1|VerifyASN1)\(", "ECDSA", "crypto/ecdsa",
         size_pattern=r"elliptic\.P(\d+)\("),
    Rule(r"ecdh\.P(?:256|384|521)\(", "ECDH", "crypto/ecdh", size_pattern=r"ecdh\.P(\d+)\("),
    Rule(r"(?:ecdh|curve25519)\.X25519\(", "X25519", "crypto/ecdh"),
    Rule(r"\bdsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\(", "DSA", "crypto/dsa"),
    Rule(r"ed25519\.(?:GenerateKey|NewKeyFromSeed|Sign|Verify)\(", "Ed25519", "crypto/ed25519"),

    # symmetric ciphers: the mode and key size are worked out from the rest of the file
    Rule(r"aes\.NewCipher\(", "AES", "crypto/aes", infer_size=True, mode_from_file=True),

    # hashes
    Rule(r"\bsha1\.(?:New|Sum)\(", "SHA-1", "crypto/sha1"),
    Rule(r"\bmd5\.(?:New|Sum)\(", "MD5", "crypto/md5"),
    Rule(r"\bsha256\.(?:New|Sum256)\(", "SHA-256", "crypto/sha256"),
    Rule(r"\bsha256\.(?:New224|Sum224)\(", "SHA-224", "crypto/sha256"),
    Rule(r"\bsha512\.(?:New384|Sum384)\(", "SHA-384", "crypto/sha512"),
    Rule(r"\bsha512\.(?:New|Sum512)\(", "SHA-512", "crypto/sha512"),

    # post-quantum libraries (good news)
    Rule(r'"crypto/mlkem"', "ML-KEM", "crypto/mlkem", note="NIST FIPS 203"),
    Rule(r'"github\.com/cloudflare/circl/(?:kem|sign)/(\w+)', "PQC library ({g1})", "github.com/cloudflare/circl"),

    # not a quantum issue, but worth reporting
    Rule(r'^\s*"math/rand(?:/v2)?"', "math/rand RNG", "math/rand", note=RNG_NOTE),
]

RULES = {".py": PY_RULES, ".go": GO_RULES}  # add ".java": JAVA_RULES later


# ---------------------------------------------------------------- helpers
def infer_key_size(text: str, ext: str):
    """Guess the AES key size from constants in the file. Returns (bits, note) or (None, note)."""
    found = {}  # bits -> note
    if ext == ".py":
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
    elif ext == ".go":
        for m in re.finditer(r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*(\d+)\s*$", text, re.M):
            name, value = m.group(1), int(m.group(2))
            if re.search(r"(?i)key_?(len|size|bytes)", name):
                found[value * 8] = f"key size inferred from {name}"
        for m in re.finditer(r'^(?:var|const)\s+([A-Za-z_]\w*)\s*=\s*\[\]byte\("(.*)"\)', text, re.M):
            name, literal = m.group(1), m.group(2)
            if "key" in name.lower():
                found[len(literal) * 8] = f"key size inferred from {name}; hardcoded key in source"
    if len(found) == 1:
        return next(iter(found.items()))
    return None, "AES key size could not be determined" if not found else "several possible AES key sizes found"


def detect_aes_mode(text: str, ext: str):
    """Work out the AES mode for Go, where it is chosen by a separate call. Returns (mode, note)."""
    if ext != ".go":
        return None, None
    if re.search(r"cipher\.NewGCM", text):
        return "GCM", None
    for name in ("CBC", "CFB", "CTR", "OFB"):
        if re.search(rf"cipher\.New{name}", text):
            return name, None
    if re.search(r"\bblock\.Encrypt\(", text):
        return "ECB", "no cipher mode is used: block.Encrypt is called one block at a time, which is ECB"
    return None, "AES mode could not be determined"


def load_versions(root: Path) -> dict:
    """Read pinned library versions: requirements.txt (Python) and go.mod (Go)."""
    versions = {}
    for req in root.rglob("requirements.txt"):
        for line in req.read_text(errors="ignore").splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([\w.]+)", line)
            if m:
                versions[m.group(1).lower()] = m.group(2)
    for mod in root.rglob("go.mod"):
        text = mod.read_text(errors="ignore")
        m = re.search(r"^go\s+([\d.]+)", text, re.M)
        if m:
            versions["go"] = m.group(1)
        for dep in re.finditer(r"^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+(v[\w.+-]+)", text, re.M):
            versions[dep.group(1)] = dep.group(2)
    return versions


def label_library(library: str, ext: str, versions: dict) -> str:
    if library in versions:
        return f"{library} {versions[library]}"
    if ext == ".go" and library.startswith(("crypto/", "math/")) and "go" in versions:
        return f"{library} (Go {versions['go']})"
    return library


# ---------------------------------------------------------------- scanning
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
            library = label_library(rule.library.replace("{g1}", g1), ext, versions)

            notes = [rule.note] if rule.note else []
            key_length = None
            if rule.size_pattern:
                window = "\n".join(lines[i:i + 1 + LOOKAHEAD])
                sm = re.search(rule.size_pattern, window)
                if sm:
                    key_length = int(sm.group(1))
            if rule.mode_from_file:
                mode, mode_note = detect_aes_mode(text, ext)
                if mode:
                    algorithm = f"AES-{mode}"
                if mode_note:
                    notes.append(mode_note)
            if rule.infer_size:
                key_length, size_note = infer_key_size(text, ext)
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
    folder = sys.argv[1] if len(sys.argv) > 1 else "data/code"
    out = sys.argv[2] if len(sys.argv) > 2 else "output/results.json"
    results = scan_folder(folder)
    for f in results:
        size = f"-{f.key_length}" if f.key_length else ""
        print(f"{f.asset:34} {f.location:9} {f.algorithm}{size:6} [{f.library}]  {f.notes or ''}")
    save_findings(results, out)
    print(f"\n{len(results)} findings saved to {out}")