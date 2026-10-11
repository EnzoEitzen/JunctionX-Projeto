"""Code scanner: finds cryptographic algorithm usage in source code and outputs Finding objects.

Usage:  python code_scanner.py data/code/ [output/results.json]

Python (.py), Go (.go) and Java (.java) are supported. To add another language, write a list of
Rule objects like PY_RULES, register it in RULES, and add its comment style to mask_comments().

How a file is scanned:
  1. Comments (and Python docstrings) are blanked out, so text in them can never create a finding.
  2. Two copies are kept: one with string contents blanked (most rules use this, so a log message
     that mentions "md5" is ignored) and one with strings kept (rules that read a string literal,
     such as Cipher.getInstance("AES/GCM/NoPadding"), use this).
  3. Every line is matched against the rules of its language. Calls that carry the algorithm in
     their arguments (hmac.new(...), PBKDF2HMAC(...)) are read as a whole, even over several lines.
"""
import argparse
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

try:
    from findings import Finding, save_findings      # the team's module name
except ImportError:
    from finding import Finding, save_findings

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "vendor", "target", "build", "dist"}
MAX_BYTES = 2_000_000    # files larger than this are skipped and reported
LOOKAHEAD = 4            # lines after a match that are searched for a key size
CALL_LOOKAHEAD = 12      # lines a single call may span

RNG_NOTE = "Non-cryptographic random generator. Use a cryptographic source instead. Not a quantum issue."
WEAK_KEY_ALGORITHMS = {"RSA", "DSA", "Diffie-Hellman"}


@dataclass
class Rule:
    pattern: str                      # regex matched against one line
    algorithm: str                    # "{g1}" is replaced by the normalized first capture group
    library: str                      # library the call belongs to
    note: str | None = None
    size_pattern: str | None = None   # regex searched in this line + the next few; group is a number or a constant
    call: str | None = None           # pattern must end with "(": this regex is searched inside the whole call
    infer_size: bool = False          # try to infer the AES key size from the rest of the file
    mode_from_file: bool = False      # work out the AES mode from the rest of the file (Go)
    stop: bool = False                # after a match, skip the other rules on this line (and the rest of the call)
    literal: bool | None = None       # True: match against text with string contents; None: decide from the pattern


NAME_MAP = {
    # hashes
    "sha1": "SHA-1", "sha-1": "SHA-1", "sha": "SHA-1", "sha224": "SHA-224", "sha-224": "SHA-224",
    "sha256": "SHA-256", "sha-256": "SHA-256", "sha384": "SHA-384", "sha-384": "SHA-384",
    "sha512": "SHA-512", "sha-512": "SHA-512", "md5": "MD5", "md2": "MD2",
    "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
    # public-key names as written in Java
    "rsa": "RSA", "dsa": "DSA", "ec": "ECDSA/ECDH", "ecdh": "ECDH", "dh": "Diffie-Hellman",
    "diffiehellman": "Diffie-Hellman", "xdh": "XDH", "x25519": "X25519",
    "ed25519": "Ed25519", "ed448": "Ed448", "eddsa": "EdDSA",
}


def norm(name: str) -> str:
    return NAME_MAP.get(name.lower(), name.upper())


def first_group(m) -> str:
    return next((g for g in m.groups() if g), "")


# ---------------------------------------------------------------- Python rules
PY_RSA_SIZE = (r"(?:key_size\s*=\s*(\w+)"                                         # key_size=2048
               r"|generate_private_key\(\s*(?:public_exponent\s*=\s*)?\w+\s*,\s*(\w+)\s*[,)])")  # positional

PY_RULES = [
    # calls whose algorithm is inside their arguments (read as a whole, even over several lines)
    Rule(r"hmac\.(?:new|digest)\(", "HMAC-{g1}", "hmac", stop=True,
         call=r"hashlib\.(\w+)|[\"'](sha\w+|md5)[\"']"),
    Rule(r"PBKDF2HMAC\(", "PBKDF2-HMAC-{g1}", "cryptography", note="password-based key derivation",
         stop=True, call=r"hashes\.(\w+)\("),
    Rule(r"\bCipher\(", "AES-{g1}", "cryptography", infer_size=True, stop=True,
         call=r"algorithms\.AES\([\s\S]*?modes\.(\w+)\("),

    # public-key algorithms (broken by Shor's algorithm)
    Rule(r"rsa\.generate_private_key\(", "RSA", "cryptography", size_pattern=PY_RSA_SIZE),
    Rule(r"padding\.PKCS1v15\(", "RSA-PKCS1v15", "cryptography", note="RSA with legacy PKCS#1 v1.5 padding"),
    Rule(r"padding\.(OAEP|PSS)\(", "RSA-{g1}", "cryptography", note="RSA padding scheme"),
    Rule(r"ec\.generate_private_key\(", "ECDSA/ECDH", "cryptography", size_pattern=r"ec\.SECP(\d+)[RK]1"),
    Rule(r"\bec\.ECDSA\(", "ECDSA", "cryptography"),
    Rule(r"\bec\.ECDH\(", "ECDH", "cryptography"),
    Rule(r"dsa\.generate_private_key\(", "DSA", "cryptography", size_pattern=PY_RSA_SIZE),
    Rule(r"dh\.generate_parameters\(", "Diffie-Hellman", "cryptography", size_pattern=PY_RSA_SIZE),
    Rule(r"ed25519\.Ed25519(?:Private|Public)Key", "Ed25519", "cryptography"),
    Rule(r"x25519\.X25519(?:Private|Public)Key", "X25519", "cryptography"),

    # symmetric ciphers
    Rule(r"AESGCM\(", "AES-GCM", "cryptography", infer_size=True),
    Rule(r"AESCCM\(", "AES-CCM", "cryptography", infer_size=True),
    Rule(r"algorithms\.AES\(", "AES", "cryptography", infer_size=True),
    Rule(r"algorithms\.TripleDES\(", "3DES", "cryptography"),
    Rule(r"algorithms\.ARC4\(", "RC4", "cryptography"),

    # hashes
    Rule(r"hashlib\.new\(\s*[\"'](sha1|sha224|sha256|sha384|sha512|md5|sha3_\d+)[\"']", "{g1}", "hashlib"),
    Rule(r"hashlib\.new\(\s*(?![\"'\s])", "unresolved-hash", "hashlib",
         note="algorithm is chosen at runtime; review manually"),
    Rule(r"hashlib\.(sha1|sha224|sha256|sha384|sha512|md5|sha3_\d+)\b", "{g1}", "hashlib"),
    Rule(r"hashes\.(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|SHA3_\d+)\(", "{g1}", "cryptography"),

    # post-quantum libraries (good news)
    Rule(r"(?:import|from)\s+(oqs|pqcrypto|kyber_py|dilithium_py)\b", "PQC library ({g1})", "{g1}"),

    # not a quantum issue, but worth reporting
    Rule(r"\brandom\.(?:getrandbits|randint|random|choice|randbytes)\(", "random-module RNG", "random", note=RNG_NOTE),
]

# ---------------------------------------------------------------- Go rules
GO_RULES = [
    # calls whose algorithm is inside their arguments
    Rule(r"hmac\.New\(", "HMAC-{g1}", "crypto/hmac", stop=True, call=r"(sha1|sha256|sha512|md5)\.New"),

    # public-key algorithms (broken by Shor's algorithm)
    Rule(r"rsa\.GenerateKey\(", "RSA", "crypto/rsa", size_pattern=r"rsa\.GenerateKey\([^,]*,\s*(\w+)"),
    Rule(r"rsa\.(?:Sign|Verify|Encrypt|Decrypt)PKCS1v15\(", "RSA-PKCS1v15", "crypto/rsa",
         note="RSA with legacy PKCS#1 v1.5 padding"),
    Rule(r"rsa\.(?:EncryptOAEP|DecryptOAEP|SignPSS|VerifyPSS)\(", "RSA", "crypto/rsa",
         note="RSA encryption or signature (OAEP/PSS padding)"),
    Rule(r"ecdsa\.(?:GenerateKey|Sign|Verify|SignASN1|VerifyASN1)\(", "ECDSA", "crypto/ecdsa",
         size_pattern=r"elliptic\.P(\d+)\("),
    Rule(r"ecdh\.P(?:256|384|521)\(", "ECDH", "crypto/ecdh", size_pattern=r"ecdh\.P(\d+)\("),
    Rule(r"(?:ecdh|curve25519)\.X25519\(", "X25519", "crypto/ecdh"),
    Rule(r"\bdsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\(", "DSA", "crypto/dsa"),
    Rule(r"ed25519\.(?:GenerateKey|NewKeyFromSeed|Sign|Verify)\(", "Ed25519", "crypto/ed25519"),

    # symmetric ciphers: the mode and key size are worked out from the rest of the file
    Rule(r"aes\.NewCipher\(", "AES", "crypto/aes", infer_size=True, mode_from_file=True),
    Rule(r"\bdes\.NewTripleDESCipher\(", "3DES", "crypto/des"),
    Rule(r"\bdes\.NewCipher\(", "DES", "crypto/des"),
    Rule(r"\brc4\.NewCipher\(", "RC4", "crypto/rc4"),

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

    # not a quantum issue, but worth reporting (an import alias is allowed: mrand "math/rand")
    Rule(r'^\s*(?:import\s+)?(?:\w+\s+)?"math/rand(?:/v2)?"', "math/rand RNG", "math/rand", note=RNG_NOTE),
]

# ---------------------------------------------------------------- Java rules
JAVA_SIZE = (r"(?:initialize\(\s*(\w+)\s*[,)]"       # kpg.initialize(2048) or a constant
             r"|RSAKeyGenParameterSpec\(\s*(\w+)"       # new RSAKeyGenParameterSpec(2048, ...)
             r"|(?:secp|prime|P-?)(\d{3}))")             # secp256r1, P-256, prime256v1

JAVA_RULES = [
    # signatures: one finding for the scheme and one for the hash it uses
    Rule(r'Signature\.getInstance\("(?:MD5|SHA\d+)withRSA"', "RSA-PKCS1v15", "java.security",
         note="RSA signature with legacy PKCS#1 v1.5 padding"),
    Rule(r'Signature\.getInstance\("RSASSA-PSS"', "RSA-PSS", "java.security", note="RSA signature (PSS padding)"),
    Rule(r'Signature\.getInstance\("\w+withECDSA"', "ECDSA", "java.security"),
    Rule(r'Signature\.getInstance\("\w+withDSA"', "DSA", "java.security"),
    Rule(r'Signature\.getInstance\("(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)with', "{g1}", "java.security"),
    Rule(r'(?:Signature|KeyFactory|KeyPairGenerator)\.getInstance\("(Ed25519|Ed448|EdDSA)"', "{g1}", "java.security"),

    # public-key algorithms (broken by Shor's algorithm)
    Rule(r'KeyPairGenerator\.getInstance\("(RSA|DSA|EC|DH|DiffieHellman|XDH|X25519)"', "{g1}", "java.security",
         size_pattern=JAVA_SIZE),
    Rule(r'KeyFactory\.getInstance\("(RSA|DSA|EC|DH|DiffieHellman|XDH|X25519)"', "{g1}", "java.security",
         note="key parsed or loaded from encoded form"),
    Rule(r'KeyAgreement\.getInstance\("(ECDH|DH|DiffieHellman|X25519|XDH)"', "{g1}", "javax.crypto"),

    # combined calls
    Rule(r'Mac\.getInstance\("Hmac(SHA1|SHA224|SHA256|SHA384|SHA512|MD5)"', "HMAC-{g1}", "javax.crypto"),
    Rule(r'SecretKeyFactory\.getInstance\("PBKDF2WithHmac(SHA1|SHA224|SHA256|SHA384|SHA512)"',
         "PBKDF2-HMAC-{g1}", "javax.crypto", note="password-based key derivation"),

    # symmetric ciphers (the transformation may be a constant, see string_constants)
    Rule(r'Cipher\.getInstance\("AES(?:_\d+)?/(\w+)/', "AES-{g1}", "javax.crypto", infer_size=True),
    Rule(r'Cipher\.getInstance\("AES(?:_\d+)?"\s*[,)]', "AES-ECB", "javax.crypto", infer_size=True,
         note="no mode given: Java defaults to ECB"),
    Rule(r'Cipher\.getInstance\("(?:DESede|TripleDES)', "3DES", "javax.crypto"),
    Rule(r'Cipher\.getInstance\("DES(?:/|"\s*[,)])', "DES", "javax.crypto"),
    Rule(r'Cipher\.getInstance\("(?:RC4|ARCFOUR)', "RC4", "javax.crypto"),
    Rule(r'Cipher\.getInstance\("RSA', "RSA", "javax.crypto", note="RSA encryption"),

    # hashes
    Rule(r'MessageDigest\.getInstance\("(SHA-1|SHA1|SHA|MD5|MD2|SHA-224|SHA-256|SHA-384|SHA-512)"', "{g1}", "java.security"),
    Rule(r'MessageDigest\.getInstance\("(SHA3-\d+)"', "{g1}", "java.security"),

    # an algorithm name that is not a string literal cannot be read: say so instead of staying silent
    Rule(r'\b(Cipher|MessageDigest|Signature|KeyPairGenerator|KeyFactory|KeyAgreement|Mac|SecretKeyFactory)'
         r'\.getInstance\((?!\s*")', "unresolved-{raw1}", "java.security", literal=False,
         note="algorithm name is not a string literal; review manually"),

    # post-quantum (good news)
    Rule(r'(?:KeyPairGenerator|KEM|Signature)\.getInstance\("(ML-KEM(?:-\d+)?|ML-DSA(?:-\d+)?|SLH-DSA[\w-]*)"',
         "{g1}", "java.security", note="NIST post-quantum standard"),
    Rule(r'import\s+org\.bouncycastle\.pqc', "PQC library (BouncyCastle)", "bouncycastle"),

    # not a quantum issue, but worth reporting
    Rule(r'\bnew\s+Random\(|\bMath\.random\(|\bThreadLocalRandom\b', "java.util.Random RNG", "java.util", note=RNG_NOTE),
]

RULES = {".py": PY_RULES, ".go": GO_RULES, ".java": JAVA_RULES}
FLAGS = {".py": 0, ".go": 0, ".java": re.I}   # Java algorithm names are case-insensitive

# (rule, compiled pattern, compiled call pattern, needs string contents)
COMPILED = {
    ext: [(r, re.compile(r.pattern, FLAGS[ext]),
           re.compile(r.call, FLAGS[ext] | re.S) if r.call else None,
           any(q in r.pattern for q in "\"'") if r.literal is None else r.literal)
          for r in rules]
    for ext, rules in RULES.items()
}


# ---------------------------------------------------------------- text preparation
def _blank(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


def mask_comments(text: str, ext: str, keep_strings: bool) -> str:
    """Return text of the same length with comments blanked out (Python docstrings too).

    keep_strings=False also blanks the inside of string literals. Newlines are never touched, so line
    numbers stay correct."""
    line_comment = "#" if ext == ".py" else "//"
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith(line_comment, i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif ext in (".go", ".java") and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(_blank(text[i:j]))
            i = j
        elif ext == ".py" and text.startswith(('"""', "'''"), i):          # docstring or other triple string
            j = text.find(text[i:i + 3], i + 3)
            j = n if j == -1 else j + 3
            out.append(_blank(text[i:j]))
            i = j
        elif (ext == ".java" and text.startswith('"""', i)) or (ext == ".go" and c == "`"):
            closer = '"""' if ext == ".java" else "`"                      # Java text block / Go raw string
            j = text.find(closer, i + len(closer))
            j = n if j == -1 else j + len(closer)
            s = text[i:j]
            out.append(s if keep_strings else _blank(s))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            s = text[i:j]
            if not keep_strings:
                s = s[0] + _blank(s[1:-1]) + s[-1] if len(s) >= 2 and s[-1] == c else s[0] + _blank(s[1:])
            out.append(s)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


ALIASABLE = {"hashlib", "hmac", "random", "rsa", "ec", "dsa", "dh", "ed25519", "x25519", "hashes", "padding"}


def python_alias_map(code: str) -> dict:
    """Map local names to the names the rules expect, e.g. 'import hashlib as hl' -> hl = hashlib,
    'from hashlib import sha1' -> sha1 = hashlib.sha1."""
    amap = {}
    for m in re.finditer(r"^[ \t]*import\s+([\w.]+)\s+as\s+(\w+)", code, re.M):
        last = m.group(1).split(".")[-1]
        if last in ALIASABLE:
            amap[m.group(2)] = last
    for m in re.finditer(r"^[ \t]*from\s+([\w.]+)\s+import\s+(\([^)]*\)|[^\n]+)", code, re.M):
        last = m.group(1).split(".")[-1]
        for part in re.split(r"[,\n]", m.group(2).strip("()")):
            nm = re.match(r"\s*(\w+)(?:\s+as\s+(\w+))?\s*$", part)
            if not nm:
                continue
            name, alias = nm.group(1), nm.group(2) or nm.group(1)
            if name in ALIASABLE:
                if alias != name:
                    amap[alias] = name
            elif last in ALIASABLE:
                amap[alias] = f"{last}.{name}"
    return amap


def apply_aliases(code_line: str, lit_line: str, alias_re, amap: dict):
    """Rewrite aliased names in both copies of a line in the same places."""
    out_c, out_l, last = [], [], 0
    for m in alias_re.finditer(code_line):
        out_c += [code_line[last:m.start()], amap[m.group(1)]]
        out_l += [lit_line[last:m.start()], amap[m.group(1)]]
        last = m.end()
    out_c.append(code_line[last:])
    out_l.append(lit_line[last:])
    return "".join(out_c), "".join(out_l)


def balanced_call(text: str, open_idx: int) -> str:
    """Return the text of a call from its opening parenthesis to the matching closing one."""
    depth, quote, i = 0, None, open_idx
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx:i + 1]
        i += 1
    return text[open_idx:]


# ---------------------------------------------------------------- constants and inference
def int_constants(text: str, ext: str) -> dict:
    """Integer constants in the file, so that initialize(KEY_BITS) can be resolved to a number."""
    if ext == ".java":
        pattern = r"(?:static\s+)?(?:final\s+)?int\s+(\w+)\s*=\s*(\d+)\s*;"
    else:
        pattern = r"^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)\s*=\s*(\d+)\s*$"
    return {m.group(1): int(m.group(2)) for m in re.finditer(pattern, text, re.M)}


def string_constants(text: str, ext: str) -> dict:
    """Java string constants, so that Cipher.getInstance(TRANSFORMATION) can be read as its literal."""
    if ext != ".java":
        return {}
    pattern = r'(?:static\s+)?(?:final\s+)?String\s+(\w+)\s*=\s*"([^"\n]*)"\s*;'
    return {m.group(1): m.group(2) for m in re.finditer(pattern, text)}


def substitute_constants(line: str, str_consts: dict) -> str:
    return re.sub(r"getInstance\((\w+)",
                  lambda m: f'getInstance("{str_consts[m.group(1)]}"' if m.group(1) in str_consts else m.group(0),
                  line)


def infer_key_size(text: str, ext: str):
    """Guess the AES key size from constants and key variables in the file. Returns (bits, note)."""
    found = {}  # bits -> note
    consts = int_constants(text, ext)

    def size_of(value):
        return int(value) if value.isdigit() else consts.get(value)

    if ext == ".py":
        for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(\d+)\s*$", text, re.M):
            name, value = m.group(1), int(m.group(2))
            if re.search(r"KEY_(LEN|SIZE|BYTES)", name):
                found.setdefault(value * 8, f"key size inferred from {name}")
        for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*b?[\"'](.*)[\"']\s*$", text, re.M):
            if "KEY" in m.group(1):
                found.setdefault(len(m.group(2)) * 8, f"key size inferred from {m.group(1)}; hardcoded key in source")
        for m in re.finditer(r"bit_length\s*=\s*(\d+)", text):
            found.setdefault(int(m.group(1)), "key size from bit_length")
        for m in re.finditer(r"(\w*key\w*)\s*=\s*(?:os\.urandom|secrets\.token_bytes)\(\s*(\w+)\s*\)", text, re.I):
            size = size_of(m.group(2))
            if size:
                found.setdefault(size * 8, f"key size inferred from {m.group(1)}")
    elif ext == ".go":
        for m in re.finditer(r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*(\d+)\s*$", text, re.M):
            name, value = m.group(1), int(m.group(2))
            if re.search(r"(?i)key_?(len|size|bytes)", name):
                found.setdefault(value * 8, f"key size inferred from {name}")
        for m in re.finditer(r'^(?:var|const)\s+([A-Za-z_]\w*)\s*=\s*\[\]byte\("(.*)"\)', text, re.M):
            if "key" in m.group(1).lower():
                found.setdefault(len(m.group(2)) * 8, f"key size inferred from {m.group(1)}; hardcoded key in source")
        for m in re.finditer(r"(\w*key\w*)\s*:?=\s*make\(\[\]byte,\s*(\w+)\)", text, re.I):
            size = size_of(m.group(2))
            if size:
                found.setdefault(size * 8, f"key size inferred from {m.group(1)}")
    elif ext == ".java":
        for m in re.finditer(r"(?:static\s+)?(?:final\s+)?int\s+(\w+)\s*=\s*(\d+)\s*;", text):
            name, value = m.group(1), int(m.group(2))
            low = name.lower()
            if "key" not in low:
                continue
            if "bits" in low:
                found.setdefault(value, f"key size inferred from {name}")
            elif re.search(r"len|bytes", low):
                found.setdefault(value * 8, f"key size inferred from {name}")
            elif "size" in low:
                found.setdefault(value if value in (128, 192, 256) else value * 8, f"key size inferred from {name}")
        for m in re.finditer(r'byte\[\]\s+(\w+)\s*=\s*"(.*?)"\.getBytes', text):
            if "key" in m.group(1).lower():
                found.setdefault(len(m.group(2)) * 8, f"key size inferred from {m.group(1)}; hardcoded key in source")
        for m in re.finditer(r"\.init\(\s*(128|192|256)\b", text):
            found.setdefault(int(m.group(1)), "key size from KeyGenerator.init")
        for m in re.finditer(r"byte\[\]\s+(\w*key\w*)\s*=\s*new\s+byte\[\s*(\w+)\s*\]", text, re.I):
            size = size_of(m.group(2))
            if size:
                found.setdefault(size * 8, f"key size inferred from {m.group(1)}")

    found = {bits: note for bits, note in found.items() if bits in (128, 192, 256)}  # valid AES sizes only
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


# ---------------------------------------------------------------- library versions
@lru_cache(maxsize=None)
def dir_versions(directory: Path) -> dict:
    """Versions declared by the manifests in one directory: requirements.txt, go.mod, pom.xml, build.gradle."""
    versions = {}

    def read(name):
        p = directory / name
        return p.read_text(encoding="utf-8-sig", errors="replace") if p.is_file() else ""

    for line in read("requirements.txt").splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*([\w.]+)", line)
        if m:
            name, op, ver = m.groups()
            versions[name.lower().replace("_", "-")] = ver if op == "==" else f"{op}{ver}"

    text = read("go.mod")
    m = re.search(r"^go\s+([\d.]+)", text, re.M)
    if m:
        versions["go"] = m.group(1)
    for dep in re.finditer(r"^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+(v[\w.+-]+)", text, re.M):
        versions[dep.group(1)] = dep.group(2)

    text = read("pom.xml")
    m = re.search(r"<(?:java\.version|maven\.compiler\.(?:release|source|target)|release)>\s*([\d.]+)\s*<", text)
    if m:
        versions["java"] = m.group(1)
    for dep in re.finditer(r"<artifactId>\s*(bc[\w.-]+)\s*</artifactId>\s*<version>\s*([\w.]+)\s*</version>", text):
        versions["bouncycastle"] = dep.group(2)

    text = read("build.gradle") or read("build.gradle.kts")
    m = re.search(r"(?:sourceCompatibility\s*=\s*(?:JavaVersion\.VERSION_)?['\"]?|JavaLanguageVersion\.of\()([\d_.]+)", text)
    if m:
        versions["java"] = m.group(1).replace("_", ".")
    return versions


def versions_for(path: Path, root: Path) -> dict:
    """Versions that apply to a file: manifests from the scan root down to the file's folder, nearest wins."""
    chain, d = [], path.parent
    while True:
        chain.append(d)
        if d == root or d == d.parent:
            break
        d = d.parent
    merged = {}
    for directory in reversed(chain):
        merged.update(dir_versions(directory))
    return merged


def label_library(library: str, ext: str, versions: dict) -> str:
    if library in versions:
        return f"{library} {versions[library]}"
    if ext == ".go" and library.startswith(("crypto/", "math/")) and "go" in versions:
        return f"{library} (Go {versions['go']})"
    if ext == ".java" and library.startswith(("java.", "javax.")) and "java" in versions:
        return f"{library} (Java {versions['java']})"
    return library


# ---------------------------------------------------------------- scanning
def scan_text(text: str, ext: str, asset: str = "<text>", versions: dict | None = None) -> list:
    """Scan source text of one language and return its findings."""
    versions = versions or {}
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lit = mask_comments(text, ext, keep_strings=True)
    code = mask_comments(text, ext, keep_strings=False)
    lit_lines, code_lines = lit.split("\n"), code.split("\n")

    if ext == ".py":
        amap = python_alias_map(code)
        if amap:
            alias_re = re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, amap)) + r")(?=\s*[.(])")
            for i, (c, l) in enumerate(zip(code_lines, lit_lines)):
                if not re.match(r"\s*(?:from|import)\b", c):
                    code_lines[i], lit_lines[i] = apply_aliases(c, l, alias_re, amap)

    consts = int_constants(lit, ext)
    str_consts = string_constants(lit, ext)
    findings, skip_until = [], -1

    for i, (code_line, lit_line) in enumerate(zip(code_lines, lit_lines)):
        if i <= skip_until or not code_line.strip():
            continue
        lit_match_line = substitute_constants(lit_line, str_consts) if str_consts else lit_line
        code_match_line = substitute_constants(code_line, str_consts) if str_consts else code_line
        for rule, rx, call_rx, needs_strings in COMPILED[ext]:
            m = rx.search(lit_match_line if needs_strings else code_match_line)
            if not m:
                continue
            span_end = i
            if call_rx:                                    # read the whole call, even over several lines
                window = "\n".join(lit_lines[i:i + CALL_LOOKAHEAD])
                call = balanced_call(window, m.end() - 1)
                m = call_rx.search(call)
                if not m:
                    continue
                span_end = i + call.count("\n")

            g1 = norm(first_group(m)) if m.groups() else ""
            algorithm = rule.algorithm.replace("{g1}", g1).replace("{raw1}", first_group(m) if m.groups() else "")
            library = label_library(rule.library.replace("{g1}", g1), ext, versions)

            notes = [rule.note] if rule.note else []
            key_length = None
            if rule.size_pattern:
                window = "\n".join(lit_lines[i:i + 1 + LOOKAHEAD])
                sm = re.search(rule.size_pattern, window, FLAGS[ext])
                if sm:
                    value = first_group(sm)
                    key_length = int(value) if value.isdigit() else consts.get(value)
                    if key_length is None:
                        notes.append(f"key size is set by '{value}', which could not be resolved")
            if rule.mode_from_file:
                mode, mode_note = detect_aes_mode(lit, ext)
                if mode:
                    algorithm = f"AES-{mode}"
                if mode_note:
                    notes.append(mode_note)
            if rule.infer_size:
                key_length, size_note = infer_key_size(lit, ext)
                notes.append(size_note)
            if algorithm.endswith("-ECB"):
                notes.append("ECB mode leaks patterns and is insecure regardless of quantum computers")
            if algorithm in WEAK_KEY_ALGORITHMS and key_length and key_length < 2048:
                notes.append(f"{key_length}-bit key is weak even for classical computers")

            findings.append(Finding(
                source="code", asset=asset, location=f"line {i + 1}", algorithm=algorithm,
                key_length=key_length, library=library, notes="; ".join(notes) or None,
            ))
            if rule.stop:
                skip_until = max(skip_until, span_end)     # the rest of this call is already covered
                break
    return findings


def scan_file(path: Path, root: Path) -> list:
    """Scan one file. Raises OSError / ValueError if it cannot be read."""
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"larger than {MAX_BYTES // 1_000_000} MB")
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    asset = path.relative_to(root).as_posix() if path != root else path.name
    return scan_text(text, path.suffix.lower(), asset, versions_for(path, root))


def source_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in RULES:
            if not (set(path.relative_to(root).parts[:-1]) & SKIP_DIRS):   # only folders inside the scan root
                yield path


def scan_folder(root, skipped: list | None = None) -> list:
    """Scan a folder (or a single file). Files that cannot be read are added to `skipped` as (path, reason)."""
    root = Path(root)
    dir_versions.cache_clear()
    base = root.parent if root.is_file() else root
    findings = []
    for path in source_files(root):
        try:
            findings += scan_file(path, base if path != root else path.parent)
        except (OSError, ValueError) as err:
            if skipped is not None:
                skipped.append((str(path), str(err)))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Find cryptographic algorithms in Python, Go and Java source code.")
    ap.add_argument("folder", nargs="?", default="data/code", help="folder or file to scan (default: data/code)")
    ap.add_argument("out", nargs="?", default="output/results.json", help="results file (default: output/results.json)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    args = ap.parse_args(argv)

    root = Path(args.folder)
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    skipped = []
    results = scan_folder(root, skipped)
    if not args.quiet and results:
        w_asset = max(len(f.asset) for f in results)
        for f in results:
            size = f"-{f.key_length}" if f.key_length else ""
            print(f"{f.asset:{w_asset}}  {f.location:9}  {f.algorithm + size:24} [{f.library}]  {f.notes or ''}")
        print()
    for path, reason in skipped:
        print(f"warning: skipped {path} ({reason})", file=sys.stderr)
    if not results:
        print(f"no findings in {root} (looked at {', '.join(sorted(RULES))} files)")
    save_findings(results, args.out)
    print(f"{len(results)} findings saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())