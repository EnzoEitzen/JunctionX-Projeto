"""
config_scanner.py - cloud configuration scanner.

Reads the three AWS configuration dumps (KMS keys, ACM certificates, load
balancer listeners), extracts the cryptographic essentials from each, wraps
them in the team's shared Finding format (findings.py) and saves them as JSON.

Usage:
    python config_scanner.py
    python config_scanner.py data/cloud-posture
    python config_scanner.py data/cloud-posture output/config_scanner_output.json

Relative paths are resolved from the folder you run the command in.
Requires findings.py in the same folder as this script, and Python 3.10+
(findings.py uses the "int | None" syntax).
"""

import argparse
import json
import os
import re
import sys

from findings import Finding, save_findings

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
DEFAULT_INPUT_DIR = os.path.join("data", "cloud-posture")
DEFAULT_OUTPUT_FILE = os.path.join("output", "config_scanner_output.json")

KMS_FILENAME = "kms_key_inventory.json"
ACM_FILENAME = "acm_certificates.json"
LB_FILENAME = "load_balancer_listeners.json"

# Finding.source value for this scanner.
SOURCE = "cloud"

# Finding.library values: the AWS service each finding comes from.
LIB_KMS = "AWS KMS"
LIB_ACM = "AWS ACM"
LIB_ELB = "AWS ELB"

# KMS SYMMETRIC_DEFAULT is always AES-256-GCM in AWS. The file never states
# the size, so this is an assumption taken from AWS documentation.
SYMMETRIC_DEFAULT_ALGORITHM = "AES-256"
SYMMETRIC_DEFAULT_KEY_LENGTH = 256

# ACM names EC keys by curve, not by bit size, so we map curve -> bits.
ACM_EC_CURVE_BITS = {
    "prime256v1": 256,
    "secp384r1": 384,
    "secp521r1": 521,
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def load_json(path):
    """Load a JSON file. Returns the parsed data, or None if it can't be read.

    A missing or corrupt file is reported and skipped, so one bad file does
    not stop the other two from being scanned.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[WARN] File not found, skipping: {path}")
    except json.JSONDecodeError as exc:
        print(f"[WARN] Invalid JSON in {path}, skipping: {exc}")
    except OSError as exc:
        print(f"[WARN] Could not read {path}, skipping: {exc}")
    return None


def get_list(data, key, filename):
    """Return data[key] if it is a list, otherwise warn and return []."""
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        print(f"[WARN] '{key}' list not found in {filename}, nothing to scan")
        return []
    return data[key]


# --------------------------------------------------------------------------
# Parsers: turn an AWS "spec" string into (algorithm, key_length)
#
# Algorithm names follow the findings README ("normalized family"):
# RSA, ECDSA, AES-256. Elliptic-curve keys are named after what they are
# used for: ECDSA for signing, ECDH for key agreement.
# --------------------------------------------------------------------------
def parse_kms_key_spec(key_spec, key_usage=None):
    """Convert a KMS KeySpec (and KeyUsage) into (algorithm, key_length).

    SYMMETRIC_DEFAULT                -> ("AES-256", 256)  (assumption)
    RSA_2048                         -> ("RSA", 2048)
    ECC_NIST_P256 (SIGN_VERIFY)      -> ("ECDSA", 256)
    ECC_NIST_P256 (KEY_AGREEMENT)    -> ("ECDH", 256)
    ECC_SECG_P256K1                  -> same rule as ECC_NIST
    HMAC_256                         -> ("HMAC", 256)
    anything else                    -> (key_spec, None)  so nothing is lost
    """
    if not isinstance(key_spec, str):
        return None, None

    if key_spec == "SYMMETRIC_DEFAULT":
        return SYMMETRIC_DEFAULT_ALGORITHM, SYMMETRIC_DEFAULT_KEY_LENGTH

    match = re.fullmatch(r"RSA_(\d+)", key_spec)
    if match:
        return "RSA", int(match.group(1))

    match = re.fullmatch(r"ECC_(?:NIST|SECG)_P(\d+)(?:K1)?", key_spec)
    if match:
        algorithm = "ECDH" if key_usage == "KEY_AGREEMENT" else "ECDSA"
        return algorithm, int(match.group(1))

    match = re.fullmatch(r"HMAC_(\d+)", key_spec)
    if match:
        return "HMAC", int(match.group(1))

    return key_spec, None


def parse_acm_key_algorithm(key_algorithm):
    """Convert an ACM KeyAlgorithm into (algorithm, key_length).

    RSA_2048       -> ("RSA", 2048)
    EC_prime256v1  -> ("ECDSA", 256)
    EC_secp384r1   -> ("ECDSA", 384)
    anything else  -> (key_algorithm, None)

    Certificate keys authfenticate the server (signatures), hence ECDSA.
    Accepts both "_" and "-" separators, because the AWS API itself uses
    "RSA-2048" / "EC-prime256v1" while this dataset uses underscores.
    """
    if not isinstance(key_algorithm, str):
        return None, None

    match = re.fullmatch(r"RSA[_-](\d+)", key_algorithm)
    if match:
        return "RSA", int(match.group(1))

    match = re.fullmatch(r"EC[_-](.+)", key_algorithm)
    if match:
        curve = match.group(1)
        bits = ACM_EC_CURVE_BITS.get(curve)
        if bits is None:
            # Unknown curve name: fall back to the first number inside it.
            digits = re.search(r"\d+", curve)
            bits = int(digits.group()) if digits else None
        return "ECDSA", bits

    return key_algorithm, None


# --------------------------------------------------------------------------
# Scanners: each one returns a list of Finding objects
#
# Field mapping (follows the "cloud" row of the findings README):
#   source     -> "cloud"
#   asset      -> alias / certificate domain / load balancer name
#   location   -> "<file>, <field>", e.g. "kms_key_inventory.json, KeySpec"
#   algorithm  -> RSA / ECDSA / ECDH / AES-256 / "TLS Policy"
#   key_length -> bits, or None if unknown / not applicable
#   library    -> "AWS KMS" / "AWS ACM" / "AWS ELB"
#   notes      -> assumptions and the raw policy name
#   risk_tier, replacement -> left at defaults (classifier's job)
# --------------------------------------------------------------------------
def scan_kms(input_dir):
    """KMS: read KeySpec, extract algorithm (RSA/ECDSA/AES-256) and key_length."""
    data = load_json(os.path.join(input_dir, KMS_FILENAME))
    if data is None:
        return []

    findings = []
    for key in get_list(data, "Keys", KMS_FILENAME):
        if not isinstance(key, dict):
            print(f"[WARN] Skipping malformed KMS entry: {key!r}")
            continue

        key_spec = key.get("KeySpec")
        key_id = key.get("KeyId") or key.get("KeyArn") or "unknown"
        name = key.get("AliasName") or key_id

        algorithm, key_length = parse_kms_key_spec(
            key_spec, key.get("KeyUsage"))
        if algorithm is None:
            print(f"[WARN] KMS key {key_id} has no KeySpec, skipping")
            continue

        notes = None
        if key_spec == "SYMMETRIC_DEFAULT":
            notes = "KeySpec SYMMETRIC_DEFAULT: AES-256 assumed (AWS default)"
        elif key_length is None:
            notes = f"Unrecognised KeySpec: {key_spec}"
            print(f"[WARN] KMS key {key_id}: unrecognised KeySpec "
                  f"'{key_spec}', key_length left empty")

        findings.append(Finding(
            source=SOURCE,
            asset=name,
            location=f"{KMS_FILENAME}, KeySpec",
            algorithm=algorithm,
            key_length=key_length,
            library=LIB_KMS,
            notes=notes,
        ))
    return findings


def scan_acm(input_dir):
    """ACM: read KeyAlgorithm, extract algorithm and key_length."""
    data = load_json(os.path.join(input_dir, ACM_FILENAME))
    if data is None:
        return []

    findings = []
    for cert in get_list(data, "Certificates", ACM_FILENAME):
        if not isinstance(cert, dict):
            print(f"[WARN] Skipping malformed ACM entry: {cert!r}")
            continue

        key_algorithm = cert.get("KeyAlgorithm")
        arn = cert.get("CertificateArn") or "unknown"
        name = cert.get("DomainName") or arn

        algorithm, key_length = parse_acm_key_algorithm(key_algorithm)
        if algorithm is None:
            print(f"[WARN] ACM certificate {arn} has no KeyAlgorithm, "
                  f"skipping")
            continue

        notes = None
        if key_length is None:
            notes = f"Unrecognised KeyAlgorithm: {key_algorithm}"
            print(f"[WARN] ACM certificate {arn}: unrecognised "
                  f"KeyAlgorithm '{key_algorithm}', key_length left empty")

        findings.append(Finding(
            source=SOURCE,
            asset=name,
            location=f"{ACM_FILENAME}, KeyAlgorithm",
            algorithm=algorithm,
            key_length=key_length,
            library=LIB_ACM,
            notes=notes,
        ))
    return findings


def scan_load_balancers(input_dir):
    """Load balancers: read SslPolicy, save it as algorithm 'TLS Policy'.

    Finding has no dedicated field for the policy name, so it goes into
    notes as "SslPolicy: <name>; listener port <port>". The port is kept
    because one load balancer can have several TLS listeners, and asset is
    only the load balancer name. Listeners without an SslPolicy (plain
    HTTP) carry no TLS configuration, so they are skipped.
    """
    data = load_json(os.path.join(input_dir, LB_FILENAME))
    if data is None:
        return []

    findings = []
    skipped_no_tls = 0

    for lb in get_list(data, "LoadBalancers", LB_FILENAME):
        if not isinstance(lb, dict):
            print(f"[WARN] Skipping malformed load balancer entry: {lb!r}")
            continue

        lb_name = lb.get("LoadBalancerName") or lb.get("LoadBalancerArn") \
            or "unknown"

        # "or []" guards against a null Listeners value.
        for listener in lb.get("Listeners") or []:
            if not isinstance(listener, dict):
                print(f"[WARN] Skipping malformed listener in {lb_name}: "
                      f"{listener!r}")
                continue

            ssl_policy = listener.get("SslPolicy")
            if not ssl_policy:
                skipped_no_tls += 1
                continue

            notes = f"SslPolicy: {ssl_policy}"
            port = listener.get("Port")
            if port is not None:
                notes += f"; listener port {port}"

            findings.append(Finding(
                source=SOURCE,
                asset=lb_name,
                location=f"{LB_FILENAME}, SslPolicy",
                algorithm="TLS Policy",
                key_length=None,
                library=LIB_ELB,
                notes=notes,
            ))

    if skipped_no_tls:
        print(f"[INFO] {skipped_no_tls} listener(s) without SslPolicy "
              f"(plain HTTP) skipped")
    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Scan AWS KMS, ACM and load balancer configuration "
                    "dumps and save the results as Finding objects.")
    parser.add_argument("input_dir", nargs="?", default=DEFAULT_INPUT_DIR,
                        help=f"folder with the three JSON files "
                             f"(default: {DEFAULT_INPUT_DIR})")
    parser.add_argument("output_file", nargs="?", default=DEFAULT_OUTPUT_FILE,
                        help=f"where to save the findings "
                             f"(default: {DEFAULT_OUTPUT_FILE})")
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"[ERROR] Input directory not found: {args.input_dir}")
        sys.exit(1)

    kms_findings = scan_kms(args.input_dir)
    acm_findings = scan_acm(args.input_dir)
    lb_findings = scan_load_balancers(args.input_dir)
    findings = kms_findings + acm_findings + lb_findings

    # save_findings() creates the output folder if needed.
    save_findings(findings, path=args.output_file)

    print(f"[OK] KMS: {len(kms_findings)} | ACM: {len(acm_findings)} | "
          f"Load balancers: {len(lb_findings)} | Total: {len(findings)}")
    print(f"[OK] Written to {args.output_file}")


if __name__ == "__main__":
    main()
