"""export_cbom_lib.py - converte results.json num CBOM com a biblioteca oficial
cyclonedx-python-lib (CycloneDX 1.6) e valida o resultado contra o schema.

Instalar:
    pip install "cyclonedx-python-lib[json-validation]"

Uso:
    python export_cbom_lib.py                      # le todos os .json de output/
    python export_cbom_lib.py output -o output/cbom.json
    python export_cbom_lib.py results.json         # tambem aceita um ficheiro
"""
import argparse
import json
import sys
from pathlib import Path

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesType,
)
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion

# "evidence.occurrences" so existe em versoes recentes da biblioteca.
# Se nao existir, a localizacao vai para as properties.
try:
    from cyclonedx.model.component import ComponentEvidence, Occurrence
except ImportError:
    ComponentEvidence = Occurrence = None

# Valores validos de "primitive" no CycloneDX 1.6, deduzidos pelo nome do algoritmo
PRIMITIVE_HINTS = [
    ("mlkem", "kem"), ("ml-kem", "kem"),
    ("ml-dsa", "signature"), ("slh-dsa", "signature"),
    ("ecdsa", "signature"), ("ed25519", "signature"), ("dsa", "signature"),
    ("x25519", "key-agree"), ("ecdh", "key-agree"), ("diffie", "key-agree"),
    ("hmac", "mac"),
    ("pbkdf2", "kdf"), ("scrypt", "kdf"), ("argon", "kdf"),
    ("gcm", "ae"),
    ("aes", "block-cipher"), ("3des", "block-cipher"),
    ("rsa", "pke"),
    ("sha", "hash"), ("md5", "hash"),
]

ASSET_TYPE_BY_SOURCE = {
    "network": "protocol",
    "acm": "certificate",
    "kms": "related-crypto-material",
    "code": "algorithm",
}


def guess_primitive(algorithm):
    alg = str(algorithm).lower()
    for hint, primitive in PRIMITIVE_HINTS:
        if hint in alg:
            return CryptoPrimitive(primitive)
    return CryptoPrimitive.OTHER


def build_component(item, index):
    algorithm = item.get("algorithm", "")
    source = str(item.get("source", "")).lower()
    asset_type = ASSET_TYPE_BY_SOURCE.get(source, "algorithm")

    crypto_kwargs = {"asset_type": CryptoAssetType(asset_type)}
    if asset_type == "algorithm":
        algo_kwargs = {"primitive": guess_primitive(algorithm)}
        if item.get("key_length"):
            algo_kwargs["parameter_set_identifier"] = str(item["key_length"])
        crypto_kwargs["algorithm_properties"] = AlgorithmProperties(**algo_kwargs)
    elif asset_type == "protocol":
        crypto_kwargs["protocol_properties"] = ProtocolProperties(type=ProtocolPropertiesType("tls"))

    extras = {
        "quantumtrace:risk-tier": item.get("risk_tier"),
        "quantumtrace:replacement": item.get("replacement"),
        "quantumtrace:algorithm": algorithm,
        "quantumtrace:library": item.get("library"),
        "quantumtrace:source": source,
    }

    component_kwargs = {
        "name": item.get("asset", "Unknown Asset"),
        "type": ComponentType.CRYPTOGRAPHIC_ASSET,
        "bom_ref": f"crypto-{index}",
        "crypto_properties": CryptoProperties(**crypto_kwargs),
    }

    location = item.get("location")
    if location:
        try:
            component_kwargs["evidence"] = ComponentEvidence(occurrences=[Occurrence(location=location)])
        except (TypeError, NameError):
            extras["quantumtrace:location"] = location

    component_kwargs["properties"] = [
        Property(name=k, value=str(v)) for k, v in extras.items() if v not in (None, "")
    ]
    return Component(**component_kwargs)


def validate(text):
    """Valida o JSON contra o schema oficial 1.6. Devolve True se valido."""
    try:
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        print("Aviso: validacao ignorada (instala 'cyclonedx-python-lib[json-validation]').", file=sys.stderr)
        return True
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    if error:
        print(f"CBOM INVALIDO segundo o schema CycloneDX 1.6:\n{error}", file=sys.stderr)
        return False
    print("CBOM valido segundo o schema CycloneDX 1.6.", file=sys.stderr)
    return True


def findings_from_file(path):
    """Le um ficheiro JSON e devolve a lista de findings (ou [] se nao for um results)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Aviso: {path} ignorado (JSON invalido: {e}).", file=sys.stderr)
        return []

    # Ignora CBOMs ja gerados
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        return []
    # Aceita tanto uma lista como {"findings": [...]}
    findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        return []
    return [f for f in findings if isinstance(f, dict)]


def load_findings(input_path, output_file=None):
    """Se input_path for uma pasta, junta os findings de todos os .json lá dentro."""
    path = Path(input_path)
    if not path.exists():
        print(f"Erro: {input_path} nao encontrado.", file=sys.stderr)
        sys.exit(1)

    if path.is_file():
        return findings_from_file(path)

    out = Path(output_file).resolve() if output_file else None
    files = sorted(p for p in path.glob("*.json") if p.resolve() != out)
    if not files:
        print(f"Erro: nenhum ficheiro .json em {input_path}.", file=sys.stderr)
        sys.exit(1)

    findings = []
    for p in files:
        found = findings_from_file(p)
        print(f"  {p.name}: {len(found)} findings", file=sys.stderr)
        findings.extend(found)
    return findings


def generate_cbom(input_path, output_file=None):
    findings = load_findings(input_path, output_file)

    bom = Bom()
    for i, item in enumerate(findings, start=1):
        bom.components.add(build_component(item, i))

    text = JsonV1Dot6(bom).output_as_string(indent=2)
    ok = validate(text)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"CBOM exportado para {output_file}", file=sys.stderr)
    else:
        print(text)
    if not ok:
        sys.exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="?", default="output",
                        help="pasta com os .json (por omissao: output) ou um ficheiro")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    generate_cbom(args.results, args.output)