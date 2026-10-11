"""
QuantumTrace CBOM Exporter (CycloneDX 1.6)

Exports cryptographic findings into CycloneDX 1.6 Cryptography Bill of Materials (CBOM)
with strict schema validation, rich metadata inference (code, network, and cloud), and Streamlit support.
Supports automatic aggregation of all .json findings files from the 'output' directory.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    CryptoAssetType,
    CryptoProperties,
    RelatedCryptoMaterialType,
)
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

try:
    import streamlit as st
except ImportError:
    st = None


# Algoritmos assimétricos e curvas quebrados pelo Algoritmo de Shor num computador quântico
SHOR_VULNERABLE = {
    "RSA", "DSA", "ECDSA", "ECDH", "DH", "DIFFIE-HELLMAN",
    "ED25519", "EDDSA", "CURVE25519", "X25519", "ECC"
}

# Algoritmos clássicos (assimétricos vulneráveis a Shor + simétricos/hashes fracos ou afetados por Grover)
CLASSIC_ALGORITHMS = SHOR_VULNERABLE | {
    "AES", "DES", "3DES", "TRIPLEDES", "RC4", "BLOWFISH",
    "MD5", "SHA1", "SHA-1"
}

# Algoritmos Post-Quantum Padronizados pelo NIST / Candidatos PQC
PQC_ALGORITHMS = {
    "KYBER", "CRYSTALS-KYBER", "ML-KEM",
    "DILITHIUM", "CRYSTALS-DILITHIUM", "ML-DSA",
    "SPHINCS+", "SLH-DSA", "FALCON"
}


def _clean_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _clean_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        if isinstance(val, str):
            val = val.strip()
            if not val or val.lower() == "none":
                return None
        return int(val)
    except (ValueError, TypeError):
        return None


def _is_pqc(algo: Optional[str]) -> bool:
    if not algo:
        return False
    algo_upper = algo.upper()
    return any(p in algo_upper for p in PQC_ALGORITHMS)


def _is_quantum_vulnerable(algo: Optional[str]) -> bool:
    if not algo:
        return False
    algo_upper = algo.upper()
    if _is_pqc(algo_upper):
        return False
    return any(c in algo_upper for c in CLASSIC_ALGORITHMS)


def _infer_asset_type(finding: Dict[str, Any]) -> CryptoAssetType:
    raw_type = _clean_str(finding.get("asset_type"))
    if raw_type:
        normalized = raw_type.lower().replace("-", "_").replace(" ", "_")
        for member in CryptoAssetType:
            if member.value.lower() == normalized or member.name.lower() == normalized:
                return member

    source = _clean_str(finding.get("source")) or ""
    algo = (_clean_str(finding.get("algorithm")) or "").upper()
    target = (_clean_str(finding.get("asset")) or _clean_str(finding.get("target")) or "").lower()

    if "acm" in target or "cert" in target or "certificate" in target:
        return CryptoAssetType.CERTIFICATE
    if "kms" in target or "key" in target:
        return CryptoAssetType.RELATED_CRYPTO_MATERIAL
    if "protocol" in target or "tls" in target or "ssl" in target or "ssh" in target:
        return CryptoAssetType.PROTOCOL

    if source == "network":
        return CryptoAssetType.PROTOCOL
    if source == "cloud":
        if "cert" in target or "acm" in target:
            return CryptoAssetType.CERTIFICATE
        return CryptoAssetType.RELATED_CRYPTO_MATERIAL

    if any(h in algo for h in ["SHA", "MD5"]):
        return CryptoAssetType.ALGORITHM

    return CryptoAssetType.ALGORITHM


def _normalize_algorithm_name(raw: Optional[str]) -> str:
    if not raw:
        return "UNKNOWN"
    norm = raw.strip().upper()
    aliases = {
        "KYBER": "ML-KEM (Kyber)",
        "CRYSTALS-KYBER": "ML-KEM (Kyber)",
        "DILITHIUM": "ML-DSA (Dilithium)",
        "CRYSTALS-DILITHIUM": "ML-DSA (Dilithium)",
        "SPHINCS+": "SLH-DSA (SPHINCS+)",
    }
    return aliases.get(norm, norm)


def _safe_bom_ref(finding: Dict[str, Any], index: int) -> str:
    target = _clean_str(finding.get("asset")) or _clean_str(finding.get("target")) or "crypto"
    source = _clean_str(finding.get("source")) or "asset"
    safe_slug = re.sub(r"[^a-zA-Z0-9_\-\.]", "-", f"{source}-{target}")[:60].strip("-")
    uid = uuid.uuid4().hex[:8]
    return f"qt-{safe_slug}-{index}-{uid}"


def create_crypto_component(finding: Dict[str, Any], index: int) -> Component:
    algo_raw = _clean_str(finding.get("algorithm"))
    algo_norm = _normalize_algorithm_name(algo_raw)
    asset_type = _infer_asset_type(finding)
    
    # Obtém o nome do ficheiro ou alvo (suporta 'asset' do findings.py ou 'target')
    target = _clean_str(finding.get("asset")) or _clean_str(finding.get("target")) or "unspecified-target"
    key_length = _clean_int(finding.get("key_length")) or _clean_int(finding.get("key_size"))

    name = f"{algo_norm} @ {target}" if target else algo_norm
    version = str(key_length) if key_length else _clean_str(finding.get("version"))

    crypto_props = CryptoProperties(asset_type=asset_type)

    if asset_type == CryptoAssetType.CERTIFICATE and hasattr(crypto_props, "certificate_properties"):
        cert_props = getattr(crypto_props, "certificate_properties", None)
        if cert_props and hasattr(cert_props, "subject_name"):
            setattr(cert_props, "subject_name", target)

    elif asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL and hasattr(crypto_props, "related_crypto_material_properties"):
        mat_props = getattr(crypto_props, "related_crypto_material_properties", None)
        if mat_props:
            if hasattr(mat_props, "material_type"):
                setattr(mat_props, "material_type", RelatedCryptoMaterialType.KEY)
            if key_length and hasattr(mat_props, "size"):
                setattr(mat_props, "size", key_length)

    bom_ref = _safe_bom_ref(finding, index)
    component = Component(
        name=name,
        version=version,
        type=ComponentType.APPLICATION,
        bom_ref=bom_ref,
        crypto_properties=crypto_props,
    )

    # Propriedades enriquecidas com base no modelo Finding do QuantumTrace
    metadata_map = [
        ("quantumtrace:source", _clean_str(finding.get("source"))),
        ("quantumtrace:asset", target),
        ("quantumtrace:location", _clean_str(finding.get("location"))),
        ("quantumtrace:key_length", str(key_length) if key_length else None),
        ("quantumtrace:library", _clean_str(finding.get("library"))),
        ("quantumtrace:risk_tier", _clean_str(finding.get("risk_tier")) or _clean_str(finding.get("severity"))),
        ("quantumtrace:replacement", _clean_str(finding.get("replacement"))),
        ("quantumtrace:quantum_vulnerable", str(_is_quantum_vulnerable(algo_raw)).lower()),
        ("quantumtrace:pqc", str(_is_pqc(algo_raw)).lower()),
        ("quantumtrace:notes", _clean_str(finding.get("notes") or finding.get("note") or finding.get("details"))),
        ("quantumtrace:cve", _clean_str(finding.get("cve"))),
    ]

    for prop_name, prop_val in metadata_map:
        if prop_val is not None:
            component.properties.add(Property(name=prop_name, value=prop_val))

    return component


def build_cbom(findings: List[Dict[str, Any]], serial_number: Optional[Any] = None) -> Bom:
    bom = Bom()
    bom.spec_version = SchemaVersion.V1_6

    if serial_number:
        if isinstance(serial_number, str):
            clean_str = serial_number.replace("urn:uuid:", "")
            bom.serial_number = uuid.UUID(clean_str)
        elif isinstance(serial_number, uuid.UUID):
            bom.serial_number = serial_number

    bom.metadata.timestamp = datetime.now(timezone.utc)
    bom.metadata.tools.components.add(
        Component(
            name="QuantumTrace",
            version="1.0.0",
            type=ComponentType.APPLICATION,
            description="Quantum Security Posture Management & CBOM Generator",
        )
    )

    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        comp = create_crypto_component(finding, idx)
        bom.components.add(comp)

    return bom


def export_cbom_json(findings: List[Dict[str, Any]], indent: int = 2) -> str:
    bom = build_cbom(findings)
    serializer = JsonV1Dot6(bom)
    output: str = serializer.output_as_string(indent=indent)
    return output


def validate_cbom_json(json_str: str) -> Tuple[bool, Optional[str]]:
    validator = JsonStrictValidator(SchemaVersion.V1_6)
    try:
        validation_error = validator.validate(json_str)
        if validation_error:
            return False, str(validation_error)
        return True, None
    except Exception as exc:
        return False, str(exc)


def render_cbom_export(findings: List[Dict[str, Any]]) -> None:
    if st is None:
        raise RuntimeError("Streamlit is not installed in the environment.")

    st.subheader("CycloneDX 1.6 CBOM Export")

    if not findings:
        st.info("No findings available to generate CBOM.")
        return

    try:
        cbom_json = export_cbom_json(findings)
        is_valid, validation_msg = validate_cbom_json(cbom_json)

        if is_valid:
            st.success("CBOM successfully validated against CycloneDX 1.6 Schema!")
        else:
            st.warning(f"CycloneDX Schema Validation Warning: {validation_msg}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"quantumtrace_cbom_{timestamp}.cdx.json"

        st.download_button(
            label="Download CBOM (JSON)",
            data=cbom_json,
            file_name=filename,
            mime="application/vnd.cyclonedx+json",
        )

        with st.expander("Preview CBOM JSON", expanded=False):
            st.code(cbom_json, language="json")

    except Exception as e:
        st.error(f"Failed to generate CBOM: {e}")


def load_findings_from_path(target_path: Path) -> List[Dict[str, Any]]:
    """Carrega findings de um ficheiro JSON ou agrega todos os .json dentro de uma pasta."""
    all_findings: List[Dict[str, Any]] = []

    if target_path.is_file():
        files = [target_path]
    elif target_path.is_dir():
        files = sorted(list(target_path.glob("*.json")))
        if not files:
            sys.stderr.write(f"Aviso: Nenhum ficheiro .json encontrado na pasta '{target_path}'.\n")
            return []
    else:
        sys.stderr.write(f"Erro: O caminho '{target_path}' não existe.\n")
        sys.exit(1)

    for file_path in files:
        # Ignora eventuais ficheiros CBOM anteriores para evitar duplicações em loops
        if "cbom" in file_path.name.lower():
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "findings" in data:
                items = data["findings"]
            elif isinstance(data, list):
                items = data
            else:
                items = []

            all_findings.extend(items)
            sys.stderr.write(f"Carregados {len(items)} findings de: {file_path.name}\n")
        except Exception as e:
            sys.stderr.write(f"Erro ao ler '{file_path}': {e}\n")

    return all_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gera CBOM CycloneDX 1.6 agregando ficheiros JSON de findings."
    )
    parser.add_argument(
        "input",
        type=Path,
        nargs="?",
        default=Path("output"),
        help="Ficheiro JSON ou pasta com ficheiros JSON (padrão: pasta 'output')",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Caminho do ficheiro de saída (padrão: stdout)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Valida o CBOM contra o esquema estrito CycloneDX 1.6",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="Indentação JSON (padrão: 2)",
    )

    args = parser.parse_args()

    input_path = args.input
    if not input_path.exists():
        sys.stderr.write(f"Erro: O diretório ou ficheiro '{input_path}' não foi encontrado.\n")
        sys.stderr.write("Certifica-te de que a pasta 'output' existe na raiz do projeto.\n")
        sys.exit(1)

    findings = load_findings_from_path(input_path)
    if not findings:
        sys.stderr.write("Nenhum finding válido encontrado para exportar.\n")
        sys.exit(1)

    sys.stderr.write(f"Total de findings agregados: {len(findings)}\n")

    try:
        cbom_output = export_cbom_json(findings, indent=args.indent)
    except Exception as e:
        sys.stderr.write(f"Erro ao gerar CBOM: {e}\n")
        sys.exit(1)

    if args.validate:
        is_valid, error = validate_cbom_json(cbom_output)
        if not is_valid:
            sys.stderr.write(f"Falha na validação do schema CycloneDX 1.6:\n{error}\n")
            sys.exit(2)
        sys.stderr.write("Validação CycloneDX 1.6: OK (Válido)\n")

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(cbom_output)
            sys.stderr.write(f"CBOM guardado com sucesso em: {args.output}\n")
        except Exception as e:
            sys.stderr.write(f"Erro ao gravar ficheiro de saída: {e}\n")
            sys.exit(1)
    else:
        print(cbom_output)


if __name__ == "__main__":
    main()
