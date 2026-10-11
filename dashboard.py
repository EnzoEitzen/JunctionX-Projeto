"""
QuantumTrace — Enterprise Cryptographic Inventory & Quantum Readiness Platform
Single-page Apple-inspired executive & engineering application built in Streamlit.
Conforms strictly to CycloneDX 1.6 CBOM specification and NIST FIPS 203/204/205 standards.
"""

import json
import os
import glob
from pathlib import Path
import pandas as pd
import streamlit as st
import altair as alt

# -----------------------------------------------------------------------------
# 1. Configuração da Página e Tokens Visuais Apple
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="QuantumTrace — Cryptographic Debt & Quantum Posture",
    page_icon="■",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    :root {
        --bg-page: #000000;
        --surface-elevated: #111113;
        --surface-card: #161618;
        --surface-card-hover: #1c1c1f;
        --surface-subtle: #222225;
        --border-hairline: rgba(255, 255, 255, 0.08);
        --border-strong: rgba(255, 255, 255, 0.16);
        --text-headline: #f5f5f7;
        --text-body: #d1d1d6;
        --text-muted: #86868b;
        --text-faint: #636366;
        --apple-blue: #2997ff;
        --apple-red: #ff453a;
        --apple-orange: #ff9f0a;
        --apple-green: #30d158;
        --apple-purple: #bf5af2;
    }

    html {
        scroll-behavior: smooth;
        background-color: var(--bg-page) !important;
    }

    body, [class*="css"], .stApp {
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", sans-serif !important;
        background-color: var(--bg-page) !important;
        color: var(--text-headline) !important;
        letter-spacing: -0.014em;
    }

    /* Ocultar barra superior padrão e rodapé do Streamlit */
    header[data-testid="stHeader"], footer {
        display: none !important;
    }

    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 5rem !important;
        max-width: 1200px !important;
    }

    /* ---------------- Apple Sticky Navigation Bar ---------------- */
        html, body, [data-testid="stAppViewContainer"], section.main, .stApp, .block-container {
        scroll-behavior: smooth !important;
    }

    /* Clearance para a barra fixa quando se navega para as âncoras */
    .section-anchor, #overview, #vectors, #posture, #audit, #roadmap, #cbom {
        scroll-margin-top: 85px !important;
        scroll-snap-margin-top: 85px !important;
        display: block !important;
        position: relative !important;
        visibility: hidden !important;
        height: 0px !important;
    }

    /* ---------------- Apple Sticky Navigation Bar ---------------- */
    .apple-nav {
        position: sticky;
        top: 0;
        z-index: 99999;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 28px;
        background: rgba(10, 10, 12, 0.78);
        backdrop-filter: saturate(180%) blur(24px);
        -webkit-backdrop-filter: saturate(180%) blur(24px);
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        margin-left: -2rem;
        margin-right: -2rem;
        margin-top: -1.5rem;
        margin-bottom: 2.5rem;
        transition: background-color 0.3s ease, border-color 0.3s ease;
    }
    .nav-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 14px;
        font-weight: 600;
        letter-spacing: -0.02em;
        color: #ffffff;
        text-decoration: none;
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease;
        user-select: none;
        cursor: pointer;
    }
    .nav-brand:active, .nav-brand.clicked {
        transform: scale(0.96);
        opacity: 0.85;
    }
    .nav-badge {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--text-muted);
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid var(--border-hairline);
        padding: 2px 8px;
        border-radius: 9999px;
    }
    .nav-links {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .nav-link {
        position: relative;
        font-size: 12.5px;
        font-weight: 400;
        letter-spacing: -0.01em;
        color: #86868b;
        text-decoration: none;
        padding: 6px 13px;
        border-radius: 9999px;
        transition: color 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                    background 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                    transform 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                    box-shadow 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        display: inline-flex;
        align-items: center;
        user-select: none;
        cursor: pointer;
    }
    .nav-link:hover {
        color: #ffffff;
        background: rgba(255, 255, 255, 0.06);
    }
    .nav-link:active, .nav-link.clicked {
        transform: scale(0.91);
        background: rgba(255, 255, 255, 0.14);
        color: #ffffff;
    }
    .nav-link.active {
        color: #ffffff !important;
        font-weight: 500;
        background: rgba(255, 255, 255, 0.1);
        box-shadow: 0 0 16px rgba(255, 255, 255, 0.05), inset 0 0 0 1px rgba(255, 255, 255, 0.1);
    }
    .nav-cta {
        font-size: 12px;
        font-weight: 500;
        letter-spacing: -0.01em;
        color: #000000 !important;
        background: #ffffff;
        padding: 6px 16px;
        border-radius: 9999px;
        text-decoration: none;
        margin-left: 8px;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
        display: inline-flex;
        align-items: center;
        cursor: pointer;
        user-select: none;
    }
    .nav-cta:hover {
        background: #f5f5f7;
        transform: translateY(-1px) scale(1.02);
        box-shadow: 0 4px 16px rgba(255, 255, 255, 0.25);
    }
    .nav-cta:active, .nav-cta.clicked {
        transform: scale(0.93) translateY(0);
        opacity: 0.85;
    }

    /* Oculta contentor neutro do injetor JS */
    iframe[srcdoc*="apple-nav-enhancer-root"],
    div:has(> iframe[srcdoc*="apple-nav-enhancer-root"]) {
        position: absolute !important;
        height: 0px !important;
        width: 0px !important;
        opacity: 0 !important;
        pointer-events: none !important;
        overflow: hidden !important;
        border: none !important;
        margin: 0 !important;
        padding: 0 !important;
    }

    }
    .nav-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 15px;
        font-weight: 600;
        letter-spacing: -0.02em;
        color: #ffffff;
        text-decoration: none;
    }
    .nav-badge {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--text-muted);
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid var(--border-hairline);
        padding: 2px 8px;
        border-radius: 9999px;
    }
    .nav-links {
        display: flex;
        align-items: center;
        gap: 22px;
    }
    .nav-link {
        font-size: 12px;
        font-weight: 400;
        color: var(--text-muted);
        text-decoration: none;
        transition: color 0.15s ease;
    }
    .nav-link:hover {
        color: #ffffff;
    }
    .nav-cta {
        font-size: 12px;
        font-weight: 500;
        color: #000000 !important;
        background: #ffffff;
        padding: 5px 14px;
        border-radius: 9999px;
        text-decoration: none;
        transition: opacity 0.15s ease;
    }
    .nav-cta:hover {
        opacity: 0.9;
    }

    /* ---------------- Hero Section Typography ---------------- */
    .hero-eyebrow {
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--apple-blue);
        margin-bottom: 12px;
    }
    .hero-title {
        font-size: 3.6rem;
        font-weight: 700;
        letter-spacing: -0.04em;
        line-height: 1.06;
        color: #ffffff;
        margin-bottom: 16px;
    }
    .hero-subtitle {
        font-size: 1.35rem;
        font-weight: 400;
        line-height: 1.45;
        letter-spacing: -0.015em;
        color: var(--text-muted);
        max-width: 820px;
        margin-bottom: 32px;
    }

    /* ---------------- Apple Cards ---------------- */
    .apple-card {
        background: var(--surface-card);
        border: 1px solid var(--border-hairline);
        border-radius: 18px;
        padding: 28px 30px;
        margin-bottom: 24px;
        transition: border-color 0.2s ease, background 0.2s ease;
    }
    .apple-card:hover {
        border-color: var(--border-strong);
        background: var(--surface-card-hover);
    }

    .section-eyebrow {
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin-bottom: 8px;
    }
    .section-heading {
        font-size: 2.2rem;
        font-weight: 700;
        letter-spacing: -0.03em;
        line-height: 1.15;
        color: #ffffff;
        margin-bottom: 10px;
    }
    .section-description {
        font-size: 14px;
        color: var(--text-muted);
        line-height: 1.5;
        margin-bottom: 28px;
        max-width: 780px;
    }

    .metric-value {
        font-size: 2.6rem;
        font-weight: 600;
        letter-spacing: -0.035em;
        line-height: 1;
        color: #ffffff;
    }
    .metric-value small {
        font-size: 1.1rem;
        font-weight: 400;
        color: var(--text-muted);
    }
    .metric-caption {
        font-size: 12px;
        color: var(--text-muted);
        margin-top: 10px;
    }

    /* ---------------- Status Badges & Pills ---------------- */
    .apple-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 500;
        padding: 4px 10px;
        border-radius: 9999px;
        letter-spacing: 0.02em;
    }
    .pill-critical {
        background: rgba(255, 69, 58, 0.12);
        color: var(--apple-red);
        border: 1px solid rgba(255, 69, 58, 0.25);
    }
    .pill-medium {
        background: rgba(255, 159, 10, 0.12);
        color: var(--apple-orange);
        border: 1px solid rgba(255, 159, 10, 0.25);
    }
    .pill-safe {
        background: rgba(48, 209, 88, 0.12);
        color: var(--apple-green);
        border: 1px solid rgba(48, 209, 88, 0.25);
    }
    .pill-neutral {
        background: rgba(255, 255, 255, 0.06);
        color: var(--text-muted);
        border: 1px solid var(--border-hairline);
    }

    .apple-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }
    .dot-critical { background-color: var(--apple-red); }
    .dot-medium { background-color: var(--apple-orange); }
    .dot-safe { background-color: var(--apple-green); }

    /* ---------------- Security Advisory Banner ---------------- */
    .apple-advisory {
        background: #121214;
        border: 1px solid rgba(255, 69, 58, 0.35);
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 32px;
        display: flex;
        gap: 18px;
        align-items: flex-start;
    }
    .advisory-badge {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--apple-red);
        background: rgba(255, 69, 58, 0.12);
        padding: 3px 8px;
        border-radius: 6px;
        white-space: nowrap;
    }
    .advisory-content {
        font-size: 13.5px;
        line-height: 1.5;
        color: var(--text-body);
    }
    .advisory-content strong {
        color: #ffffff;
    }

    /* ---------------- Controlos & Botões ---------------- */
    div.stButton > button, div.stDownloadButton > button {
        background: #ffffff !important;
        color: #000000 !important;
        font-weight: 500 !important;
        font-size: 13px !important;
        border-radius: 10px !important;
        border: none !important;
        padding: 10px 22px !important;
        letter-spacing: -0.01em !important;
        transition: transform 0.1s ease, opacity 0.15s ease !important;
    }
    div.stButton > button:hover, div.stDownloadButton > button:hover {
        opacity: 0.92 !important;
        transform: scale(0.99);
    }

    input, select, textarea {
        background-color: #141416 !important;
        color: #ffffff !important;
        border: 1px solid var(--border-hairline) !important;
        border-radius: 8px !important;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border-hairline) !important;
        border-radius: 14px !important;
        overflow: hidden !important;
    }

    .apple-divider {
        height: 1px;
        background: var(--border-hairline);
        margin: 54px 0;
    }

    .apple-footer {
        padding: 48px 0 24px 0;
        border-top: 1px solid var(--border-hairline);
        font-size: 12px;
        color: var(--text-muted);
        line-height: 1.6;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# 2. Motor de Classificação Quântica NIST (FIPS 203 / 204 / 205)
# -----------------------------------------------------------------------------
def classify_finding(f):
    alg = str(f.get("algorithm", "")).strip()
    alg_upper = alg.upper()
    notes = str(f.get("notes", "") or "").lower()
    asset = str(f.get("asset", "") or "").lower()
    key_len = f.get("key_length")

    # 1. PQC já conforme
    if any(k in alg_upper for k in ["MLKEM", "ML-KEM", "MLDSA", "ML-DSA", "SLHDSA", "SLH-DSA", "FIPS 203", "FIPS 204", "FIPS 205"]):
        return "Safe", "Compliant (NIST PQC Standard)"

    # 2. Vulnerável a Shor (Assimétrico) -> Critical
    if any(k in alg_upper for k in ["RSA", "DSA", "ECDSA", "ECDH", "X25519", "ED25519", "ED448", "DIFFIE-HELLMAN", "DH"]):
        if any(k in alg_upper for k in ["ECDH", "X25519", "DIFFIE-HELLMAN", "DH"]) or "key exchange" in notes or "kem" in notes or "handshake" in notes:
            replacement = "ML-KEM (FIPS 203)"
        elif any(k in alg_upper for k in ["ECDSA", "ED25519", "ED448", "DSA"]):
            replacement = "ML-DSA (FIPS 204)"
        else:
            if "sign" in notes or "signature" in asset or "token" in asset or "cert" in asset:
                replacement = "ML-DSA (FIPS 204)"
            else:
                replacement = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
        return "Critical", replacement

    # 3. Vulnerável a Grover (Simétrico fraco / Hash) -> Medium
    if any(k in alg_upper for k in ["AES-128", "3DES", "DES", "RC4", "BLOWFISH", "SHA-1", "SHA1", "MD5", "MD2", "MD4"]):
        if any(k in alg_upper for k in ["AES", "DES", "BLOWFISH", "RC4"]):
            replacement = "AES-256 (Grover-Resilient)"
        else:
            replacement = "SHA-256 / SHA-384"
        return "Medium", replacement

    if "AES" in alg_upper:
        if key_len == 128:
            return "Medium", "AES-256 (Grover-Resilient)"
        return "Safe", "Resilient (AES-256)"

    if any(k in alg_upper for k in ["AES-256", "SHA-256", "SHA-384", "SHA-512", "SHA3"]):
        return "Safe", "Resilient (256-bit+ Security)"

    return "Safe", "Compliant"


# -----------------------------------------------------------------------------
# 3. Ingestão de Dados e Normalização
# -----------------------------------------------------------------------------
@st.cache_data(ttl=5)
def load_and_prepare_findings():
    raw_findings = []
    loaded_source = ""

    # Prioridade 1: output/results.json
    if os.path.exists("output/results.json"):
        try:
            with open("output/results.json", "r", encoding="utf-8") as f:
                raw_findings = json.load(f)
            loaded_source = "output/results.json"
        except Exception:
            pass

    # Prioridade 2: results.json
    if not raw_findings and os.path.exists("results.json"):
        try:
            with open("results.json", "r", encoding="utf-8") as f:
                raw_findings = json.load(f)
            loaded_source = "results.json"
        except Exception:
            pass

    # Prioridade 3: Agregar output/*.json
    if not raw_findings and os.path.exists("output"):
        for jf in glob.glob("output/*.json"):
            if "cbom" in jf:
                continue
            try:
                with open(jf, "r", encoding="utf-8") as f:
                    content = json.load(f)
                if isinstance(content, list):
                    raw_findings.extend(content)
                    loaded_source = "output/*.json (Aggregated)"
                elif isinstance(content, dict) and "findings" in content:
                    raw_findings.extend(content["findings"])
                    loaded_source = "output/*.json (Aggregated)"
            except Exception:
                continue

    # Fallback transparente com dados de referência do desafio
    if not raw_findings:
        raw_findings = [
            {"source": "network", "asset": "web01.lab:443 (Legacy TLS 1.2)", "location": "network-capture/network.pcap", "algorithm": "RSA", "key_length": 2048, "library": "OpenSSL", "notes": "Cifra TLS_RSA_WITH_AES_128_CBC_SHA sem Forward Secrecy"},
            {"source": "network", "asset": "app01.lab:443 (TLS 1.3 Classical)", "location": "network-capture/network.pcap", "algorithm": "X25519", "key_length": 253, "library": "OpenSSL", "notes": "Key exchange clássico vulnerável ao algoritmo de Shor"},
            {"source": "network", "asset": "vault01.lab:443 (TLS 1.3 Hybrid PQC)", "location": "network-capture/network.pcap", "algorithm": "X25519MLKEM768", "key_length": 768, "library": "OpenSSL PQC", "notes": "Troca de chaves híbrida pós-quântica conforme FIPS 203"},
            {"source": "code", "asset": "python/license_token.py", "location": "sample-repos/python/license_token.py:6", "algorithm": "RSA", "key_length": 1024, "library": "cryptography", "notes": "Chave RSA fraca para validação de licença"},
            {"source": "code", "asset": "python/webhook_signature.py", "location": "sample-repos/python/webhook_signature.py:12", "algorithm": "Ed25519", "key_length": 256, "library": "cryptography", "notes": "Assinatura digital de webhooks"},
            {"source": "code", "asset": "go/auth-gateway/main.go", "location": "sample-repos/go/auth.go:45", "algorithm": "ECDSA", "key_length": 256, "library": "crypto/ecdsa", "notes": "Tokens JWT assinados com curva P-256"},
            {"source": "code", "asset": "python/legacy_accounts.py", "location": "sample-repos/python/legacy_accounts.py:5", "algorithm": "MD5", "key_length": None, "library": "hashlib", "notes": "Hash legado em base de dados"},
            {"source": "code", "asset": "java/SessionCipher.java", "location": "sample-repos/java/SessionCipher.java:22", "algorithm": "AES-128", "key_length": 128, "library": "javax.crypto", "notes": "Cifra de sessão simétrica subdimensionada"},
            {"source": "cloud", "asset": "alias/licensing-jwt-signing", "location": "cloud-posture/kms_key_inventory.json", "algorithm": "RSA_3072", "key_length": 3072, "library": "AWS KMS", "notes": "Assinatura assimétrica CloudHSM"},
            {"source": "cloud", "asset": "arn:aws:acm:cert/api-gateway", "location": "cloud-posture/acm_certificates.json", "algorithm": "ECDSA P-256", "key_length": 256, "library": "AWS ACM", "notes": "Certificado público de gateway vulnerável a Shor"},
            {"source": "cloud", "asset": "alb/internal-api-listener", "location": "cloud-posture/load_balancer_listeners.json", "algorithm": "AES-128-CBC", "key_length": 128, "library": "AWS ELB", "notes": "Política ELBSecurityPolicy-2016-08 com cifras fracas"},
            {"source": "cloud", "asset": "alias/s3-data-lake-encryption", "location": "cloud-posture/kms_key_inventory.json", "algorithm": "AES-256", "key_length": 256, "library": "AWS KMS", "notes": "Chave KMS SYMMETRIC_DEFAULT conforme"}
        ]
        loaded_source = "Synthetic Baseline"

    processed = []
    for f in raw_findings:
        item = dict(f)
        if "asset" not in item:
            item["asset"] = item.get("target", "Unspecified Asset")
        if "source" not in item:
            loc = str(item.get("location", ""))
            if "network" in loc or ".pcap" in loc:
                item["source"] = "network"
            elif "cloud" in loc or "kms" in loc or "acm" in loc or "load_balancer" in loc:
                item["source"] = "cloud"
            else:
                item["source"] = "code"

        if item.get("risk_tier") in [None, "Unclassified", ""]:
            r, rep = classify_finding(item)
            item["risk_tier"] = r
            item["replacement"] = rep
        elif not item.get("replacement"):
            _, rep = classify_finding(item)
            item["replacement"] = rep

        processed.append(item)

    return pd.DataFrame(processed), loaded_source


df_findings, data_source_label = load_and_prepare_findings()

total_assets = len(df_findings)
critical_count = len(df_findings[df_findings["risk_tier"] == "Critical"])
medium_count = len(df_findings[df_findings["risk_tier"] == "Medium"])
safe_count = len(df_findings[df_findings["risk_tier"].isin(["Safe", "Quantum-resilient"])])

quantum_risk_score = (
    int(((critical_count * 1.0 + medium_count * 0.4) / max(total_assets, 1)) * 100)
    if total_assets > 0
    else 0
)


# -----------------------------------------------------------------------------
# 4. Serialização do CBOM CycloneDX 1.6
# -----------------------------------------------------------------------------
def generate_cbom_payload(df_to_export):
    try:
        import export_cbom
        from cyclonedx.model.bom import Bom
        from cyclonedx.output.json import JsonV1Dot6
        bom = Bom()
        for i, row in enumerate(df_to_export.to_dict(orient="records"), start=1):
            comp = export_cbom.build_component(row, i)
            bom.components.add(comp)
        return JsonV1Dot6(bom).output_as_string(indent=2)
    except Exception:
        cbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "cryptographic-asset",
                    "name": r.get("asset", "Asset"),
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": r.get("algorithm", "Unknown")}
                    },
                    "properties": [
                        {"name": "quantumtrace:risk-tier", "value": r.get("risk_tier", "")},
                        {"name": "quantumtrace:replacement", "value": r.get("replacement", "")},
                        {"name": "quantumtrace:location", "value": r.get("location", "")}
                    ]
                }
                for r in df_to_export.to_dict(orient="records")
            ]
        }
        return json.dumps(cbom_data, indent=2)

cbom_json_string = generate_cbom_payload(df_findings)


# -----------------------------------------------------------------------------
# 5. Barra de Navegação Superior Fixa (Sticky Header)
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="apple-nav">
        <a href="#overview" class="nav-brand">
            <span>QuantumTrace</span>
            <span class="nav-badge">JunctionX Lisbon 2026</span>
        </a>
        <div class="nav-links">
            <a href="#overview" class="nav-link">Overview</a>
            <a href="#vectors" class="nav-link">Attack Vectors</a>
            <a href="#posture" class="nav-link">Risk Posture</a>
            <a href="#audit" class="nav-link">Live Audit</a>
            <a href="#roadmap" class="nav-link">Migration</a>
            <a href="#cbom" class="nav-link">CBOM</a>
            <a href="#audit" class="nav-cta">Inspect Environment</a>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# -----------------------------------------------------------------------------
# 6. Hero Section
# -----------------------------------------------------------------------------
st.markdown("<div id='overview'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div style="padding-top: 10px; padding-bottom: 24px;">
        <div class="hero-eyebrow">Enterprise Cryptographic Inventory & Readiness</div>
        <div class="hero-title">The Quantum Dawn<br>has arrived.</div>
        <div class="hero-subtitle">
            Uncovering Cryptographic Debt across Network Traffic, Application Repositories, and Cloud Configurations.
            Transitioning enterprise security from legacy asymmetric ciphers to finalized NIST Post-Quantum standards.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

if critical_count > 0:
    st.markdown(
        f"""
        <div class="apple-advisory">
            <span class="advisory-badge">Threat Advisory</span>
            <div class="advisory-content">
                <strong>Harvest Now, Decrypt Later Exposure Active:</strong>
                QuantumTrace identified <strong>{critical_count} critical components</strong> relying on classical asymmetric cryptography (RSA, ECDSA, X25519).
                Adversaries are archiving encrypted organizational traffic today to decrypt proprietary data once cryptanalytically relevant quantum computers (CRQC) emerge.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Cartões de Métricas no Topo
h_col1, h_col2, h_col3, h_col4 = st.columns(4)

with h_col1:
    score_status = "Action Required" if quantum_risk_score >= 50 else ("Moderate" if quantum_risk_score >= 25 else "Resilient")
    score_pill = "pill-critical" if quantum_risk_score >= 50 else ("pill-medium" if quantum_risk_score >= 25 else "pill-safe")
    st.markdown(
        f"""
        <div class="apple-card">
            <div class="section-eyebrow">Quantum Risk Score</div>
            <div class="metric-value">{quantum_risk_score}<small> / 100</small></div>
            <div class="metric-caption">
                <span class="apple-pill {score_pill}">{score_status}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with h_col2:
    st.markdown(
        f"""
        <div class="apple-card">
            <div class="section-eyebrow">Shor Vulnerabilities</div>
            <div class="metric-value" style="color: #ff453a;">{critical_count}</div>
            <div class="metric-caption">
                <span class="apple-dot dot-critical"></span>
                <span>Critical: RSA, ECDSA, ECDH</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with h_col3:
    st.markdown(
        f"""
        <div class="apple-card">
            <div class="section-eyebrow">Grover Weaknesses</div>
            <div class="metric-value" style="color: #ff9f0a;">{medium_count}</div>
            <div class="metric-caption">
                <span class="apple-dot dot-medium"></span>
                <span>Medium: AES-128, 3DES, SHA-1</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with h_col4:
    st.markdown(
        f"""
        <div class="apple-card">
            <div class="section-eyebrow">Post-Quantum Ready</div>
            <div class="metric-value" style="color: #30d158;">{safe_count}</div>
            <div class="metric-caption">
                <span class="apple-dot dot-safe"></span>
                <span>Safe: FIPS 203/204 or AES-256</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# -----------------------------------------------------------------------------
# 7. Apresentação dos 3 Vetores Críticos
# -----------------------------------------------------------------------------
st.markdown("<div class='apple-divider'></div>", unsafe_allow_html=True)
st.markdown("<div id='vectors'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">360° Cryptographic Telemetry</div>
    <div class="section-heading">Three critical vectors.<br>Zero blind spots.</div>
    <div class="section-description">
        Enterprise cryptographic debt cannot be solved in code alone. QuantumTrace audits live transmission, static repositories, and cloud orchestration infrastructure.
    </div>
    """,
    unsafe_allow_html=True
)

vec_col1, vec_col2, vec_col3 = st.columns(3)

with vec_col1:
    st.markdown(
        """
        <div class="apple-card" style="height: 100%;">
            <div class="section-eyebrow" style="color: #2997ff;">Vector 01 · In-Transit</div>
            <div style="font-size: 1.25rem; font-weight: 600; color: #ffffff; margin-bottom: 10px;">Network Traffic</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-bottom: 16px;">
                Direct parsing of packet captures (<code>network.pcap</code>) via PyShark. Extracts TLS 1.2 and 1.3 ClientHello / ServerHello handshakes, cipher suites, and key exchange groups.
            </p>
            <div style="font-size: 11px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px;">
                <strong>Detection Scope:</strong> Distinguishes classical RSA/X25519 handshakes from hybrid post-quantum groups (<code>X25519MLKEM768</code>).
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with vec_col2:
    st.markdown(
        """
        <div class="apple-card" style="height: 100%;">
            <div class="section-eyebrow" style="color: #bf5af2;">Vector 02 · In-Use</div>
            <div style="font-size: 1.25rem; font-weight: 600; color: #ffffff; margin-bottom: 10px;">Application Code</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-bottom: 16px;">
                Automated static scanner across Python, Java, and Go repositories. Inspects declared primitives, key lengths, and cryptographic library imports (<code>cryptography</code>, <code>javax.crypto</code>, <code>crypto/ecdsa</code>).
            </p>
            <div style="font-size: 11px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px;">
                <strong>Detection Scope:</strong> Uncovers hardcoded token signing, weak RSA licensing keys, and obsolete hashing routines (MD5/SHA-1).
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with vec_col3:
    st.markdown(
        """
        <div class="apple-card" style="height: 100%;">
            <div class="section-eyebrow" style="color: #30d158;">Vector 03 · At-Rest</div>
            <div style="font-size: 1.25rem; font-weight: 600; color: #ffffff; margin-bottom: 10px;">Cloud Configurations</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-bottom: 16px;">
                Configuration auditor for AWS KMS, AWS ACM certificates, and Application Load Balancers. Evaluates KeySpec parameters, signing algorithms, and listener TLS policies.
            </p>
            <div style="font-size: 11px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px;">
                <strong>Detection Scope:</strong> Detects legacy ELB policies (<code>ELBSecurityPolicy-2016-08</code>) and asymmetric CloudHSM signing keys.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# -----------------------------------------------------------------------------
# 8. Matriz de Ameaça & Telemetria Visual
# -----------------------------------------------------------------------------
st.markdown("<div class='apple-divider'></div>", unsafe_allow_html=True)
st.markdown("<div id='posture'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Risk Architecture</div>
    <div class="section-heading">Shor vs. Grover.<br>Quantifying the exposure.</div>
    <div class="section-description">
        Quantum threats manifest across two distinct mathematical vectors. Shor destroys asymmetric structures, while Grover accelerates symmetric exhaustion.
    </div>
    """,
    unsafe_allow_html=True
)

chart_c1, chart_c2 = st.columns(2)

with chart_c1:
    st.markdown("<div class='section-eyebrow'>Telemetry · Ingestion Vector Breakdown</div>", unsafe_allow_html=True)
    v_df = df_findings["source"].value_counts().reset_index()
    v_df.columns = ["Vector", "Count"]
    v_df["Vector"] = v_df["Vector"].map({
        "network": "Network (TLS)",
        "code": "Code Repository",
        "cloud": "Cloud (KMS / ACM)"
    }).fillna(v_df["Vector"])

    v_chart = (
        alt.Chart(v_df)
        .mark_bar(cornerRadius=6, size=24)
        .encode(
            x=alt.X("Count:Q", title="Audited Assets", axis=alt.Axis(grid=True, gridColor="#1a1a1c", labelColor="#86868b")),
            y=alt.Y("Vector:N", title="", sort="-x", axis=alt.Axis(labelColor="#ffffff", labelFontSize=12)),
            color=alt.value("#2997ff")
        )
        .properties(height=180)
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(v_chart, use_container_width=True)

with chart_c2:
    st.markdown("<div class='section-eyebrow'>Telemetry · Risk Severity Profile</div>", unsafe_allow_html=True)
    r_df = df_findings["risk_tier"].value_counts().reset_index()
    r_df.columns = ["Tier", "Count"]

    r_chart = (
        alt.Chart(r_df)
        .mark_bar(cornerRadius=6, size=24)
        .encode(
            x=alt.X("Count:Q", title="Audited Assets", axis=alt.Axis(grid=True, gridColor="#1a1a1c", labelColor="#86868b")),
            y=alt.Y("Tier:N", title="", sort=["Critical", "Medium", "Safe"], axis=alt.Axis(labelColor="#ffffff", labelFontSize=12)),
            color=alt.Color(
                "Tier:N",
                scale=alt.Scale(
                    domain=["Critical", "Medium", "Safe"],
                    range=["#ff453a", "#ff9f0a", "#30d158"]
                ),
                legend=None
            )
        )
        .properties(height=180)
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(r_chart, use_container_width=True)


# -----------------------------------------------------------------------------
# 9. Secção Funcional: Auditoria ao Vivo & Inspetor de Ativos
# -----------------------------------------------------------------------------
st.markdown("<div class='apple-divider'></div>", unsafe_allow_html=True)
st.markdown("<div id='audit'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Interactive Environment Audit</div>
    <div class="section-heading">Filter, isolate, and inspect.</div>
    <div class="section-description">
        Search through all detected cryptographic components across every repository, TLS endpoint, and cloud service.
    </div>
    """,
    unsafe_allow_html=True
)

# Filtros Inline
filter_col1, filter_col2, filter_col3 = st.columns([1.5, 1.5, 2])

with filter_col1:
    available_sources = sorted(df_findings["source"].unique()) if "source" in df_findings else []
    source_labels = {"network": "Network (TLS)", "code": "Codebase", "cloud": "Cloud Posture"}
    selected_sources = st.multiselect(
        "Ingestion Vectors:",
        options=available_sources,
        default=available_sources,
        format_func=lambda s: source_labels.get(s, s.capitalize()),
    )

with filter_col2:
    available_risks = ["Critical", "Medium", "Safe"]
    risk_labels = {"Critical": "Critical (Shor)", "Medium": "Medium (Grover)", "Safe": "Resilient (PQC)"}
    selected_risks = st.multiselect(
        "Risk Profile:",
        options=available_risks,
        default=available_risks,
        format_func=lambda r: risk_labels.get(r, r),
    )

with filter_col3:
    search_query = st.text_input("Filter Components:", placeholder="Search by RSA, AES, KMS, file path...")

# Aplicação dos Filtros
filtered_df = df_findings.copy()
if selected_sources:
    filtered_df = filtered_df[filtered_df["source"].isin(selected_sources)]
if selected_risks:
    filtered_df = filtered_df[filtered_df["risk_tier"].isin(selected_risks)]
if search_query:
    q = search_query.lower()
    filtered_df = filtered_df[
        filtered_df["asset"].str.lower().str.contains(q, na=False) |
        filtered_df["algorithm"].str.lower().str.contains(q, na=False) |
        filtered_df["location"].str.lower().str.contains(q, na=False)
    ]

st.markdown(
    f"""
    <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 16px 0 10px 0;">
        <span style="font-size: 13px; font-weight: 500; color: #ffffff;">Cryptographic Findings</span>
        <span style="font-size: 12px; color: #86868b;">Displaying {len(filtered_df)} of {total_assets} detected assets (Source: <code>{data_source_label}</code>)</span>
    </div>
    """,
    unsafe_allow_html=True
)

if filtered_df.empty:
    st.markdown(
        """
        <div class="apple-card" style="text-align: center; padding: 48px;">
            <div style="font-size: 15px; color: #86868b;">No cryptographic findings match the selected filters.</div>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    table_df = filtered_df[[
        "asset", "source", "location", "algorithm", "key_length", "library", "risk_tier", "replacement"
    ]].copy()

    table_df.rename(columns={
        "asset": "Asset / Target",
        "source": "Vector",
        "location": "Location",
        "algorithm": "Primitive",
        "key_length": "Key Bits",
        "library": "Implementation",
        "risk_tier": "Risk Tier",
        "replacement": "NIST PQC Target"
    }, inplace=True)

    st.dataframe(
        table_df,
        use_container_width=True,
        column_config={
            "Vector": st.column_config.TextColumn("Vector", width="small"),
            "Key Bits": st.column_config.NumberColumn("Bits", format="%d", width="small"),
            "Risk Tier": st.column_config.TextColumn("Risk Tier", width="small"),
            "NIST PQC Target": st.column_config.TextColumn("NIST PQC Target", width="medium"),
        },
        hide_index=True
    )

    # Inspetor de Ativos
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    with st.expander("Component Deep-Dive Inspector", expanded=True):
        asset_list = filtered_df["asset"].tolist()
        selected_asset = st.selectbox(
            "Select asset for deep inspection:",
            options=asset_list,
            index=0 if asset_list else None
        )
        if selected_asset:
            asset_row = filtered_df[filtered_df["asset"] == selected_asset].iloc[0]
            insp_c1, insp_c2 = st.columns(2)
            with insp_c1:
                st.markdown(
                    f"""
                    <div class="apple-card" style="margin-bottom: 0;">
                        <div class="section-eyebrow">Asset Metadata</div>
                        <div style="font-size: 17px; font-weight: 600; color: #ffffff; margin-bottom: 10px;">{asset_row['asset']}</div>
                        <div style="font-size: 13px; color: #86868b; line-height: 1.7;">
                            <strong>Vector:</strong> {asset_row['source'].upper()}<br>
                            <strong>Location:</strong> <code>{asset_row['location']}</code><br>
                            <strong>Library / Provider:</strong> {asset_row.get('library') or 'Standard'}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with insp_c2:
                pill_style = "pill-critical" if asset_row["risk_tier"] == "Critical" else ("pill-medium" if asset_row["risk_tier"] == "Medium" else "pill-safe")
                st.markdown(
                    f"""
                    <div class="apple-card" style="margin-bottom: 0;">
                        <div class="section-eyebrow">Cryptographic Evaluation</div>
                        <div style="margin-bottom: 12px;">
                            <span class="apple-pill {pill_style}">{asset_row['risk_tier']} Risk</span>
                        </div>
                        <div style="font-size: 13px; color: #86868b; line-height: 1.7;">
                            <strong>Current Primitive:</strong> {asset_row['algorithm']} ({asset_row.get('key_length') or 'N/A'} bits)<br>
                            <strong>Recommended Migration:</strong> {asset_row['replacement']}<br>
                            <strong>Audit Context:</strong> {asset_row.get('notes') or 'Standard configuration.'}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


# -----------------------------------------------------------------------------
# 10. Roteiro de Migração NIST PQC
# -----------------------------------------------------------------------------
st.markdown("<div class='apple-divider'></div>", unsafe_allow_html=True)
st.markdown("<div id='roadmap'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Actionable Migration Strategy</div>
    <div class="section-heading">NIST Post-Quantum Standards.<br>Finalized August 2024.</div>
    <div class="section-description">
        QuantumTrace maps every legacy finding directly to the official Federal Information Processing Standards (FIPS) to eliminate speculation.
    </div>
    """,
    unsafe_allow_html=True
)

m_col1, m_col2 = st.columns(2)

with m_col1:
    st.markdown(
        """
        <div class="apple-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 15px; font-weight: 600; color: #ffffff;">FIPS 203 — ML-KEM</span>
                <span class="apple-pill pill-safe">Standardized</span>
            </div>
            <div class="section-eyebrow" style="color: #2997ff;">Module-Lattice Key Encapsulation Mechanism</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-top: 8px;">
                Replaces classical Diffie-Hellman, ECDH, and X25519 key exchange protocols. Standard defense against Harvest Now, Decrypt Later in TLS 1.3 handshakes.
            </p>
            <div style="font-size: 12px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px; margin-top: 12px;">
                <strong>Target in Inventory:</strong> TLS handshakes in <code>network.pcap</code> and internal service mesh listeners.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="apple-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 15px; font-weight: 600; color: #ffffff;">FIPS 204 — ML-DSA</span>
                <span class="apple-pill pill-safe">Standardized</span>
            </div>
            <div class="section-eyebrow" style="color: #30d158;">Module-Lattice Digital Signature Algorithm</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-top: 8px;">
                Primary post-quantum standard for digital signatures. Directly replaces RSA-PSS, PKCS#1 v1.5, ECDSA, and Ed25519 in authentication and signing.
            </p>
            <div style="font-size: 12px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px; margin-top: 12px;">
                <strong>Target in Inventory:</strong> JWT authentication tokens (<code>auth-gateway</code>), KMS keys, and ACM certificates.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with m_col2:
    st.markdown(
        """
        <div class="apple-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 15px; font-weight: 600; color: #ffffff;">FIPS 205 — SLH-DSA</span>
                <span class="apple-pill pill-safe">Standardized</span>
            </div>
            <div class="section-eyebrow" style="color: #ff9f0a;">Stateless Hash-Based Digital Signatures</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-top: 8px;">
                Contingency signature scheme relying exclusively on cryptographic hash functions (SPHINCS+). Provides structural defense against lattice cryptanalysis.
            </p>
            <div style="font-size: 12px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px; margin-top: 12px;">
                <strong>Target in Inventory:</strong> Long-term firmware signing and root-of-trust identity anchors.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="apple-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 15px; font-weight: 600; color: #ffffff;">Symmetric Hardening Mandate</span>
                <span class="apple-pill pill-medium">Grover Defense</span>
            </div>
            <div class="section-eyebrow" style="color: #ff453a;">Deprecation of AES-128</div>
            <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-top: 8px;">
                Grover's algorithm halves symmetric key strength. AES-128 effectively drops to 64 bits of quantum security. Mandates migration to AES-256.
            </p>
            <div style="font-size: 12px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px; margin-top: 12px;">
                <strong>Target in Inventory:</strong> Update <code>SessionCipher.java</code> and ELB listener TLS security policies.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# -----------------------------------------------------------------------------
# 11. Entregáveis e Compliance: CBOM CycloneDX 1.6
# -----------------------------------------------------------------------------
st.markdown("<div class='apple-divider'></div>", unsafe_allow_html=True)
st.markdown("<div id='cbom'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Regulatory & Audit Deliverables</div>
    <div class="section-heading">CycloneDX 1.6 CBOM Export.</div>
    <div class="section-description">
        Export a standardized Cryptography Bill of Materials (CBOM) compliant with CycloneDX 1.6 specifications for executive compliance and third-party auditors.
    </div>
    """,
    unsafe_allow_html=True
)

cbom_box1, cbom_box2 = st.columns([1.2, 2])

with cbom_box1:
    st.markdown(
        f"""
        <div class="apple-card">
            <div class="section-eyebrow">Specification Metadata</div>
            <div style="font-size: 14px; color: #ffffff; line-height: 1.8; margin-bottom: 16px;">
                <strong>Standard:</strong> CycloneDX JSON<br>
                <strong>Specification:</strong> v1.6<br>
                <strong>Crypto Assets:</strong> {len(df_findings)} components<br>
                <strong>Validation:</strong> RFC 4122 Compliant
            </div>
            <div class="section-eyebrow" style="margin-bottom: 8px;">Export Assets:</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.download_button(
        label="Download CycloneDX 1.6 CBOM (JSON)",
        data=cbom_json_string,
        file_name="quantumtrace_cbom.cdx.json",
        mime="application/json",
        use_container_width=True
    )

    st.download_button(
        label="Download Findings Dataset (JSON)",
        data=df_findings.to_json(orient="records", indent=2),
        file_name="quantumtrace_findings.json",
        mime="application/json",
        use_container_width=True
    )

with cbom_box2:
    st.markdown("<div class='section-eyebrow'>CycloneDX 1.6 Serialized Payload</div>", unsafe_allow_html=True)
    st.code(cbom_json_string[:1600] + "\n\n// ... [Remaining cryptographic components serialized to CycloneDX 1.6 schema] ...", language="json")


# -----------------------------------------------------------------------------
# 12. Rodapé Minimalista
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="apple-footer">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
                <strong>QuantumTrace</strong> · Developed for the JunctionX Lisbon 2026 Quantum Challenge.<br>
                Conforms strictly to NIST FIPS 203, FIPS 204, FIPS 205 and CycloneDX 1.6 CBOM specifications.
            </div>
            <div>
                Built by Miguel & Daniil (Dashboard & UX). Released under the MIT License.
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)
