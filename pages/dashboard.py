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
import streamlit.components.v1 as components

# -----------------------------------------------------------------------------
# 1. Configuração da Página e Tokens Visuais Apple
# -----------------------------------------------------------------------------
# Page config is set once in app.py (multipage entry point).

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

    html, body, [data-testid="stAppViewContainer"], section.main, .stApp, .block-container {
        scroll-behavior: smooth !important;
        background-color: var(--bg-page) !important;
    }

    body, [class*="css"], .stApp {
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", sans-serif !important;
        color: var(--text-headline) !important;
        letter-spacing: -0.014em;
    }

    header[data-testid="stHeader"], footer { display: none !important; }

    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 5rem !important;
        max-width: 1200px !important;
    }

    .section-anchor {
        scroll-margin-top: 16px !important;
        scroll-snap-margin-top: 16px !important;
        display: block !important;
        position: relative !important;
        visibility: hidden !important;
        height: 0px !important;
    }

    /* Navigation bar (scrolls with the page) */
    .apple-nav {
        position: relative; z-index: 99999;
        display: flex; align-items: center; justify-content: space-between;
        padding: 10px 28px;
        background: rgba(10, 10, 12, 0.78);
        backdrop-filter: saturate(180%) blur(24px);
        -webkit-backdrop-filter: saturate(180%) blur(24px);
        border-bottom: 1px solid var(--border-hairline);
        margin-left: -2rem; margin-right: -2rem; margin-top: -1.5rem; margin-bottom: 2.5rem;
    }
    .nav-brand {
        display: flex; align-items: center; gap: 10px;
        font-size: 14px; font-weight: 600; letter-spacing: -0.02em; color: #ffffff;
        text-decoration: none; cursor: pointer; user-select: none;
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease;
    }
    .nav-brand:active, .nav-brand.clicked { transform: scale(0.96); opacity: 0.85; }
    .nav-badge {
        font-size: 10px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase;
        color: var(--text-muted); background: rgba(255, 255, 255, 0.06);
        border: 1px solid var(--border-hairline); padding: 2px 8px; border-radius: 9999px;
    }
    .nav-links { display: flex; align-items: center; gap: 6px; }
    .nav-link {
        font-size: 12.5px; font-weight: 400; color: #86868b; text-decoration: none;
        padding: 6px 13px; border-radius: 9999px; cursor: pointer; user-select: none;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        display: inline-flex; align-items: center;
    }
    .nav-link:hover { color: #ffffff; background: rgba(255, 255, 255, 0.06); }
    .nav-link:active, .nav-link.clicked { transform: scale(0.91); background: rgba(255, 255, 255, 0.14); color: #ffffff; }
    .nav-link.active {
        color: #ffffff !important; font-weight: 500; background: rgba(255, 255, 255, 0.1);
        box-shadow: 0 0 16px rgba(255, 255, 255, 0.05), inset 0 0 0 1px rgba(255, 255, 255, 0.1);
    }
    .nav-cta {
        font-size: 12px; font-weight: 500; color: #000000 !important; background: #ffffff;
        padding: 6px 16px; border-radius: 9999px; text-decoration: none; margin-left: 8px;
        cursor: pointer; user-select: none; transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4); display: inline-flex; align-items: center;
    }
    .nav-cta:hover { background: #f5f5f7; transform: translateY(-1px) scale(1.02); box-shadow: 0 4px 16px rgba(255, 255, 255, 0.25); }
    .nav-cta:active, .nav-cta.clicked { transform: scale(0.93) translateY(0); opacity: 0.85; }

    /* Esconde o iframe de injeção JavaScript */
    div:has(> iframe[srcdoc*="apple-nav-enhancer-root"]) {
        position: absolute !important; height: 0 !important; width: 0 !important;
        opacity: 0 !important; pointer-events: none !important; border: none !important;
    }

    /* Tipografia e Cartões Apple */
    .hero-eyebrow { font-size: 12px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--apple-blue); margin-bottom: 12px; }
    .hero-title { font-size: 3.4rem; font-weight: 700; letter-spacing: -0.04em; line-height: 1.06; color: #ffffff; margin-bottom: 16px; }
    .hero-subtitle { font-size: 1.2rem; font-weight: 400; line-height: 1.5; color: var(--text-muted); max-width: 820px; margin-bottom: 28px; }

    .apple-card {
        background: var(--surface-card); border: 1px solid var(--border-hairline);
        border-radius: 16px; padding: 22px; margin-bottom: 20px;
        transition: border-color 0.2s ease, background 0.2s ease;
    }
    .apple-card:hover { border-color: var(--border-strong); background: var(--surface-card-hover); }

    .metric-hero-card {
        background: var(--surface-elevated); border: 1px solid var(--border-hairline);
        border-radius: 16px; padding: 20px; position: relative;
    }
    .metric-value-huge { font-size: 2.6rem; font-weight: 700; letter-spacing: -0.04em; line-height: 1; margin: 8px 0 4px 0; }
    .metric-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    .metric-sub { font-size: 11.5px; color: var(--text-faint); }

    .apple-pill {
        display: inline-flex; align-items: center; gap: 6px; font-size: 11px;
        font-weight: 600; letter-spacing: 0.02em; padding: 3px 10px; border-radius: 9999px;
    }
    .pill-critical { color: #ff453a; background: rgba(255, 69, 58, 0.12); border: 1px solid rgba(255, 69, 58, 0.24); }
    .pill-medium { color: #ff9f0a; background: rgba(255, 159, 10, 0.12); border: 1px solid rgba(255, 159, 10, 0.24); }
    .pill-safe { color: #30d158; background: rgba(48, 209, 88, 0.12); border: 1px solid rgba(48, 209, 88, 0.24); }

    .section-eyebrow { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--apple-blue); margin-bottom: 8px; }
    .section-heading { font-size: 2.1rem; font-weight: 700; letter-spacing: -0.03em; color: #ffffff; margin-bottom: 10px; }
    .section-description { font-size: 14.5px; color: var(--text-muted); line-height: 1.55; max-width: 740px; margin-bottom: 28px; }

    .vector-number { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; color: var(--text-faint); text-transform: uppercase; margin-bottom: 8px; }
    .vector-title { font-size: 17px; font-weight: 600; color: #ffffff; letter-spacing: -0.02em; margin-bottom: 8px; }
    .vector-desc { font-size: 13px; color: var(--text-body); line-height: 1.5; margin-bottom: 16px; }
    .vector-meta { font-size: 11.5px; color: var(--text-muted); background: rgba(255, 255, 255, 0.03); border-radius: 8px; padding: 10px 12px; border: 1px solid var(--border-hairline); }

    .apple-divider { height: 1px; background: var(--border-hairline); margin: 55px 0; }
    .apple-footer { padding: 40px 0; border-top: 1px solid var(--border-hairline); font-size: 12px; color: var(--text-faint); line-height: 1.8; }

    .stButton>button {
        background-color: var(--surface-card) !important; color: var(--text-headline) !important;
        border: 1px solid var(--border-hairline) !important; border-radius: 9999px !important;
        padding: 6px 18px !important; font-size: 13px !important; font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }
    .stButton>button:hover { background-color: var(--surface-card-hover) !important; border-color: var(--border-strong) !important; color: #ffffff !important; }
    .stDownloadButton>button {
        background-color: #ffffff !important; color: #000000 !important; border: none !important;
        border-radius: 9999px !important; padding: 8px 20px !important; font-size: 13px !important;
        font-weight: 600 !important; letter-spacing: -0.01em !important; transition: opacity 0.2s ease !important;
    }
    .stDownloadButton>button:hover { opacity: 0.9 !important; }

    .apple-nav a, .apple-nav a:hover, .apple-nav a:visited { text-decoration: none !important; }
    .apple-nav .nav-link { color: #86868b !important; } .apple-nav .nav-link:hover, .apple-nav .nav-link.active { color: #ffffff !important; }
    .apple-nav .nav-brand { color: #ffffff !important; } .apple-nav .nav-cta { color: #000000 !important; }
    /* Revelação progressiva */
    @keyframes qtFadeUp { from { opacity: 0; transform: translateY(18px); } to { opacity: 1; transform: none; } }
    .hero-eyebrow, .hero-title, .hero-subtitle, .apple-card, .metric-hero-card, .section-heading, .section-description {
        animation: qtFadeUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    .hero-title { animation-delay: 0.08s; } .hero-subtitle { animation-delay: 0.16s; }
    @supports (animation-timeline: view()) {
        .apple-card, .section-heading, .section-description, .metric-hero-card {
            animation-timeline: view(); animation-range: entry 0% cover 22%;
        }
    }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
    .hero-title { font-size: clamp(2.2rem, 6vw, 4.2rem) !important; }
    .section-heading { font-size: clamp(1.6rem, 3.6vw, 2.4rem) !important; }
    .data-notice { font-size: 12.5px; color: var(--text-muted); background: rgba(255,255,255,0.04);
        border: 1px solid var(--border-hairline); border-radius: 12px; padding: 12px 16px; margin-bottom: 24px; }
    html, body, .stApp { overflow-x: hidden !important; }
    @media (max-width: 900px) {
        .nav-links .nav-link { display: none; }
        .apple-nav { padding: 10px 16px; margin-left: -1rem; margin-right: -1rem; }
        .block-container { padding-left: 1rem !important; padding-right: 1rem !important; }
        [data-testid="stHorizontalBlock"] { flex-wrap: wrap !important; gap: 12px !important; }
        [data-testid="stHorizontalBlock"] > [data-testid="stColumn"], [data-testid="stHorizontalBlock"] > div[data-testid="column"] {
            min-width: calc(50% - 12px) !important; flex: 1 1 calc(50% - 12px) !important; }
        .metric-value-huge { font-size: 2rem; }
    }
    @media (max-width: 600px) {
        [data-testid="stHorizontalBlock"] > [data-testid="stColumn"], [data-testid="stHorizontalBlock"] > div[data-testid="column"] {
            min-width: 100% !important; flex: 1 1 100% !important; }
        .hero-subtitle { font-size: 1rem; }
        .stButton>button, .stDownloadButton>button { min-height: 44px; }
    }
    </style>
    """,
    unsafe_allow_html=True
)

# -----------------------------------------------------------------------------
# 2. Motor de Classificação Quântica NIST (FIPS 203 / 204 / 205)
# -----------------------------------------------------------------------------
def classify_finding(f):
    alg = str(f.get("algorithm", "")).strip().upper()
    notes = str(f.get("notes", "") or "").lower()
    asset = str(f.get("asset", "") or "").lower()
    key_len = f.get("key_length")

    if any(k in alg for k in ["MLKEM", "ML-KEM", "MLDSA", "ML-DSA", "SLHDSA", "SLH-DSA", "FIPS 203", "FIPS 204", "FIPS 205"]):
        return "Safe", "Compliant (NIST PQC Standard)"

    if any(k in alg for k in ["RSA", "DSA", "ECDSA", "ECDH", "X25519", "ED25519", "ED448", "DIFFIE-HELLMAN", "DH"]):
        if any(k in alg for k in ["ECDH", "X25519", "DIFFIE-HELLMAN", "DH"]) or "key exchange" in notes or "kem" in notes or "handshake" in notes:
            replacement = "ML-KEM (FIPS 203)"
        elif any(k in alg for k in ["ECDSA", "ED25519", "ED448", "DSA"]):
            replacement = "ML-DSA (FIPS 204)"
        else:
            if "sign" in notes or "signature" in asset or "token" in asset or "cert" in asset:
                replacement = "ML-DSA (FIPS 204)"
            else:
                replacement = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
        return "Critical", replacement

    if any(k in alg for k in ["AES-128", "3DES", "DES", "RC4", "BLOWFISH", "SHA-1", "SHA1", "MD5", "MD2", "MD4"]):
        replacement = "AES-256 (Grover-Resilient)" if any(k in alg for k in ["AES", "DES", "BLOWFISH", "RC4"]) else "SHA-256 / SHA-384"
        return "Medium", replacement

    if "AES" in alg and key_len == 128:
        return "Medium", "AES-256 (Grover-Resilient)"

    return "Safe", "Resilient (256-bit+ Security)"

# -----------------------------------------------------------------------------
# 3. Ingestão de Dados e Normalização
# -----------------------------------------------------------------------------
@st.cache_data(ttl=5, show_spinner=False)
def load_and_prepare_findings(findings_json=None):
    """findings_json: JSON text produced by your analysis program (list of findings,
    or {"findings": [...]}). Falls back to output/results.json."""
    raw_findings = []
    loaded_source = ""

    if findings_json:
        data = json.loads(findings_json)
        raw_findings = data.get("findings", []) if isinstance(data, dict) else list(data)
        loaded_source = st.session_state.get("results_label", "Uploaded analysis")

    for target_path in ([] if raw_findings else ["output/results.json", "results.json"]):
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    raw_findings = json.load(f)
                loaded_source = target_path
                break
            except Exception:
                pass

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

    if not raw_findings:
        return pd.DataFrame(), ""

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

@st.cache_data(show_spinner=False)
def sample_results():
    """Default report: the example data in the repository data/ folder, analysed once per server start
    with the same pipeline as a new audit. Falls back to output/results.json if the pipeline cannot run."""
    import shutil, tempfile
    from pathlib import Path as _P
    src = _P("data")
    if src.is_dir():
        try:
            from integration import run_analysis
            run_dir = _P(tempfile.gettempdir()) / "quantumtrace_uploads" / "sample-data"
            shutil.rmtree(run_dir, ignore_errors=True)
            shutil.copytree(src, run_dir / "data")
            return run_analysis(run_dir / "data"), "Sample data · data/"
        except Exception as exc:
            print(f"[QuantumTrace] Sample analysis failed, using output/results.json: {exc}")
    return None, ""


_results = st.session_state.get("results_json")
if not _results:
    with st.spinner("Loading sample data…"):
        _results, _label = sample_results()
    if _results:
        st.session_state["results_label"] = _label
df_findings, data_source_label = load_and_prepare_findings(_results)
if df_findings.empty:
    st.markdown(
        '<div style="max-width:620px;margin:18vh auto;text-align:center;">'
        '<div style="font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#2997ff;margin-bottom:12px;">No report loaded</div>'
        '<div style="font-size:clamp(2rem,5vw,3rem);font-weight:700;letter-spacing:-.04em;color:#fff;margin-bottom:14px;">Start with your data.</div>'
        '<div style="font-size:15px;color:#86868b;line-height:1.55;">No analysis results were found. Use New audit to upload your files and create a report.</div></div>',
        unsafe_allow_html=True,
    )
    _c = st.columns([1, 1, 1])[1]
    if _c.button("New audit", use_container_width=True):
        st.switch_page("pages/welcome.py")
    st.stop()
total_assets = len(df_findings)
critical_count = len(df_findings[df_findings["risk_tier"] == "Critical"])
medium_count = len(df_findings[df_findings["risk_tier"] == "Medium"])
safe_count = len(df_findings[df_findings["risk_tier"].isin(["Safe", "Quantum-resilient"])])
quantum_risk_score = int(((critical_count * 1.0 + medium_count * 0.4) / max(total_assets, 1)) * 100) if total_assets > 0 else 0

# -----------------------------------------------------------------------------
# 4. Serialização do CBOM CycloneDX 1.6
# -----------------------------------------------------------------------------
def generate_cbom_payload(df_to_export):
    try:
        import export_cbom
        # to_json turns NaN into null, so empty cells are exported as null (not the text "nan")
        records = json.loads(df_to_export.to_json(orient="records"))
        return export_cbom.export_cbom_json(records, indent=2)
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
# 5. Barra de Navegação Superior Fixa & Scroll Suave Apple
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
            <a href="/new-audit" target="_self" class="nav-link">New audit</a>
            <a href="#audit" class="nav-cta">Inspect Environment</a>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# Motor de Scroll Suave e Micro-interação Tátil
components.html(
    """
    <div id="apple-nav-enhancer-root"></div>
    <script>
    (function() {
        function attachAppleNavigation() {
            var doc = window.parent.document;
            if (!doc) return;
            var nav = doc.querySelector('.apple-nav');
            if (!nav) return;

            function getScrollContainer(fromEl) {
                // Sobe a partir do alvo até encontrar o elemento que realmente faz scroll
                var el = fromEl || doc.getElementById('overview') || nav;
                var win = doc.defaultView;
                while (el && el !== doc.body && el !== doc.documentElement) {
                    var oy = win.getComputedStyle(el).overflowY;
                    if ((oy === 'auto' || oy === 'scroll' || oy === 'overlay') && el.scrollHeight > el.clientHeight + 1) return el;
                    el = el.parentElement;
                }
                var known = doc.querySelector('[data-testid="stMain"], section.stMain, section.main, [data-testid="stAppViewContainer"]');
                if (known && known.scrollHeight > known.clientHeight + 1) return known;
                return doc.scrollingElement || doc.documentElement;
            }

            var links = nav.querySelectorAll('a[href^="#"]');
            links.forEach(function(link) {
                if (link.dataset.appleEnhanced === 'true') return;
                link.dataset.appleEnhanced = 'true';

                link.addEventListener('click', function(e) {
                    var targetId = this.getAttribute('href');
                    if (!targetId || targetId === '#') return;
                    var targetEl = doc.querySelector(targetId);
                    if (!targetEl) return;

                    e.preventDefault();
                    e.stopPropagation();

                    // Micro-interação tátil de clique (Spring scale)
                    link.classList.add('clicked');
                    setTimeout(function() { link.classList.remove('clicked'); }, 280);

                    // Atualização imediata do item ativo
                    if (link.classList.contains('nav-link')) {
                        nav.querySelectorAll('.nav-link').forEach(function(l) { l.classList.remove('active'); });
                        link.classList.add('active');
                    }

                    // Scroll suave com compensação da barra fixa (80px)
                    var container = getScrollContainer(targetEl);
                    var isWindow = (container === doc.documentElement || container === doc.body || container === doc.scrollingElement);
                    var containerTop = isWindow ? 0 : container.getBoundingClientRect().top;
                    var targetTop = targetEl.getBoundingClientRect().top;
                    var currentScroll = isWindow
                        ? (window.pageYOffset || doc.documentElement.scrollTop || doc.body.scrollTop || 0)
                        : container.scrollTop;

                    var targetY = currentScroll + (targetTop - containerTop) - 80;
                    container.scrollTo({ top: Math.max(0, targetY), behavior: 'smooth' });
                });
            });

            // Scrollspy dinâmico
            var sectionIds = ['overview', 'vectors', 'posture', 'audit', 'roadmap', 'cbom'];
            var sectionElements = sectionIds.map(function(id) { return doc.getElementById(id); }).filter(Boolean);

            if (window._appleNavObserver) window._appleNavObserver.disconnect();
            var container = getScrollContainer();
            var observerRoot = (container === doc.documentElement || container === doc.body) ? null : container;

            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        var id = entry.target.id;
                        nav.querySelectorAll('.nav-link').forEach(function(l) {
                            if (l.getAttribute('href') === '#' + id) l.classList.add('active');
                            else l.classList.remove('active');
                        });
                    }
                });
            }, { root: observerRoot, rootMargin: '-15% 0px -70% 0px', threshold: 0 });

            sectionElements.forEach(function(s) { observer.observe(s); });
            window._appleNavObserver = observer;
        }

        attachAppleNavigation();
        if (!window._appleNavInterval) window._appleNavInterval = setInterval(attachAppleNavigation, 600);
    })();
    </script>
    """,
    height=0
)

# -----------------------------------------------------------------------------
# 6. Hero Section & Indicadores Chave
# -----------------------------------------------------------------------------
st.markdown('<div id="overview" class="section-anchor"></div>', unsafe_allow_html=True)

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

st.markdown(
    """
    <div style="background: rgba(255, 69, 58, 0.08); border: 1px solid rgba(255, 69, 58, 0.25); border-radius: 12px; padding: 18px 22px; margin-bottom: 32px; display: flex; align-items: flex-start; gap: 16px;">
        <div style="color: #ff453a; font-size: 20px; line-height: 1;">⚠️</div>
        <div>
            <div style="font-size: 13.5px; font-weight: 600; color: #ffffff; letter-spacing: -0.01em;">
                Critical Exposure Vector: "Harvest Now, Decrypt Later" (HNDL)
            </div>
            <div style="font-size: 12.5px; color: #d1d1d6; line-height: 1.5; margin-top: 4px;">
                Adversaries are capturing and archiving encrypted TLS sessions and signatures today. The instant a cryptanalytically relevant quantum computer (CRQC) becomes operational, all stored traffic protected by RSA, ECDH, and ECDSA will be broken retroactively.
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

k1, k2, k3, k4 = st.columns(4)
score_color = "#ff453a" if quantum_risk_score > 60 else ("#ff9f0a" if quantum_risk_score > 30 else "#30d158")

metrics = [
    (k1, "Quantum Risk Score", str(quantum_risk_score), score_color, "Enterprise exposure index (/100)"),
    (k2, "Shor Vulnerabilities", str(critical_count), "#ff453a", "Critical: RSA, ECDSA, ECDH, Ed25519"),
    (k3, "Grover Weaknesses", str(medium_count), "#ff9f0a", "Medium: AES-128, 3DES, MD5, SHA-1"),
    (k4, "PQC Compliance", str(safe_count), "#30d158", "Safe: NIST FIPS 203 / Resilient 256-bit")
]
for col, lbl, val, clr, sub in metrics:
    with col:
        st.markdown(
            f'<div class="metric-hero-card"><div class="metric-label">{lbl}</div><div class="metric-value-huge" style="color: {clr};">{val}</div><div class="metric-sub">{sub}</div></div>',
            unsafe_allow_html=True
        )

# -----------------------------------------------------------------------------
# 7. Apresentação dos 3 Vetores Críticos
# -----------------------------------------------------------------------------
if True:
    st.markdown(f'<div class="data-notice">Data source: <code>{data_source_label}</code> · {total_assets} findings loaded.</div>', unsafe_allow_html=True)

st.markdown('<div class="apple-divider"></div>', unsafe_allow_html=True)
st.markdown('<div id="vectors" class="section-anchor"></div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Architecture & Visibility</div>
    <div class="section-heading">Comprehensive 360° Auditing.</div>
    <div class="section-description">
        QuantumTrace ingests and unifies cryptographic telemetry across every layer of the enterprise technology stack without intrusive agents.
    </div>
    """,
    unsafe_allow_html=True
)

v_cols = st.columns(3)
vector_data = [
    ("Vector 01", "In-Transit Network", "Passive inspection of raw TLS handshakes from packet captures (.pcap). Identifies classical key exchanges and hybrid PQC suites.", "network-capture/*.pcap", "TLS 1.2 / 1.3 Key Exchanges", len(df_findings[df_findings["source"] == "network"]), "captured endpoints"),
    ("Vector 02", "In-Use Codebase", "Static AST and semantic scanning across Python, Java, and Go repositories for hardcoded algorithms, tokens, and cryptographic libraries.", "sample-repos/ (Python, Java, Go)", "cryptography, crypto/ecdsa, javax", len(df_findings[df_findings["source"] == "code"]), "source occurrences"),
    ("Vector 03", "At-Rest Cloud", "Configuration audits across AWS KMS key rings, ACM SSL/TLS certificates, and Application Load Balancer security policies.", "cloud-posture/*.json", "KMS policies, ACM certs, ELB ciphers", len(df_findings[df_findings["source"] == "cloud"]), "cloud configurations")
]

for col, (num, title, desc, ing, focus, count, unit) in zip(v_cols, vector_data):
    with col:
        st.markdown(
            f"""
            <div class="apple-card">
                <div class="vector-number">{num}</div>
                <div class="vector-title">{title}</div>
                <div class="vector-desc">{desc}</div>
                <div class="vector-meta">
                    <strong>Ingestion:</strong> {ing}<br>
                    <strong>Focus:</strong> {focus}<br>
                    <strong>Findings:</strong> {count} {unit}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# -----------------------------------------------------------------------------
# 8. Matriz de Ameaça & Telemetria Visual
# -----------------------------------------------------------------------------
st.markdown('<div class="apple-divider"></div>', unsafe_allow_html=True)
st.markdown('<div id="posture" class="section-anchor"></div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Threat Matrix & Posture</div>
    <div class="section-heading">Cryptographic Debt Breakdown.</div>
    <div class="section-description">
        Visualizing algorithm distribution by vulnerability class, quantum impact mechanism, and ingestion source.
    </div>
    """,
    unsafe_allow_html=True
)

g_col1, g_col2 = st.columns(2)

with g_col1:
    st.markdown('<div class="section-eyebrow">Risk Classification Distribution</div>', unsafe_allow_html=True)
    df_risk = df_findings["risk_tier"].value_counts().reset_index()
    df_risk.columns = ["Risk Tier", "Count"]

    chart_risk = (
        alt.Chart(df_risk).mark_bar(cornerRadius=6, height=28).encode(
            x=alt.X("Count:Q", title="Component Count", axis=alt.Axis(grid=True, gridColor="#1c1c1f")),
            y=alt.Y("Risk Tier:N", sort=["Critical", "Medium", "Safe"], title=""),
            color=alt.Color("Risk Tier:N", scale=alt.Scale(domain=["Critical", "Medium", "Safe"], range=["#ff453a", "#ff9f0a", "#30d158"]), legend=None),
            tooltip=["Risk Tier", "Count"]
        ).properties(height=180, background="transparent").configure_view(strokeOpacity=0)
    )
    st.altair_chart(chart_risk, use_container_width=True)

with g_col2:
    st.markdown('<div class="section-eyebrow">Telemetry · Ingestion Vector Breakdown</div>', unsafe_allow_html=True)
    df_source = df_findings["source"].value_counts().reset_index()
    df_source.columns = ["Vector", "Count"]
    df_source["Vector"] = df_source["Vector"].str.capitalize()

    chart_source = (
        alt.Chart(df_source).mark_bar(cornerRadius=6, height=28).encode(
            x=alt.X("Count:Q", title="Component Count", axis=alt.Axis(grid=True, gridColor="#1c1c1f")),
            y=alt.Y("Vector:N", title=""),
            color=alt.Color("Vector:N", scale=alt.Scale(domain=["Network", "Code", "Cloud"], range=["#2997ff", "#bf5af2", "#ff9f0a"]), legend=None),
            tooltip=["Vector", "Count"]
        ).properties(height=180, background="transparent").configure_view(strokeOpacity=0)
    )
    st.altair_chart(chart_source, use_container_width=True)

# -----------------------------------------------------------------------------
# 9. Secção Funcional: Auditoria ao Vivo & Inspetor de Ativos
# -----------------------------------------------------------------------------
st.markdown('<div class="apple-divider"></div>', unsafe_allow_html=True)
st.markdown('<div id="audit" class="section-anchor"></div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Interactive Environment Audit</div>
    <div class="section-heading">Cryptographic Asset Inventory.</div>
    <div class="section-description">
        Filter, inspect, and analyze every discovered cryptographic asset. Trace the vulnerable primitive to its source and review the NIST-mandated replacement.
    </div>
    """,
    unsafe_allow_html=True
)

filter_col1, filter_col2, filter_col3 = st.columns([1.2, 1.2, 2])
with filter_col1:
    source_options = ["All Vectors"] + sorted(list(df_findings["source"].unique()))
    selected_source = st.selectbox("Ingestion Vector", options=source_options, index=0)

with filter_col2:
    risk_options = ["All Tiers"] + sorted(list(df_findings["risk_tier"].unique()))
    selected_risk = st.selectbox("Risk Classification", options=risk_options, index=0)

with filter_col3:
    search_query = st.text_input("Search Asset or Algorithm", placeholder="e.g. RSA, TLS, license_token.py...")

filtered_df = df_findings.copy()
if selected_source != "All Vectors":
    filtered_df = filtered_df[filtered_df["source"] == selected_source]
if selected_risk != "All Tiers":
    filtered_df = filtered_df[filtered_df["risk_tier"] == selected_risk]
if search_query:
    q = search_query.lower()
    filtered_df = filtered_df[
        filtered_df["asset"].fillna("").astype(str).str.lower().str.contains(q, regex=False)
        | filtered_df["algorithm"].fillna("").astype(str).str.lower().str.contains(q, regex=False)
        | filtered_df["location"].fillna("").astype(str).str.lower().str.contains(q, regex=False)
        | filtered_df["replacement"].fillna("").astype(str).str.lower().str.contains(q, regex=False)
    ]

st.markdown(f'<div style="font-size: 13px; color: #86868b; margin-bottom: 12px;">Displaying <strong>{len(filtered_df)}</strong> of {total_assets} cryptographic components · Source: <code>{data_source_label}</code></div>', unsafe_allow_html=True)

display_cols = ["asset", "source", "algorithm", "key_length", "risk_tier", "replacement", "location"]
table_df = filtered_df[display_cols].rename(columns={
    "asset": "Cryptographic Asset",
    "source": "Vector",
    "algorithm": "Algorithm",
    "key_length": "Key Size (bits)",
    "risk_tier": "Quantum Risk",
    "replacement": "NIST PQC Replacement",
    "location": "Source File / Target"
})

st.dataframe(table_df, use_container_width=True, hide_index=True)

st.markdown('<div style="height: 12px;"></div>', unsafe_allow_html=True)
with st.expander("Component Deep-Dive Inspector", expanded=True):
    asset_list = filtered_df["asset"].tolist()
    if not asset_list:
        st.info("No assets match the current filters. Adjust the vector, risk tier or search to inspect a component.")
    selected_asset = st.selectbox("Select asset for deep inspection:", options=asset_list, index=0 if asset_list else None, key="inspector_asset") if asset_list else None
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
            tier_class = "pill-critical" if asset_row['risk_tier'] == "Critical" else ("pill-medium" if asset_row['risk_tier'] == "Medium" else "pill-safe")
            st.markdown(
                f"""
                <div class="apple-card" style="margin-bottom: 0;">
                    <div class="section-eyebrow">Quantum Posture Assessment</div>
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                        <span style="font-size: 17px; font-weight: 600; color: #ffffff;">{asset_row['algorithm']} ({asset_row.get('key_length') or 'N/A'} bits)</span>
                        <span class="apple-pill {tier_class}">{asset_row['risk_tier']}</span>
                    </div>
                    <div style="font-size: 13px; color: #86868b; line-height: 1.7;">
                        <strong>Mandated Migration:</strong> <span style="color: #2997ff; font-weight: 500;">{asset_row['replacement']}</span><br>
                        <strong>Audit Notes:</strong> {asset_row.get('notes') or 'Analyzed against NIST PQC requirements.'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

# -----------------------------------------------------------------------------
# 10. Roteiro de Migração NIST PQC
# -----------------------------------------------------------------------------
st.markdown('<div class="apple-divider"></div>', unsafe_allow_html=True)
st.markdown('<div id="roadmap" class="section-anchor"></div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="section-eyebrow">Cryptographic Agility & Migration</div>
    <div class="section-heading">NIST Post-Quantum Standards Roadmap.</div>
    <div class="section-description">
        Transition strategy aligning enterprise findings with the official post-quantum standards finalized by NIST in August 2024.
    </div>
    """,
    unsafe_allow_html=True
)

m_col1, m_col2 = st.columns(2)
roadmap_standards = [
    (m_col1, "FIPS 203 — ML-KEM", "Standardized", "pill-safe", "Module-Lattice Key Encapsulation (Kyber)", "Mandated for general-purpose post-quantum public-key encryption and key establishment. Replaces ECDH, RSA, and X25519 in TLS 1.3.", "Target in Inventory: Update TLS handshakes across public web endpoints and API gateways."),
    (m_col1, "FIPS 204 — ML-DSA", "Standardized", "pill-safe", "Module-Lattice Digital Signatures (Dilithium)", "Primary standard for quantum-resistant digital signatures. Direct successor to RSA-2048/3072, ECDSA P-256, and Ed25519.", "Target in Inventory: Re-sign JWT tokens, webhooks, and AWS KMS asymmetric signing keys."),
    (m_col2, "FIPS 205 — SLH-DSA", "Standardized", "pill-safe", "Stateless Hash-Based Digital Signatures", "Contingency signature scheme relying exclusively on cryptographic hash functions (SPHINCS+). Provides structural defense against lattice cryptanalysis.", "Target in Inventory: Long-term firmware signing and root-of-trust identity anchors."),
    (m_col2, "Symmetric Hardening", "Grover Defense", "pill-medium", "Deprecation of AES-128", "Grover's algorithm halves symmetric key strength. AES-128 effectively drops to 64 bits of quantum security. Mandates migration to AES-256.", "Target in Inventory: Update SessionCipher.java and ELB listener TLS security policies.")
]

for col, title, badge, badge_cls, subtitle, desc, target in roadmap_standards:
    with col:
        st.markdown(
            f"""
            <div class="apple-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 15px; font-weight: 600; color: #ffffff;">{title}</span>
                    <span class="apple-pill {badge_cls}">{badge}</span>
                </div>
                <div class="section-eyebrow">{subtitle}</div>
                <p style="font-size: 13px; color: #86868b; line-height: 1.5; margin-top: 8px;">{desc}</p>
                <div style="font-size: 12px; color: #d1d1d6; background: rgba(255, 255, 255, 0.04); border-radius: 8px; padding: 12px; margin-top: 12px;">
                    <strong>{target.split(':')[0]}:</strong>{target.split(':')[1]}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# -----------------------------------------------------------------------------
# 11. Entregáveis e Compliance: CBOM CycloneDX 1.6
# -----------------------------------------------------------------------------
st.markdown('<div class="apple-divider"></div>', unsafe_allow_html=True)
st.markdown('<div id="cbom" class="section-anchor"></div>', unsafe_allow_html=True)

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
    st.markdown('<div class="section-eyebrow">CycloneDX 1.6 Serialized Payload</div>', unsafe_allow_html=True)
    preview_cbom = cbom_json_string[:1400] + "\\n\\n// ... [Remaining cryptographic components serialized to CycloneDX 1.6 schema] ..."
    st.code(preview_cbom, language="json")

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
