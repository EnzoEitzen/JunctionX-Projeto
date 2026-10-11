"""
QuantumTrace — Welcome page.
Upload a folder with the same structure as the repository `data/` folder,
hand it to your analysis program (integration.py) and open the report.
"""
import io
import json
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

import streamlit as st

from integration import run_analysis

# Same structure and file names as the repository data/ folder
REQUIRED_FILES = [
    "cloud-posture/kms_key_inventory.json",
    "cloud-posture/acm_certificates.json",
    "cloud-posture/load_balancer_listeners.json",
    "network-capture/network.pcap",
]
KNOWN_ROOTS = ("cloud-posture", "network-capture", "sample-repos")
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "quantumtrace_uploads"   # temporary; deleted after each audit


def normalize_relpath(name: str):
    """'data/cloud-posture/x.json' -> 'cloud-posture/x.json' (None if outside the known folders)."""
    parts = [p for p in re.split(r"[\\/]+", name) if p and p != "."]
    for i, p in enumerate(parts):
        if p in KNOWN_ROOTS:
            return "/".join(parts[i:])
    return None


def validate_structure(rel_paths):
    missing = [f for f in REQUIRED_FILES if f not in rel_paths]
    code_files = [p for p in rel_paths if p.startswith("sample-repos/") and p.endswith((".py", ".java", ".go"))]
    if not code_files:
        missing.append("sample-repos/ (Python, Java or Go files)")
    return {"ok": not missing, "missing": missing, "code_files": len(code_files)}

st.markdown(
    """
    <style>
    :root {
        --bg-page: #000000; --surface-card: #161618; --surface-elevated: #111113;
        --border-hairline: rgba(255,255,255,0.08); --border-strong: rgba(255,255,255,0.16);
        --text-headline: #f5f5f7; --text-muted: #86868b; --text-faint: #636366;
        --accent: #2997ff; --red: #ff453a; --green: #30d158;
    }
    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background: var(--bg-page) !important; }
    .stApp, body { font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", sans-serif !important; color: var(--text-headline) !important; letter-spacing: -0.014em; }
    header[data-testid="stHeader"], footer { display: none !important; }
    .block-container { max-width: 980px !important; padding-top: 0 !important; padding-bottom: 6rem !important; }
    html, body, .stApp { overflow-x: hidden !important; }

    @keyframes qtFadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: none; } }
    @keyframes qtGlow { 0%,100% { opacity: .55; transform: scale(1); } 50% { opacity: .9; transform: scale(1.06); } }

    .w-nav { display:flex; justify-content:space-between; align-items:center; padding:14px 0; border-bottom:1px solid var(--border-hairline); margin-bottom: 9vh; }
    .w-brand { font-size:14px; font-weight:600; color:#fff; display:flex; gap:10px; align-items:center; }
    .w-badge { font-size:10px; font-weight:600; letter-spacing:.06em; text-transform:uppercase; color:var(--text-muted); border:1px solid var(--border-hairline); padding:2px 8px; border-radius:999px; }
    .w-hero { text-align:center; animation: qtFadeUp .9s cubic-bezier(.16,1,.3,1) both; }
    .w-orb { width:120px; height:120px; margin:0 auto 34px; border-radius:50%;
        background: radial-gradient(circle at 35% 30%, #ffffff 0%, #9fd0ff 18%, #2997ff 45%, #0a2a4d 75%, transparent 76%);
        box-shadow: 0 0 80px rgba(41,151,255,.35); animation: qtGlow 5s ease-in-out infinite; }
    .w-eyebrow { font-size:12px; font-weight:600; letter-spacing:.08em; text-transform:uppercase; color:var(--accent); margin-bottom:14px; }
    .w-title { font-size: clamp(2.4rem, 7vw, 4.6rem); font-weight:700; letter-spacing:-.045em; line-height:1.04; color:#fff; margin-bottom:18px; }
    .w-sub { font-size: clamp(1rem, 2.2vw, 1.25rem); color:var(--text-muted); line-height:1.5; max-width:640px; margin:0 auto 10vh; }

    .w-step { animation: qtFadeUp .9s cubic-bezier(.16,1,.3,1) .15s both; }
    .w-step-num { font-size:11px; font-weight:700; letter-spacing:.08em; color:var(--text-faint); text-transform:uppercase; margin-bottom:8px; }
    .w-step-title { font-size: clamp(1.5rem, 3.4vw, 2.2rem); font-weight:700; letter-spacing:-.03em; color:#fff; margin-bottom:8px; }
    .w-step-desc { font-size:14.5px; color:var(--text-muted); line-height:1.55; max-width:640px; margin-bottom:22px; }

    .w-tree { font-family: "SF Mono", ui-monospace, Menlo, monospace; font-size:12.5px; line-height:1.9; color:#d1d1d6;
        background:var(--surface-elevated); border:1px solid var(--border-hairline); border-radius:16px; padding:18px 22px; margin-bottom:22px; overflow-x:auto; }
    .w-tree .ok { color: var(--green); } .w-tree .miss { color: var(--red); } .w-tree .dim { color: var(--text-faint); }

    [data-testid="stFileUploaderDropzone"] { background: var(--surface-card) !important; border: 1px dashed var(--border-strong) !important; border-radius: 18px !important; padding: 34px 20px !important; transition: border-color .2s ease, background .2s ease; }
    [data-testid="stFileUploaderDropzone"]:hover { border-color: var(--accent) !important; background: #1a1a1d !important; }
    [data-testid="stFileUploader"] label, .stTextInput label { color: var(--text-muted) !important; font-size: 12px !important; }
    .stTextInput input { background: var(--surface-card) !important; color:#fff !important; border:1px solid var(--border-hairline) !important; border-radius: 12px !important; }
    [data-testid="stTabs"] button p { font-size: 13px !important; }

    .stButton>button[kind="primary"] { background:#fff !important; color:#000 !important; border:none !important; border-radius:999px !important; padding:10px 28px !important; font-weight:600 !important; font-size:14px !important; min-height:46px; transition: transform .2s cubic-bezier(.16,1,.3,1), opacity .2s; }
    .stButton>button[kind="primary"]:hover { transform: translateY(-1px) scale(1.02); }
    .stButton>button[kind="primary"]:disabled { background: #2a2a2d !important; color: var(--text-faint) !important; transform:none; }
    .stButton>button[kind="secondary"] { background: var(--surface-card) !important; color:#f5f5f7 !important; border:1px solid var(--border-hairline) !important; border-radius:999px !important; font-size:12.5px !important; }

    .w-divider { height:1px; background:var(--border-hairline); margin: 9vh 0 6vh; }
    .w-report { display:flex; justify-content:space-between; align-items:center; gap:12px; padding:14px 0; border-bottom:1px solid var(--border-hairline); }
    .w-report-name { font-size:14px; color:#fff; font-weight:500; }
    .w-report-meta { font-size:12px; color:var(--text-muted); }
    .w-note { font-size:12.5px; color:var(--text-muted); background: rgba(255,255,255,.04); border:1px solid var(--border-hairline); border-radius:12px; padding:12px 16px; margin: 6px 0 18px; }
    .w-note.err { color:#ffb4ae; background: rgba(255,69,58,.08); border-color: rgba(255,69,58,.25); }
    .w-footer { margin-top: 10vh; padding-top: 22px; border-top:1px solid var(--border-hairline); font-size:12px; color:var(--text-faint); display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
    @media (max-width: 640px) { .w-nav { margin-bottom: 6vh; } .w-sub { margin-bottom: 7vh; } }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="w-nav">
        <div class="w-brand">QuantumTrace <span class="w-badge">PQC Readiness</span></div>
        <div class="w-badge">CycloneDX 1.6 · NIST FIPS 203/204/205</div>
    </div>
    <div class="w-hero">
        <div class="w-orb"></div>
        <div class="w-eyebrow">Welcome to QuantumTrace</div>
        <div class="w-title">See your cryptography.<br>Before quantum does.</div>
        <div class="w-sub">Drop in your environment export — network capture, code repositories and cloud configuration —
        and get a full quantum-readiness report in seconds.</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Step 1 — upload
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="w-step">
        <div class="w-step-num">Step 01</div>
        <div class="w-step-title">Upload your data folder.</div>
        <div class="w-step-desc">Use the same structure and file names as the <code>data/</code> folder of the repository.
        Select the folder itself, or upload it as a single ZIP file.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_folder, tab_zip = st.tabs(["Folder", "ZIP file"])
with tab_folder:
    folder_files = st.file_uploader(
        "Select the data folder", accept_multiple_files="directory", key="upload_folder",
        label_visibility="collapsed",
    )
with tab_zip:
    zip_file = st.file_uploader("Upload data.zip", type=["zip"], key="upload_zip", label_visibility="collapsed")


def collect_uploads() -> dict[str, bytes]:
    """Return {normalized relative path: content} from whichever uploader was used."""
    files: dict[str, bytes] = {}
    if zip_file is not None:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_file.getvalue())) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    rel = normalize_relpath(info.filename)
                    if rel and ".." not in rel.split("/"):
                        files[rel] = zf.read(info)
        except zipfile.BadZipFile:
            st.markdown('<div class="w-note err">This ZIP file could not be opened. Please check the file and try again.</div>', unsafe_allow_html=True)
    for uf in folder_files or []:
        rel = normalize_relpath(uf.name)
        if rel and ".." not in rel.split("/"):
            files[rel] = uf.getvalue()
    return files


uploads = collect_uploads()
check = validate_structure(set(uploads))


def tree_html() -> str:
    def row(path, ok, label=None):
        cls, mark = ("ok", "✓") if ok else ("miss", "✕") if uploads else ("dim", "○")
        return f'<span class="{cls}">{mark}</span>&nbsp; {label or path}<br>'

    html = '<div class="w-tree"><span class="dim">data/</span><br>'
    html += '<span class="dim">├─ cloud-posture/</span><br>'
    for f in REQUIRED_FILES[:3]:
        html += "│&nbsp;&nbsp;&nbsp;" + row(f, f in uploads, f.split("/")[1])
    html += '<span class="dim">├─ network-capture/</span><br>'
    html += "│&nbsp;&nbsp;&nbsp;" + row(REQUIRED_FILES[3], REQUIRED_FILES[3] in uploads, "network.pcap")
    html += '<span class="dim">└─ sample-repos/</span><br>'
    html += "&nbsp;&nbsp;&nbsp;&nbsp;" + row("sample-repos", check["code_files"] > 0,
                                              f"python · java · go &nbsp;<span class='dim'>({check['code_files']} source files)</span>")
    return html + "</div>"


st.markdown(tree_html(), unsafe_allow_html=True)

if uploads and not check["ok"]:
    st.markdown(
        '<div class="w-note err">Some required files are missing: <strong>'
        + ", ".join(check["missing"]) + "</strong>. Keep the same folder and file names as the repository.</div>",
        unsafe_allow_html=True,
    )

# -----------------------------------------------------------------------------
# Step 2 — run the audit through integration.run_analysis()
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="w-step" style="margin-top: 7vh;">
        <div class="w-step-num">Step 02</div>
        <div class="w-step-title">Run the audit.</div>
        <div class="w-step-desc">QuantumTrace scans every handshake, source file and key, classifies each primitive
        against NIST post-quantum standards and opens the report.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

report_name = st.text_input("Report name", value="Environment audit", max_chars=80)
run = st.button("Run audit and open report", type="primary", disabled=not check["ok"])

if run:
    with st.status("Running QuantumTrace…", expanded=True) as status:
        # 1. Save the uploaded folder to disk with the original structure: uploads/<timestamp>/data/...
        data_dir = UPLOAD_ROOT / datetime.now().strftime("%Y%m%d-%H%M%S") / "data"
        st.write(f"Saving {len(uploads)} files")
        for rel, content in uploads.items():
            dest = data_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
        # 2. Hand the folder to your analysis program (see integration.py)
        st.write("Analyzing network capture, code repositories and cloud configuration")
        try:
            results = run_analysis(data_dir)
        except Exception as exc:
            status.update(label="The analysis could not be completed.", state="error")
            st.error(str(exc))
            st.stop()
        status.update(label="Audit complete", state="complete")
    # 3. The report page reads this JSON
    st.session_state["results_json"] = results if isinstance(results, str) else json.dumps(results)
    st.session_state["results_label"] = report_name.strip() or "Environment audit"
    st.switch_page("pages/dashboard.py")

st.markdown(
    '<div class="w-footer"><span>QuantumTrace · JunctionX Lisbon 2026</span><span>Cryptographic inventory · Quantum readiness</span></div>',
    unsafe_allow_html=True,
)