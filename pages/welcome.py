"""
QuantumTrace — Welcome page.
Upload a folder, ZIP or files (JSON files with any name), organise them in the
data/ layout, hand them to the analysis program (integration.py) and open the report.
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

# Accepted inputs. JSON files can have ANY name: each one is recognised by its content and saved
# under the file name the config scanner expects, so the analysis pipeline does not change.
CLOUD_TYPES = {
    # key in the JSON -> (file name expected by config_scanner.py, label)
    "Keys": ("kms_key_inventory.json", "KMS keys"),
    "Certificates": ("acm_certificates.json", "ACM certificates"),
    "LoadBalancers": ("load_balancer_listeners.json", "Load balancers"),
}
CODE_EXT = (".py", ".java", ".go")
CODE_EXTRA = ("go.mod", "requirements.txt")
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "quantumtrace_uploads"   # temporary; deleted after each audit


def _parts(name: str):
    return [p for p in re.split(r"[\\/]+", name) if p and p not in (".", "..")]


def _code_relpath(parts):
    """Keep the path below sample-repos/ (or below the top uploaded folder)."""
    if "sample-repos" in parts:
        return "/".join(parts[parts.index("sample-repos") + 1:])
    return "/".join(parts[1:] if len(parts) > 1 else parts)


def _json_kind(content: bytes):
    """Return ('cloud', key, data) | ('results', None, text) | (None, reason, None)."""
    try:
        data = json.loads(content.decode("utf-8-sig"))
    except Exception:
        return None, "not valid JSON", None
    if isinstance(data, dict):
        for key in CLOUD_TYPES:
            if isinstance(data.get(key), list):
                return "cloud", key, data
        if isinstance(data.get("findings"), list):
            return "results", None, json.dumps(data["findings"])
    if isinstance(data, list) and data and all(isinstance(x, dict) for x in data) \
            and any("algorithm" in x for x in data):
        return "results", None, json.dumps(data)
    return None, "format not recognised", None


def organize(raw: dict):
    """Sort uploaded files into the data/ layout. Returns a plan dict."""
    plan = {"files": {}, "cloud": {}, "pcaps": [], "code": 0, "results": [], "ignored": []}
    for name, content in raw.items():
        parts = _parts(name)
        if not parts:
            continue
        base = parts[-1]
        low = base.lower()
        if low.endswith(".json"):
            kind, key, data = _json_kind(content)
            if kind == "cloud":
                fname = CLOUD_TYPES[key][0]
                if fname in plan["cloud"]:          # several files of the same type -> merge their lists
                    plan["cloud"][fname][key].extend(data[key])
                else:
                    plan["cloud"][fname] = data
                plan.setdefault("sources", {}).setdefault(fname, []).append(base)
            elif kind == "results":
                plan["results"].append((base, data))
            else:
                plan["ignored"].append(f"{base} ({key})")
        elif low.endswith((".pcap", ".pcapng")):
            plan["files"][f"network-capture/{base}"] = content
            plan["pcaps"].append(base)
        elif low.endswith(CODE_EXT) or base in CODE_EXTRA:
            rel = _code_relpath(parts)
            if rel:
                plan["files"][f"sample-repos/{rel}"] = content
                plan["code"] += low.endswith(CODE_EXT)
    for fname, data in plan["cloud"].items():
        plan["files"][f"cloud-posture/{fname}"] = json.dumps(data).encode("utf-8")
    missing = []
    if not (plan["cloud"] or plan["pcaps"] or plan["code"]):
        missing.append("at least one supported file: a cloud .json (KMS keys, ACM certificates "
                       "or load balancers), a network capture (.pcap / .pcapng) or source code "
                       "(.py, .java or .go)")
    plan["missing"] = missing
    plan["ok"] = not missing
    return plan

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
        <a class="w-brand" href="/" target="_self" style="text-decoration:none">QuantumTrace <span class="w-badge">PQC Readiness</span></a>
        <a class="w-badge" href="/" target="_self" style="text-decoration:none">← Back to report</a>
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
        <div class="w-step-title">Upload your data.</div>
        <div class="w-step-desc">Select a folder, a ZIP, or individual files. JSON files can have any name —
        each one is recognised by its content. A results <code>.json</code> from a previous analysis opens the report directly.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_folder, tab_zip, tab_files = st.tabs(["Folder", "ZIP file", "Files"])
with tab_folder:
    folder_files = st.file_uploader(
        "Select the data folder", accept_multiple_files="directory", key="upload_folder",
        label_visibility="collapsed",
    )
with tab_zip:
    zip_file = st.file_uploader("Upload data.zip", type=["zip"], key="upload_zip", label_visibility="collapsed")
with tab_files:
    loose_files = st.file_uploader(
        "Upload files", accept_multiple_files=True, key="upload_files", label_visibility="collapsed",
        type=["json", "pcap", "pcapng", "py", "java", "go", "mod", "txt"],
    )


def collect_uploads() -> dict[str, bytes]:
    """Return {uploaded path: content} from every uploader."""
    files: dict[str, bytes] = {}
    if zip_file is not None:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_file.getvalue())) as zf:
                for info in zf.infolist():
                    if not info.is_dir() and "__MACOSX" not in info.filename:
                        files[info.filename] = zf.read(info)
        except zipfile.BadZipFile:
            st.markdown('<div class="w-note err">This ZIP file could not be opened. Please check the file and try again.</div>', unsafe_allow_html=True)
    for uf in (folder_files or []) + (loose_files or []):
        files[uf.name] = uf.getvalue()
    return files


raw_uploads = collect_uploads()
plan = organize(raw_uploads)
uploads = plan["files"]


def tree_html() -> str:
    def mark(ok):
        return ('<span class="ok">✓</span>' if ok else '<span class="miss">✕</span>') if raw_uploads else '<span class="dim">○</span>'

    html = '<div class="w-tree"><span class="dim">data/</span><br>'
    html += '<span class="dim">├─ cloud-posture/</span> <span class="dim">· any .json name</span><br>'
    for key, (fname, label) in CLOUD_TYPES.items():
        src = plan.get("sources", {}).get(fname, [])
        detail = f" <span class='dim'>← {', '.join(src)}</span>" if src else " <span class='dim'>(optional)</span>"
        m = mark(True) if src else ('<span class="dim">○</span>' if plan["cloud"] else mark(False))
        html += f"│&nbsp;&nbsp;&nbsp;{m}&nbsp; {label}{detail}<br>"
    html += '<span class="dim">├─ network-capture/</span><br>'
    pc = ", ".join(plan["pcaps"]) if plan["pcaps"] else ".pcap / .pcapng"
    html += f"│&nbsp;&nbsp;&nbsp;{mark(bool(plan['pcaps']))}&nbsp; {pc}<br>"
    html += '<span class="dim">└─ sample-repos/</span><br>'
    html += f"&nbsp;&nbsp;&nbsp;&nbsp;{mark(plan['code'] > 0)}&nbsp; python · java · go &nbsp;<span class='dim'>({plan['code']} source files)</span>"
    return html + "</div>"


st.markdown(tree_html(), unsafe_allow_html=True)

if plan["ignored"]:
    st.markdown('<div class="w-note">Ignored JSON files: <strong>' + ", ".join(plan["ignored"]) + "</strong>.</div>",
                unsafe_allow_html=True)

# A results .json (output of the analysis program) can be opened directly
if plan["results"]:
    names = ", ".join(n for n, _ in plan["results"])
    st.markdown(f'<div class="w-note">Analysis results found: <strong>{names}</strong>. Open them without running a new audit.</div>',
                unsafe_allow_html=True)
    if st.button("Open results in the report", type="primary", key="open_results"):
        merged = []
        for _, text in plan["results"]:
            merged.extend(json.loads(text))
        st.session_state["results_json"] = json.dumps(merged)
        st.session_state["results_label"] = names
        st.switch_page("pages/dashboard.py")
elif raw_uploads and not plan["ok"]:
    st.markdown('<div class="w-note err">Still missing: <strong>' + "; ".join(plan["missing"]) + "</strong>.</div>",
                unsafe_allow_html=True)

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
run = st.button("Run audit and open report", type="primary", disabled=not plan["ok"])

if run:
    with st.status("Running QuantumTrace…", expanded=True) as status:
        # 1. Save the uploaded folder to disk with the original structure: uploads/<timestamp>/data/...
        data_dir = UPLOAD_ROOT / datetime.now().strftime("%Y%m%d-%H%M%S") / "data"
        st.write(f"Saving {len(uploads)} files")
        # Always create every expected subfolder (empty if nothing was uploaded for it),
        # so the analysis program never fails with "Input folder not found".
        for sub in ("cloud-posture", "network-capture", "sample-repos"):
            (data_dir / sub).mkdir(parents=True, exist_ok=True)
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
