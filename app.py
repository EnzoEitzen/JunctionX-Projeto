"""
QuantumTrace — entry point.

Run with:  streamlit run app.py

Page 1 (Report, "/"): the QuantumTrace dashboard. Opens with the example data in data/.
Page 2 (New audit, "/new-audit"): upload files (any .json names), run
integration.run_analysis() and open the report with the returned JSON.
"""
import streamlit as st

st.set_page_config(
    page_title="QuantumTrace — Cryptographic Debt & Quantum Posture",
    page_icon="■",
    layout="wide",
    initial_sidebar_state="collapsed",
)

report = st.Page("pages/dashboard.py", title="Report", default=True)          # opens first, with the sample data/
welcome = st.Page("pages/welcome.py", title="New audit", url_path="new-audit")  # reached from "New audit"

st.navigation([report, welcome], position="hidden").run()
