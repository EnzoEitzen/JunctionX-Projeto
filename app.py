"""
QuantumTrace — entry point.

Run with:  streamlit run app.py

Page 1 (Welcome): upload a folder equivalent to the repository `data/` folder,
pass it to integration.run_analysis() and open the report.
Page 2 (Report):  the QuantumTrace dashboard for the returned JSON.
"""
import streamlit as st

st.set_page_config(
    page_title="QuantumTrace — Cryptographic Debt & Quantum Posture",
    page_icon="■",
    layout="wide",
    initial_sidebar_state="collapsed",
)

welcome = st.Page("pages/welcome.py", title="Welcome", default=True)
report = st.Page("pages/dashboard.py", title="Report", url_path="report")

st.navigation([welcome, report], position="hidden").run()
