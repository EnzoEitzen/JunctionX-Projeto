import json

import pandas as pd
import streamlit as st

# Configuração da página Web
st.set_page_config(
    page_title="QuantumTrace Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ QuantumTrace — Cryptographic Risk Dashboard")
st.markdown(
    "Visibilidade automatizada da dívida criptográfica e prontidão PQC."
)

# 1. Carregar os dados do results.json
try:
    with open("results.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
except FileNotFoundError:
    st.error(
        "Ficheiro 'results.json' não encontrado. Garanta que executou os scanners"
        " ou criou o ficheiro mock."
    )
    st.stop()

# 2. Cálculo do Quantum Risk Score (0 a 100)
total_assets = len(df)
critical_count = len(df[df["risk_tier"] == "Critical"])
medium_count = len(df[df["risk_tier"] == "Medium"])
safe_count = len(df[df["risk_tier"].isin(["Safe", "Quantum-resilient"])])

risk_score = (
    int(((critical_count * 1.0 + medium_count * 0.4) / max(total_assets, 1)) * 100)
    if total_assets > 0
    else 0
)

# 3. Painel de Métricas Principais no Topo
st.subheader("Enterprise Quantum Risk Score")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Quantum Risk Score", f"{risk_score} / 100")
col2.metric("Risco Crítico (Shor)", critical_count)
col3.metric("Risco Médio (Grover)", medium_count)
col4.metric("Seguro / PQC", safe_count)

st.divider()

# 4. Barra Lateral de Filtros Interativos
st.sidebar.header("Filtros de Pesquisa")
selected_risk = st.sidebar.multiselect(
    "Nível de Risco:",
    options=df["risk_tier"].unique(),
    default=df["risk_tier"].unique(),
)

# Aplicar filtros
filtered_df = df[df["risk_tier"].isin(selected_risk)]

# 5. Gráficos Visuais de Distribuição
st.subheader("Análise Visual de Risco")
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("**Distribuição por Nível de Risco**")
    if not filtered_df.empty:
        st.bar_chart(filtered_df["risk_tier"].value_counts())

with chart_col2:
    st.markdown("**Algoritmos Detetados**")
    if not filtered_df.empty:
        st.bar_chart(filtered_df["algorithm"].value_counts())

st.divider()

# 6. Tabela Detalhada com Recomendações NIST
st.subheader("Inventário Criptográfico e Recomendações de Migração")
st.dataframe(
    filtered_df[
        [
            "asset",
            "location",
            "algorithm",
            "key_length",
            "library",
            "risk_tier",
            "replacement",
        ]
    ],
    use_container_width=True,
)

# 7. Botão para descarregar relatório
st.sidebar.divider()
st.sidebar.download_button(
    label="📥 Descarregar resultados (JSON)",
    data=df.to_json(orient="records", indent=2),
    file_name="quantum_risk_report.json",
    mime="application/json",
)