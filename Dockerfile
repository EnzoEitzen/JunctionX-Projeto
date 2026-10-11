# QuantumTrace — Streamlit app image
FROM python:3.12-slim

# tshark is required by pyshark (network_analyzer); curl for the healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x entrypoint.sh

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Runs the analysis pipeline, then starts Streamlit
CMD ["./entrypoint.sh"]
