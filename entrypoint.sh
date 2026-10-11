#!/bin/sh
# QuantumTrace pipeline: run the four analyzers, then start the dashboard.
set -e

mkdir -p output

echo "==> 1/4 network_analyzer"
python network_analyzer.py data/network-capture output/network_analyzer_output.json

echo "==> 2/4 config_scanner"
python config_scanner.py data/cloud-posture output/config_scanner_output.json

echo "==> 3/4 code_scanner"
python code_scanner.py data/sample-repos output/code_scanner_output.json

echo "==> 4/4 classifier"
# CLASSIFIER_FLAGS is passed as an env var, e.g. -e CLASSIFIER_FLAGS="--strict"
python classifier.py output output/result.json ${CLASSIFIER_FLAGS:-}

echo "==> Starting dashboard"
exec streamlit run app.py --server.address=0.0.0.0 --server.port=8501
