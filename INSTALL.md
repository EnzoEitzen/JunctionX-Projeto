# Adding the web app to JunctionX-Projeto

1. Copy everything in this folder into the ROOT of the project (next to classifier.py, code_scanner.py ...).
   Every file here is NEW - nothing in your branch is replaced or edited.
2. Install Wireshark (provides tshark, needed by network_analyzer.py): https://www.wireshark.org
3. Your existing requirements.txt already has everything needed (streamlit, pandas, altair, pyshark, cyclonedx...).
   Only when the MongoDB part is ready: add `pymongo` to requirements.txt (integration.py imports it only if MONGODB_URI is set).
4. streamlit run app.py

Pages:  /         upload data/ folder (or ZIP) -> runs the pipeline -> opens the report
        /report   report for the last run (or output/results.json if no run yet)

Each upload runs in uploads/<timestamp>/ : 3 scanners -> classifier.py -> results.json. Nothing in output/ is touched.

## MongoDB (colleague)
integration.save_to_mongo() is called after every successful run. It does nothing until MONGODB_URI exists
(env var, or .streamlit/secrets.toml - see secrets.toml.example). Replace its body with the real schema.

## Online
Streamlit Cloud: main file app.py, packages.txt installs tshark, add MONGODB_URI in Secrets (and `pymongo` in requirements.txt).
Docker hosts: Dockerfile included (python 3.12 + tshark).
