# QuantumTrace

> Uncovering cryptographic debt in the quantum dawn.

Built for the **QuantumTrace challenge at JunctionX Lisbon 2026**, QuantumTrace identifies quantum-vulnerable cryptography across captured network traffic, application source code, and exported cloud configurations. It combines the findings in a Streamlit report and recommends quantum-resilient alternatives.

## What the final project includes

- **Network scan:** offline TLS handshake analysis with PyShark/TShark, including classical key exchanges and recognized hybrid post-quantum groups.
- **Code scan:** rule-based detection of cryptographic algorithms, key lengths, and library usage in Python, Java, and Go source files.
- **Config scan:** AWS KMS key inventories, ACM certificates, and load balancer listener JSON exports. Listeners are linked to certificates where possible.
- **Risk classification:** Critical, Medium, Safe, and explicit reporting of unrecognized algorithms, with replacement recommendations referencing NIST FIPS 203/204/205.
- **Interactive report:** overall risk score, separate Code/Network/Config risk scores, risk distribution, searchable/filterable findings, and report downloads.
- **New audit:** upload supported files through the application and run the relevant scanners. The first report uses the bundled sample data.
- **CBOM export:** a CycloneDX 1.6 exporter with an optional schema-validation flag.
- **Optional MongoDB synchronization:** upsert classified findings when the correct database environment variables are configured. The dashboard itself uses JSON results, not MongoDB queries.

There is no live endpoint probing or live cloud-account integration in this version.

## Run with Docker

### Requirements

Install Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin (Linux), and start Docker. On Docker Desktop, use Linux containers. Python and TShark are installed inside the image; they do not need to be installed on the host.

The following instructions use the `test` branch, which contains the reviewed final application and Docker setup.

```bash
git clone --branch test --single-branch https://github.com/EnzoEitzen/JunctionX-Projeto.git
cd JunctionX-Projeto
```

### Check the current Docker configuration

Before building, check these existing configuration inconsistencies:

1. In `entrypoint.sh`, change the classifier output from `output/result.json` to **`output/results.json`**:

   ```sh
   python classifier.py output output/results.json ${CLASSIFIER_FLAGS:-}
   ```

   The dashboard and upload pipeline use the plural filename. Remove or move any old `output/result.json` before rerunning, so it is not merged as another scanner input.

2. MongoDB is optional. Compose currently sets `MONGO_URI`, but the application reads **`MONGODB_URI`**. To enable synchronization to the included MongoDB service, replace that environment entry in `docker-compose.yml` with:

   ```yaml
   MONGODB_URI: mongodb://mongo:27017
   ```

   Without `MONGODB_URI`, synchronization is skipped and JSON-based reports still work. `MONGODB_DB` and `MONGODB_COLLECTION` optionally override the defaults `quantumtrace` and `findings`.

3. The current Compose file mounts `/var/run/docker.sock` into the app. The implemented scans do not need it. Remove that volume entry unless you intentionally require host Docker access: it grants extensive control over the host.

These are configuration checks, not changes performed by this README update.

### Start

```bash
docker compose up --build
```

The first build downloads the images and installs dependencies. The app then runs the scans and classifier before opening Streamlit. Wait for startup to finish, then open **http://localhost:8501**.

To run in the background:

```bash
docker compose up --build -d
docker compose logs -f app
```

### Startup pipeline

With the filename correction above, `entrypoint.sh` runs:

```sh
python network_analyzer.py data/network-capture output/network_analyzer_output.json
python config_scanner.py data/cloud-posture output/config_scanner_output.json
python code_scanner.py data/sample-repos output/code_scanner_output.json
python classifier.py output output/results.json ${CLASSIFIER_FLAGS:-}
streamlit run app.py --server.address=0.0.0.0 --server.port=8501
```

The pipeline stops on an error, so the dashboard will not start until every startup step succeeds. `CLASSIFIER_FLAGS` is configured in the Compose app environment; leave it empty normally. Supported examples are `--json` and `--no-mongo` (`--strict` is not a supported flag).

### Inputs and persistence

```text
data/
  network-capture/   # Packet captures
  cloud-posture/     # KMS, ACM, and load balancer JSON exports
  sample-repos/      # Python, Java, and Go source files
output/              # Startup scanner outputs and consolidated results.json
```

Compose mounts `data/` read-only, persists startup output in the host's `output/` directory, and stores MongoDB data in the `mongo-data` named volume. New audits run separately in temporary directories and return their results to the report; their temporary files are cleaned up rather than retained in the host output folder. Download a report you want to keep.

### Stop and restart

```bash
docker compose down
docker compose up -d
```

Stopping does not delete the host output or MongoDB volume. `docker compose down -v` also deletes the MongoDB volume: use it only when you intend to erase that database data. Recreate the app container to rerun the startup pipeline after changing inputs:

```bash
docker compose up -d --force-recreate app
```

### Troubleshooting and sharing

- **Dashboard unavailable:** inspect `docker compose ps` and `docker compose logs app`; scans must finish first.
- **Port 8501 already occupied:** change the app mapping to `"8502:8501"`, recreate it, and open http://localhost:8502.
- **Dependency installation fails:** use the exact error from the build log. If pip reports an encoding issue, save `requirements.txt` as UTF-8; if a pinned version is unavailable, review that pin before rebuilding.
- **MongoDB startup error:** the existing `depends_on` starts MongoDB first but does not wait for database readiness. Check `docker compose logs mongo` and restart the app once MongoDB is ready, or disable sync with `--no-mongo`.
- **Friends on the same network:** use `http://<your-computer-LAN-IP>:8501` and allow inbound access on the host firewall's trusted/private network. Streamlit's container Network/External URLs are not the host address.
- **Friends over the internet:** use an access-controlled tunnel or deployment. Do not expose sensitive audit results or MongoDB directly to the public internet. A tunnel to a local instance stops working when the computer or Docker stops.

## How risk is calculated

| Tier | Weight | Typical examples |
|---|---:|---|
| Critical | 100 | RSA, DSA, ECDSA, ECDH, classical Diffie-Hellman |
| Medium | 40 | AES-128, SHA-1, legacy symmetric primitives |
| Safe | 0 | AES-256, recognized ML-KEM/hybrid groups and supported PQC primitives |

The classifier averages these weights over unique `(source, asset, algorithm, key_length)` items, excluding unclassified items from that average. It prints both overall and per-source summaries.

The dashboard currently calculates its scores over displayed findings instead of deduplicated classifier items:

```text
Dashboard score = floor((100 × Critical findings + 40 × Medium findings) / total findings)
```

The same formula is applied separately to Code, Network, and Config (the `cloud` source is displayed as Config). A scan without findings is shown as N/A. Because the denominators differ, dashboard and classifier scores can differ. These scores are project heuristics, not an official NIST certification or a probability of compromise.

## Run without Docker

Use Python 3.12, install TShark and put it on PATH, then install the repository dependencies in a virtual environment:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the four Python commands listed in the startup pipeline, then:

```bash
streamlit run app.py
```

Use `app.py`, not `pages/dashboard.py`, as the multipage application entry point.

## Export a CBOM

Export and optionally validate the consolidated results:

```bash
python export_cbom.py output/results.json -o output/cbom.json --validate
```

Or from the running Docker app:

```bash
docker compose exec app python export_cbom.py output/results.json -o output/cbom.json --validate
```

The mounted output folder makes `output/cbom.json` available on the host. Validation failures are reported explicitly; schema validity should be checked, not assumed. Keep generated CBOM files separate from scanner inputs when rerunning the classifier.

## Implementation and limitations

The implementation uses Python, PyShark/TShark, Streamlit, pandas, Altair, the CycloneDX Python library, and optional PyMongo. Docker Compose packages the app and MongoDB.

- Network analysis depends on captured TLS handshake fields and TShark's protocol recognition; it does not decrypt application traffic or promise coverage of every protocol.
- Code scanning is rule-based, not full semantic/static analysis; dynamic algorithm selection can be missed and false positives are possible.
- Cloud analysis reads JSON exports, not live AWS accounts. Load balancer policies use a local lookup rather than live cipher enumeration; KMS symmetric defaults require assumptions.
- Binary artifact scanning and automated cryptographic remediation are not implemented.
- Recommendations and sample-data results are an inventory/migration starting point, not a security certification.

The bundled organizer data demonstrates legacy TLS 1.2, classical TLS 1.3, hybrid post-quantum TLS, AWS configuration inventories, and sample source repositories. See [READMEfindings.md](READMEfindings.md) for the shared finding format.

## Team

| Contributors | Focus |
|---|---|
| Ihor | Network analysis |
| Bicho, Enzo | Code and config scanning |
| Miguel, Daniil | Dashboard and UX |
| Whole team | Risk engine, CBOM, integration, and demo |

## Acknowledgements

- JunctionX Lisbon organizers and the QuantumTrace challenge partners
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)

## License

Released under the [MIT License](LICENSE).
