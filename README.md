# QuantumTrace

> Uncovering cryptographic debt in the quantum dawn. A lightweight, non-intrusive tool that detects, classifies and visualizes quantum-vulnerable cryptography across **network traffic**, **application code** and **cloud configurations**, and exports a **Cryptography Bill of Materials (CBOM)**.

Built in 24 hours for the **QuantumTrace** challenge at **JunctionX Lisbon 2026**.

<!-- TODO: replace/confirm the project name; add a banner, screenshot or demo GIF here -->

---

## The problem

Quantum computers running Shor's algorithm will break the public-key cryptography the internet relies on: **RSA, DSA, and elliptic-curve schemes (ECDSA, ECDH)**, plus Diffie-Hellman. Grover's algorithm also weakens some symmetric ciphers and hashes. Adversaries are already running **"Harvest Now, Decrypt Later"** attacks, archiving encrypted traffic today to decrypt it once quantum systems mature.

NIST has finalized post-quantum standards (**FIPS 203, 204, 205**), but most organizations don't know where legacy cryptography is used across their environments. You can't migrate what you can't see.

## What QuantumTrace does

QuantumTrace audits several kinds of input, identifies the cryptographic primitives in use, and classifies each one by quantum risk.

### Input sources

| Source | File(s) | What we extract |
|---|---|---|
| **Network capture** | `network.pcap` | TLS handshakes (ClientHello / ServerHello): TLS version, negotiated cipher suite, key exchange group, and whether the exchange is classical (x25519, RSA key exchange) or hybrid post-quantum (X25519MLKEM768) |
| **AWS KMS keys** | `kms_key_inventory.json` | Key spec (RSA, ECC or symmetric), key usage, signing/encryption algorithms, key origin and state |
| **AWS ACM certificates** | `acm_certificates.json` | Certificate key algorithm and signature algorithm, certificate type and validity |
| **AWS load balancers** | `load_balancer_listeners.json` | Listener protocol, port and TLS security policy, linked to the certificate each listener uses |
| **Code repositories** (Python, Java, Go) | `data/code/` | Declared algorithms, key lengths and cryptographic libraries |
| **Live endpoints** (optional) | `hosts.txt` | TLS profile of public sandbox targets, probed in real time |

<!-- TODO: remove any row you don't actually support by demo time -->

### Quantum risk classification

| Tier | Meaning | Examples |
|---|---|---|
| **Critical** | Asymmetric schemes broken by Shor's algorithm | RSA, DSA, ECDSA, ECDH (including x25519 and RSA key exchange), Diffie-Hellman |
| **Medium** | Symmetric ciphers/hashes weakened by Grover's algorithm | AES-128, 3DES, SHA-1 |
| **Safe / Quantum-resilient** | Large-key symmetric primitives and recognized PQC standards | AES-256, ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |

Each finding is mapped to a recommended replacement and the relevant NIST standard.

### Outputs

- **Quantum Risk Score** for the whole environment
- **Streamlit dashboard** with filterable findings and charts
- **CBOM export** in JSON, based on the CycloneDX 1.6 cryptographic asset model

## Sample data

The organizers provided synthetic data. This is what the scanners work on.

### `network.pcap`

About 2,000 packets containing roughly **78 TLS sessions** in three clearly different groups:

| Group | Hosts | Ports | What the handshake shows | Expected risk |
|---|---|---|---|---|
| **Legacy TLS 1.2** | `web*.lab`, `dc*.lab` | 443, 636 | RSA key exchange with `AES-CBC-SHA` cipher suites, no forward secrecy | Critical (RSA), plus Medium (AES-128, SHA-1) |
| **Modern TLS 1.3, classical** | `app*.lab`, `mail*.lab` | 443, 993 | `x25519` key exchange, `AES-128-GCM` | Critical (x25519), plus Medium (AES-128) |
| **Hybrid post-quantum TLS 1.3** | `vault*.lab` | 443 | `X25519MLKEM768` key exchange, `AES-256-GCM` | Safe (ML-KEM hybrid, AES-256) |

The capture also contains DNS, SSH, plain HTTP, SMTP (587) and PostgreSQL (5432) traffic, which can be ignored or counted as unencrypted or out-of-scope.

### `kms_key_inventory.json`

10 KMS keys with fields such as `KeySpec`, `KeyUsage`, `SigningAlgorithms`, `EncryptionAlgorithms`, `Origin` and `KeyState`:

- **RSA** keys (2048, 3072, 4096 bits): signing and decryption keys. The 3072-bit key is CloudHSM-backed.
- **ECC** keys (NIST P-256 and P-384): device attestation and an internal CA root.
- **Symmetric** keys (`SYMMETRIC_DEFAULT`): S3, EBS and session encryption. One is in `PendingDeletion` state.

### `acm_certificates.json`

5 ACM certificates, each with `KeyAlgorithm` and `SignatureAlgorithm`:

- Three **RSA 2048** certificates, two of them with SHA-256 signatures
- ECDSA P-256 and P-384 certificates
- One imported **legacy** RSA certificate with a **SHA-1 signature**, which has already passed its end date

### `load_balancer_listeners.json`

6 load balancers with listeners that give a protocol, port and **TLS policy name** (for example `ELBSecurityPolicy-2016-08` or `ELBSecurityPolicy-TLS13-1-2-2021-06`). Each HTTPS/TLS listener points to an ACM certificate by ARN, and one listener forwards plain HTTP with no TLS at all.

The load balancer file only contains **policy names**, not cipher lists. The config scanner uses a small lookup table (policy name to allowed TLS versions) and joins each listener to its certificate through the ARN.

## How it works

```
  network.pcap ─────────►  Network analyzer (PyShark) ──┐
  data/code/ ───────────►  Code scanner                ─┼──►  Normalized findings  ──►  Risk classifier
  KMS / ACM / LB JSON ──►  Config scanner              ─┘                                   │
                                                                                            ▼
                                                                     Streamlit dashboard  |  CBOM (JSON)  |  Risk score
```

Every scanner produces the same finding format: asset, location, algorithm, key length, library, risk tier, and recommended replacement.

## Tech stack

<!-- TODO: edit to match what you actually use -->

| Purpose | Library / tool |
|---|---|
| Packet capture parsing | [`pyshark`](https://github.com/KimiNewt/pyshark) (needs TShark/Wireshark installed) |
| Certificate parsing | [`cryptography`](https://cryptography.io) |
| Code and config scanning | `pathlib`, `re`, `json` (standard library) |
| Data handling | [`pandas`](https://pandas.pydata.org) |
| Dashboard | [`streamlit`](https://streamlit.io) |
| Live endpoint probing (optional) | [`sslyze`](https://github.com/nabla-c0d3/sslyze) |
| Packaging | Docker (the image includes TShark) |
| CBOM format | CycloneDX 1.6 (crypto asset module), written as JSON |

## Getting started

### Prerequisites

- Python 3.11+
- [Wireshark/TShark](https://www.wireshark.org) installed and on your PATH (PyShark calls it). Check with `tshark --version`.

### Install

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>

python -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Or install the libraries directly:

```bash
pip install pyshark cryptography pandas streamlit
```

### Add the data

```
data/
├── pcaps/network.pcap
├── cloud/
│   ├── kms_key_inventory.json
│   ├── acm_certificates.json
│   └── load_balancer_listeners.json
└── code/              # sample Python, Java and Go repositories
```

### Run the scanners

<!-- TODO: replace with your real file names and commands -->

```bash
# 1. Analyze the packet capture
python network_analyzer.py data/pcaps/network.pcap

# 2. Scan the AWS configuration dumps (KMS, ACM, load balancers)
python config_scanner.py data/cloud/

# 3. Scan sample code repositories
python code_scanner.py data/code/

# 4. (Optional) Probe live sandbox endpoints
python live_probe.py hosts.txt
```

Each command adds its findings to `output/results.json`.

### Launch the dashboard

```bash
streamlit run dashboard.py
```

The dashboard only reads `output/results.json`. PyShark is not run inside Streamlit.

### Export the CBOM

```bash
python export_cbom.py output/results.json > output/cbom.json
```

### Docker

<!-- TODO: only keep this section if you actually add a Dockerfile -->

```bash
docker build -t quantumtrace .
docker run -p 8501:8501 quantumtrace
```

Then open http://localhost:8501.

## Step-by-step guide

A walkthrough from a fresh machine to a finished audit report.

<!-- TODO: update file names, folders and commands to match your repo -->

1. **Get the code**
   ```bash
   git clone https://github.com/<your-org>/<your-repo>.git
   cd <your-repo>
   ```

2. **Create a virtual environment and install dependencies**
   ```bash
   python -m venv .venv
   source .venv/bin/activate      # on Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
   Also install Wireshark/TShark and make sure `tshark` is on your PATH.

3. **Add the input data**
   - `data/pcaps/network.pcap`
   - `data/cloud/kms_key_inventory.json`, `acm_certificates.json`, `load_balancer_listeners.json`
   - `data/code/`: the sample Python, Java and Go repositories

4. **Analyze the network capture**
   ```bash
   python network_analyzer.py data/pcaps/network.pcap
   ```
   This extracts the TLS version, cipher suite and key exchange group for each session and writes the findings to `output/results.json`.

5. **Scan the cloud configuration and the code**
   ```bash
   python config_scanner.py data/cloud/
   python code_scanner.py data/code/
   ```
   Each command adds its findings to the same `results.json`.

6. **(Optional) Probe live sandbox endpoints**
   ```bash
   python live_probe.py hosts.txt
   ```

7. **Classify the risk**
   The classifier assigns every finding to Critical, Medium or Safe, maps it to the relevant NIST standard, and computes the overall Quantum Risk Score. If this isn't already part of the scanners' output, run:
   ```bash
   python classifier.py output/results.json
   ```

8. **Explore the results**
   ```bash
   streamlit run dashboard.py
   ```
   Filter by source or risk tier, and check the Quantum Risk Score at the top.

9. **Export the CBOM**
   ```bash
   python export_cbom.py output/results.json > output/cbom.json
   ```
   The result is a structured JSON audit report based on the CycloneDX 1.6 cryptographic asset model.

10. **Act on the findings**
    Use the recommended replacements in the report (for example ML-KEM, ML-DSA or SLH-DSA) to plan your migration, starting with the Critical findings that protect long-lived data.

## Demo

We run QuantumTrace on the organizer-provided data and show how findings from the network capture, the AWS configuration dumps and the code repositories land in a single risk-ranked view. The legacy TLS 1.2 hosts, the classical TLS 1.3 hosts and the hybrid post-quantum `vault` hosts make a clear before-and-after story.

<!-- TODO: add screenshots or a link to the demo video -->

## Limitations

This was built in 24 hours, so:

- Detection is rule-based and covers a limited set of algorithms and libraries, so some false positives or misses are possible.
- The sample TLS 1.2 sessions don't appear to include certificate messages, so their key type is inferred from the cipher suite (RSA key exchange) rather than read from a certificate.
- Load balancer TLS policies are mapped from policy name using a hand-written lookup table, not from live cipher lists.
- KMS `SYMMETRIC_DEFAULT` keys are treated as AES-256, which is the AWS default, because the file doesn't state the key size.
- Code scanning uses pattern matching rather than full static analysis.
- Cloud scanning reads provided configuration dumps, not live cloud accounts.
- SSH, SMTP and database traffic in the capture is not analyzed.
- Binary artifact analysis is not supported.
- The CBOM follows the CycloneDX 1.6 cryptographic asset model in a simplified form and may not pass full schema validation.

## Roadmap

- [ ] Full CycloneDX 1.6 schema validation
- [ ] Deeper static analysis (e.g. Semgrep) for code scanning
- [ ] SSH, SMTP/STARTTLS and database TLS analysis
- [ ] Binary artifact scanning
- [ ] Live AWS, Azure and GCP integration
- [ ] CI integration to flag new quantum-vulnerable code
- [ ] Automated remediation suggestions

## Team

<!-- TODO: fill in names and GitHub handles -->

| Name | Role | Responsibilities | Main files | GitHub |
|---|---|---|---|---|
| Ihor | **Network analyst** | Parse `network.pcap` with PyShark and extract TLS version, cipher suite and key exchange group for every session; tell classical from hybrid post-quantum exchanges | `network_analyzer.py` | |
| Bicho, Enzo | **Code & config scanner** | Scan the Python, Java and Go repos for crypto algorithms, key lengths and libraries; parse the KMS, ACM and load balancer JSON dumps and link listeners to certificates | `code_scanner.py`, `config_scanner.py` | |
| Todos | **Risk engine & CBOM** | Own the shared finding format, the Critical/Medium/Safe classification table, the Quantum Risk Score, the FIPS 203/204/205 mapping, and the CycloneDX-style CBOM export | `finding.py`, `classifier.py`, `export_cbom.py` | |
| Miguel, Daniil | **Dashboard & UX** | Build the Streamlit dashboard (risk score, charts, filters, findings table) | `dashboard.py` | |
| Todos | **Integration, demo & pitch** | Repo and Git setup, `requirements.txt` and Dockerfile (with TShark), demo script, optional live endpoint probing, README, final pitch and demo video | `live_probe.py`, `Dockerfile`, `demo/` | |

**Working agreements**

- In the first two hours, agree on the shared finding format (asset, location, algorithm, key length, library, risk tier, replacement) and write it down in `finding.py`. Everyone's output depends on it.
- Each person works mainly in their own files to avoid merge conflicts, and commits small and often.
- Use short branches and merge into `main` at least every few hours so integration problems show up early.
- Stop adding features in the last two hours and use that time to test the demo end to end and rehearse the pitch.

## Acknowledgements

- JunctionX Lisbon organizers and the QuantumTrace challenge partners
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)

## License

Released under the [MIT License](LICENSE).
