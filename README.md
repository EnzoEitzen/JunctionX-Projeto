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

| Source | What we extract |
|---|---|
| **Network captures** (`.pcap` / `.pcapng`) | TLS handshakes (Client/Server Hello): negotiated cipher suites, key exchange groups, signature schemes. Distinguishes classical (RSA, secp256r1) from hybrid/post-quantum (ML-KEM/Kyber) |
| **Code repositories** (Python, Java, Go) | Declared algorithms, key lengths and cryptographic libraries |
| **Cloud configs** (KMS and load balancer JSON dumps) | Key specs and TLS policies |
| **Live endpoints** (optional) | TLS profile of public sandbox targets, probed in real time |

<!-- TODO: remove any row you don't actually support by demo time -->

### Quantum risk classification

| Tier | Meaning | Examples |
|---|---|---|
| **Critical** | Asymmetric schemes broken by Shor's algorithm | RSA, DSA, ECDSA, ECDH, Diffie-Hellman |
| **Medium** | Symmetric ciphers/hashes weakened by Grover's algorithm | AES-128, 3DES, SHA-1 |
| **Safe / Quantum-resilient** | Large-key symmetric primitives and recognized PQC standards | AES-256, ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |

Each finding is mapped to a recommended replacement and the relevant NIST standard.

### Outputs

- **Quantum Risk Score** for the whole environment
- **Dashboard** (Streamlit) with filterable findings and charts, plus a terminal view (Rich)
- **CBOM export** in JSON, based on the CycloneDX 1.6 cryptographic asset model

## How it works

```
  .pcap files   ──►  Network analyzer  ──┐
  code repos    ──►  Code scanner      ──┼──►  Normalized findings  ──►  Risk classifier
  KMS / LB JSON ──►  Config scanner    ──┘                                   │
                                                                             ▼
                                                    Dashboard  |  CBOM (JSON)  |  Risk score
```

Every scanner produces the same finding format: asset, location, algorithm, key length, library, risk tier, and recommended replacement.

## Tech stack

<!-- TODO: edit to match what you actually use -->

| Purpose | Library |
|---|---|
| Packet capture parsing | [`scapy`](https://scapy.net) or [`pyshark`](https://github.com/KimiNewt/pyshark) (needs TShark/Wireshark installed) |
| Certificate parsing | [`cryptography`](https://cryptography.io) |
| Live endpoint probing (optional) | [`sslyze`](https://github.com/nabla-c0d3/sslyze) |
| Code and config scanning | `pathlib`, `re`, `json` (standard library) |
| Data handling | [`pandas`](https://pandas.pydata.org) |
| Dashboard | [`streamlit`](https://streamlit.io) |
| Terminal UI | [`rich`](https://github.com/Textualize/rich) |
| CBOM format | CycloneDX 1.6 (crypto asset module), written as JSON |

## Getting started

### Prerequisites

- Python 3.11+
- (If using PyShark) [Wireshark/TShark](https://www.wireshark.org) installed and on your PATH

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
pip install scapy cryptography pandas streamlit rich sslyze
```

### Run the scanners

<!-- TODO: replace with your real file names and commands -->

```bash
# 1. Analyze a packet capture
python network_analyzer.py data/pcaps/

# 2. Scan sample code repositories
python code_scanner.py data/code/

# 3. Scan mock KMS / load balancer configs
python config_scanner.py data/cloud/

# 4. (Optional) Probe live sandbox endpoints
python live_probe.py hosts.txt
```

Each command adds its findings to `results.json`.

### Launch the dashboard

```bash
streamlit run dashboard.py
```

### Export the CBOM

```bash
python export_cbom.py results.json > cbom.json
```

### Terminal view

```bash
python show_results.py
```

### Docker (optional)

<!-- TODO: only keep this section if you actually add a Dockerfile -->

```bash
docker build -t quantumtrace .
docker run -p 8501:8501 quantumtrace
```

## Demo

We run QuantumTrace on the organizer-provided synthetic data (legacy TLS 1.2 sessions, modern TLS 1.3 handshakes, hybrid PQC exchanges, sample Python/Java/Go repos, and mock cloud configs) and show how findings from every source land in a single risk-ranked view.

<!-- TODO: add screenshots or a link to the demo video -->

## Limitations

This was built in 24 hours, so:

- Detection is rule-based and covers a limited set of algorithms and libraries, so some false positives or misses are possible.
- Code scanning uses pattern matching rather than full static analysis.
- Cloud scanning reads provided configuration dumps, not live cloud accounts.
- Binary artifact analysis is not supported.
- The CBOM follows the CycloneDX 1.6 cryptographic asset model in a simplified form and may not pass full schema validation.

## Roadmap

- [ ] Full CycloneDX 1.6 schema validation
- [ ] Deeper static analysis (e.g. Semgrep) for code scanning
- [ ] Binary artifact scanning
- [ ] Live AWS, Azure and GCP integration
- [ ] More protocols (SSH, IPsec, STARTTLS)
- [ ] CI integration to flag new quantum-vulnerable code
- [ ] Automated remediation suggestions

## Team

<!-- TODO: fill in names and GitHub handles -->

| Name | Role | Responsibilities | Main files | GitHub |
|---|---|---|---|---|
| | **Network analyst** | Parse the `.pcap` / `.pcapng` files and extract TLS handshake details (cipher suites, key exchange groups, signature schemes); tell classical from hybrid/PQC exchanges | `network_analyzer.py` | |
| | **Code & config scanner** | Scan the Python, Java and Go repos for crypto algorithms, key lengths and libraries; parse the mock KMS and load balancer JSON dumps | `code_scanner.py`, `config_scanner.py` | |
| | **Risk engine & CBOM** | Own the shared finding format, the Critical/Medium/Safe classification table, the Quantum Risk Score, the FIPS 203/204/205 mapping, and the CycloneDX-style CBOM export | `classifier.py`, `export_cbom.py` | |
| | **Dashboard & UX** | Build the Streamlit dashboard (risk score, charts, filters) and the Rich terminal view | `dashboard.py`, `show_results.py` | |
| | **Integration, demo & pitch** | Repo and Git setup, `requirements.txt` / Dockerfile, test data and demo script, optional live endpoint probing, README, final pitch and demo video | `live_probe.py`, `Dockerfile`, `demo/` | |

**Working agreements**

- In the first two hours, agree on the shared finding format (asset, location, algorithm, key length, library, risk tier, replacement) and write it down in the repo. Everyone's output depends on it.
- Each person works mainly in their own files to avoid merge conflicts, and commits small and often.
- Use short branches and merge into `main` at least every few hours so integration problems show up early.
- Stop adding features in the last two hours and use that time to test the demo end to end and rehearse the pitch.

## Acknowledgements

- JunctionX Lisbon organizers and the QuantumTrace challenge partners
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)

## License

Released under the [MIT License](LICENSE).
