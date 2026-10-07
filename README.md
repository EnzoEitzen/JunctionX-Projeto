# QuantumScan

> Find quantum-vulnerable cryptography across **code**, **network endpoints** and **cloud environments**, and see it all in one risk-ranked dashboard.

Built in 24 hours for **JunctionX Lisbon**.

<!-- TODO: replace "QuantumScan" with your final name; add a banner or demo GIF here -->

---

## The problem

Quantum computers running Shor's algorithm will break today's public-key cryptography: **RSA, Diffie-Hellman, DSA and elliptic-curve schemes (ECDSA, ECDH, Ed25519)**. Attackers are already collecting encrypted data now to decrypt later ("harvest now, decrypt later").

Most organizations don't know where this cryptography lives. It is spread across source code, dependencies, TLS endpoints, certificates and cloud key stores. You can't migrate what you can't find.

## What it does

QuantumScan runs three scanners that all produce the same finding format, then shows the results together.

| Scanner | What it checks |
|---|---|
| **Code** | Semgrep rules that flag RSA, ECDSA/ECDH, DH and DSA usage and weak key sizes in Python, Java and JavaScript |
| **Network** | Live TLS scan of a list of hostnames: protocol version, cipher suite, key exchange, certificate signature algorithm |
| **Cloud** | AWS KMS key specs and ACM certificates (or Terraform file parsing when no credentials are available) |

Each finding includes:

- **Asset and location:** file and line, hostname, or cloud resource
- **Algorithm and key size:** e.g. `RSA-2048`, `ECDSA P-256`
- **Quantum risk:** vulnerable, weakened, or safe
- **Recommended replacement:** e.g. ML-KEM, ML-DSA, SLH-DSA (NIST FIPS 203/204/205), or hybrid key exchange such as X25519MLKEM768

Results are shown in a dashboard with filtering and a priority ranking, and can be exported as a simple CycloneDX-style CBOM JSON.

<!-- TODO: trim this list to what actually works in your demo -->

## Architecture

```
  Code scanner      Network scanner      Cloud scanner
  (Semgrep)         (ssl / sslyze)       (boto3 / Terraform)
       \                  |                   /
        \                 |                  /
         v                v                 v
          Normalized findings (JSON / SQLite)
                          |
                          v
              Streamlit dashboard + export
```

## Tech stack

<!-- TODO: edit to match what you actually use -->

- **Language:** Python
- **Code scanning:** Semgrep with custom rules
- **Network scanning:** Python `ssl` / `socket`, sslyze
- **Cloud scanning:** boto3 (AWS KMS, ACM), Terraform file parsing
- **Storage:** SQLite or JSON files
- **Dashboard:** Streamlit

## Getting started

### Prerequisites

- Python 3.11+
- (Optional) AWS credentials with read-only access for the cloud scanner

### Install

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
```

Fill in any values you need (such as AWS settings). Never commit your real `.env` file.

### Run the scanners

<!-- TODO: replace these placeholder commands with your real entry points -->

```bash
# Scan a codebase
python -m quantumscan.code ./path/to/repo

# Scan TLS endpoints listed in a file
python -m quantumscan.network hosts.txt

# Scan AWS (read-only), or Terraform files
python -m quantumscan.cloud --provider aws
python -m quantumscan.cloud --terraform ./infra
```

### Launch the dashboard

```bash
streamlit run dashboard/app.py
```

## Demo

The `demo/` folder contains a deliberately vulnerable sample app, a list of test TLS endpoints, and sample cloud/Terraform resources, so you can see findings from all three scanners appear in the dashboard.

<!-- TODO: add screenshots or a link to the demo video -->

## Limitations

This was built in 24 hours, so:

- Code rules cover a limited set of languages and common crypto APIs.
- Network scanning is active (endpoint-based), not full packet-capture analysis.
- Cloud scanning supports AWS only.
- The CBOM export is simplified and not fully spec-compliant.

## Roadmap

- [ ] Packet capture (pcap) analysis for passive TLS inspection
- [ ] Azure and GCP support
- [ ] SSH, IPsec and STARTTLS coverage
- [ ] Full CycloneDX CBOM compliance
- [ ] Automated fix suggestions and pull requests
- [ ] CI integration to block new quantum-vulnerable code

## Team

<!-- TODO: add teammates -->

| Name | Role | GitHub |
|---|---|---|
| | | |

## Acknowledgements

- JunctionX Lisbon organizers and partners
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CycloneDX CBOM specification](https://cyclonedx.org/capabilities/cbom/)

## License

Released under the [MIT License](LICENSE).
