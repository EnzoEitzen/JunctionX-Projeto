# QuantumScan

> Check which websites and systems use cryptography that future quantum computers will break, and rank them by risk.

Built in 24 hours for **JunctionX Lisbon**.

<!-- TODO: replace "QuantumScan" with your final name; add a screenshot or demo GIF here -->

---

## The problem

Quantum computers running Shor's algorithm will break today's public-key cryptography: **RSA, Diffie-Hellman and elliptic-curve schemes (ECDSA, ECDH)**. Attackers are already collecting encrypted data now to decrypt it later ("harvest now, decrypt later").

Most organizations don't know where this cryptography is used, so they can't plan their migration to post-quantum cryptography.

## What it does

QuantumScan connects to a list of TLS endpoints, inspects their cryptography, and shows how exposed each one is to quantum attacks.

**Core: network scanner**
- Connects to each hostname (in parallel) and reads the TLS version, cipher suites and certificate
- Identifies the certificate's public key type and size (e.g. `RSA-2048`, `EC P-256`)
- Labels each endpoint as **vulnerable**, **weak** or **post-quantum ready**
- Suggests a replacement (e.g. ML-KEM, ML-DSA, or hybrid key exchange)

**Extras (basic versions)**
- **Code scan:** searches source files for quantum-vulnerable crypto usage such as `RSA`, `ECDSA` and `generate_private_key`
- **Cloud scan:** reads a sample cloud config (JSON or Terraform) listing key types and flags the vulnerable ones

Everything appears in a simple dashboard with a filterable risk table and chart.

<!-- TODO: remove any extra that doesn't work by demo time -->

## How it works

```
  hosts.txt  ──►  Network scanner ──┐
  source code ──► Code scanner    ──┼──►  results.json  ──►  pandas  ──►  Streamlit dashboard
  config file ──► Cloud scanner   ──┘
```

Each scanner writes findings in the same format: asset, algorithm, key size, risk level and recommended replacement.

## Tech stack

<!-- TODO: edit to match what you actually use -->

| Purpose | Library |
|---|---|
| TLS scanning | [`sslyze`](https://github.com/nabla-c0d3/sslyze) (cipher suites, certificates) |
| Certificate parsing | [`cryptography`](https://cryptography.io) (key type and size) |
| Scanning many hosts at once | `concurrent.futures` (standard library) |
| Code scanning | `pathlib` and `re` (standard library) |
| Terraform parsing (optional) | [`python-hcl2`](https://github.com/amplify-education/python-hcl2) |
| Data handling | [`pandas`](https://pandas.pydata.org) |
| Dashboard | [`streamlit`](https://streamlit.io) |
| Terminal output (fallback demo) | [`rich`](https://github.com/Textualize/rich) |
| Storage | JSON files |

## Getting started

### Prerequisites

- Python 3.11+

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
pip install sslyze cryptography pandas streamlit rich python-hcl2
```

### Run the scanners

<!-- TODO: replace with your real file names and commands -->

```bash
# 1. Scan the websites listed in hosts.txt
python network_scanner.py hosts.txt

# 2. (Optional) Scan a folder of source code
python code_scanner.py ./path/to/code

# 3. (Optional) Scan a sample cloud config
python cloud_scanner.py sample_config.json
```

Each command adds its findings to `results.json`.

### Launch the dashboard

```bash
streamlit run dashboard.py
```

Then open the local address Streamlit prints in your terminal.

### Terminal fallback

If you just want a quick view without the dashboard:

```bash
python show_results.py
```

This prints a colored risk table using `rich`.

## Demo

For the demo we scan a mix of well-known websites plus a few deliberately old or weak test endpoints, and show the live risk ranking in the dashboard.

<!-- TODO: add screenshots or a link to the demo video -->

## Limitations

This was built in 24 hours, so:

- The network scanner checks live endpoints only (no packet capture analysis).
- Risk labels are based mainly on the certificate's key type. Detecting post-quantum hybrid key exchange (e.g. X25519MLKEM768) depends on the tooling and OpenSSL version available, so it may be incomplete.
- The code scanner uses simple keyword matching, so it can produce false positives.
- The cloud scanner reads sample files rather than connecting to a live cloud account.
- Risk levels are based on a simple rule set, not a full cryptographic audit.

## Roadmap

- [ ] Reliable detection of post-quantum hybrid key exchange
- [ ] Use Semgrep for more accurate code scanning
- [ ] Connect to live AWS, Azure and GCP accounts
- [ ] Analyze packet captures (pcap) for passive TLS inspection
- [ ] Cover SSH, IPsec and email (STARTTLS)
- [ ] Export a standard CycloneDX CBOM
- [ ] Suggest automated code fixes

## Team

<!-- TODO: add teammates -->

| Name | Role | GitHub |
|---|---|---|
| | | |

## Acknowledgements

- JunctionX Lisbon organizers and partners
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)

## License

Released under the [MIT License](LICENSE).
