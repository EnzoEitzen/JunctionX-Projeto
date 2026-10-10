import asyncio
import glob
import os
import sys

import pyshark

from findings import Finding, save_findings

TSHARK_PATH = os.environ.get("TSHARK_PATH") or None   # None -> pyshark finds tshark on PATH
DEFAULT_OUTPUT = "output/results.json"

TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

CIPHER_SUITES = {
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA",            "RSA",   "AES-CBC", 128, "SHA-1"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA",            "RSA",   "AES-CBC", 256, "SHA-1"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256",         "RSA",   "AES-GCM", 128, None),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384",         "RSA",   "AES-GCM", 256, None),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      "ECDHE", "AES-CBC", 128, "SHA-1"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      "ECDHE", "AES-CBC", 256, "SHA-1"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-GCM", 128, None),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-GCM", 256, None),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   "ECDHE", "AES-GCM", 128, None),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   "ECDHE", "AES-GCM", 256, None),
    0x1301: ("TLS_AES_128_GCM_SHA256",                  None,    "AES-GCM", 128, None),
    0x1302: ("TLS_AES_256_GCM_SHA384",                  None,    "AES-GCM", 256, None),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256",            None,    "ChaCha20-Poly1305", 256, None),
}

KEY_EXCHANGE_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
HYBRID_PQC_GROUPS = {"SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024", "X25519Kyber768Draft00"}


def to_int(text):
    """tshark prints some fields as hex ('0x1301') and others as decimal ('4588').
    Using int(x, 16) on a decimal field silently gives a wrong number, so check the prefix."""
    text = str(text).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def values(layer, name):
    """All values of a repeated field. getattr(layer, name) alone returns only the FIRST one."""
    field = getattr(layer, name, None)
    if field is None:
        return []
    return [f.show for f in getattr(field, "all_fields", [field])]


def group_name(code):
    return KEY_EXCHANGE_GROUPS.get(code, f"unknown group 0x{code:04x}")


def analyse_pcap(pcap_file, findings):
    asyncio.set_event_loop(asyncio.new_event_loop())
    captures = pyshark.FileCapture(
        pcap_file,
        display_filter="tls.handshake.type == 1 or tls.handshake.type == 2",
        keep_packets=False,
        tshark_path=TSHARK_PATH,
    )
    sessions = {}
    try:
        for packet in captures:
            if not hasattr(packet, "tcp"):
                continue
            ip = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
            stream = packet.tcp.stream
            s = sessions.setdefault(stream, {"file": os.path.basename(pcap_file)})

            for tls in packet.get_multiple_layers("tls"):
                kinds = values(tls, "handshake_type")
                if "1" in kinds:      # ClientHello
                    s["port"] = packet.tcp.dstport
                    s["server_ip"] = ip.dst if ip else None
                    s["sni"] = (values(tls, "handshake_extensions_server_name") or [None])[0]
                    s["client_groups"] = [group_name(to_int(v)) for v in values(tls, "handshake_extensions_key_share_group")]
                if "2" in kinds:      # ServerHello
                    s["port"] = packet.tcp.srcport
                    s["server_ip"] = ip.src if ip else None
                    s["packet"] = packet.number
                    s["suite"] = to_int((values(tls, "handshake_ciphersuite") or ["0"])[0])
                    s["hello_version"] = to_int((values(tls, "handshake_version") or ["0x0303"])[0])
                    sv = values(tls, "handshake_extensions_supported_version")
                    s["selected_version"] = to_int(sv[0]) if sv else s["hello_version"]
                    sg = values(tls, "handshake_extensions_key_share_group")
                    s["server_group"] = group_name(to_int(sg[0])) if sg else None
    finally:
        try:
            captures.close()
        except Exception:
            pass 

    for s in sessions.values():
        if "suite" in s: 
            findings.extend(session_findings(s))


def session_findings(s):
    host = s.get("sni") or s.get("server_ip") or "unknown"
    asset = f"{host}:{s['port']}"
    version = TLS_VERSIONS.get(s["selected_version"], f"0x{s['selected_version']:04x}")
    packet_ref = f"{os.path.basename(s['file'])} packet {s['packet']}"
    where = f"{packet_ref}, {version} ServerHello"
    suite_code = s["suite"]
    out = []

    if suite_code not in CIPHER_SUITES:
        out.append(Finding("network", asset, where, "Unknown cipher suite",
                           notes=f"suite 0x{suite_code:04x} is not in CIPHER_SUITES; add it"))
        return out
    suite, kex, family, bits, mac = CIPHER_SUITES[suite_code]

    if s["server_group"]:                           
        kex_name, kex_loc = s["server_group"], f"{packet_ref}, {version} key_share"
        offered = [g for g in s["client_groups"] if g != s["server_group"]]
        pqc_offered = [g for g in offered if g in HYBRID_PQC_GROUPS]
        note = f"{version}, key exchange group chosen by server ({suite})"
        if pqc_offered:
            note += f"; client also offered {', '.join(pqc_offered)} but server did not select it"
        elif s["server_group"] in HYBRID_PQC_GROUPS:
            note += "; hybrid post-quantum key exchange"
        out.append(Finding("network", asset, kex_loc, kex_name, notes=note))
    elif kex == "RSA":
        out.append(Finding("network", asset, where, "RSA",
                           notes=f"{version}, RSA key exchange inferred from {suite}; no forward secrecy, "
                                 "so recorded traffic is decryptable once the server key is broken"))
    elif kex == "ECDHE":
        out.append(Finding("network", asset, where, "ECDHE",
                           notes=f"{version}, ECDHE inferred from {suite}; curve is in ServerKeyExchange (not parsed)"))

    
    out.append(Finding("network", asset, where, family, bits, notes=f"{version}, {suite}"))

    
    if mac == "SHA-1":
        out.append(Finding("network", asset, where, "SHA-1",
                           notes=f"HMAC-SHA1 record MAC in {suite}; HMAC is far less exposed than SHA-1 signatures "
                                 "or certificates, so consider a lower weight for this one"))
    return out


def find_captures(input_path):
    if os.path.isfile(input_path):
        return [input_path]
    files = glob.glob(os.path.join(input_path, "*.pcap")) + glob.glob(os.path.join(input_path, "*.pcapng"))
    return sorted(files)


def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: python network_analyzer.py <pcap file or folder> [output file]")
        sys.exit(1)
    input_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else DEFAULT_OUTPUT

    pcaps = find_captures(input_path)
    if not pcaps:
        print(f"No .pcap or .pcapng files found in {input_path}")
        sys.exit(1)

    findings = []
    for pcap in pcaps:
        print(f"Analysing {pcap}...")
        analyse_pcap(pcap, findings)

    save_findings(findings, path=output_file)
    print(f"{len(findings)} findings saved to {output_file}")


if __name__ == "__main__":
    main()