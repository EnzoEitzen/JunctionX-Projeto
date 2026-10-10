import asyncio
import pyshark

from findings import Finding, save_findings

pcap_file = "data/network-capture/network.pcap"

TLS_VERSIONS = {0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

CIPHER_SUITES = {
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "AES-128-CBC", 128, "SHA-1"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "AES-256-CBC", 256, "SHA-1"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "AES-128-GCM", 128, "SHA-256"),
    0x1301: ("TLS_AES_128_GCM_SHA256", "AES-128-GCM", 128, "SHA-256"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "AES-256-GCM", 256, "SHA-384"),
}

KEY_EXCHANGE_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001D: "x25519",
    0x11EC: "X25519MLKEM768",
}

SIGNATURE_SCHEMES = {
    0x0201: "RSA-PKCS1 SHA-1",
    0x0401: "RSA-PKCS1 SHA-256",
    0x0501: "RSA-PKCS1 SHA-384",
    0x0601: "RSA-PKCS1 SHA-512",
    0x0403: "ECDSA P-256 SHA-256",
    0x0503: "ECDSA P-384 SHA-384",
    0x0603: "ECDSA P-521 SHA-512",
    0x0804: "RSA-PSS SHA-256",
    0x0805: "RSA-PSS SHA-384",
    0x0806: "RSA-PSS SHA-512",
    0x0807: "Ed25519",
    0x0808: "Ed448",
}

asyncio.set_event_loop(asyncio.new_event_loop())
captures = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type in {1 2}", keep_packets=False)

findings = []

def add_suite(asset, location, suite_code, role, version):
    suite_name, bulk, bits, hash_alg = CIPHER_SUITES.get(
        suite_code, ("desconhecida", "desconhecido", None, None)
    )
    findings.append(Finding("network", asset, location, bulk, bits, notes=f"{role}, {version}, cifra {suite_name}"))
    if hash_alg == "SHA-1":
        findings.append(Finding("network", asset, location, "SHA-1", notes=f"{role}, {version}, hash da cifra {suite_name}"))
    return suite_name

for packet in captures:
    tls = packet.tls
    source_ip = packet.ip.src if hasattr(packet, "ip") else "Desconhecido"
    description_ip = packet.ip.dst if hasattr(packet, "ip") else "Desconhecido"
    asset = f"{source_ip} -> {description_ip}"
    location = f"Packet {packet.number}"

    if tls.handshake_type == "1":
        # ClientHello: o que o cliente oferece
        role = "ClientHello (oferecido)"

        version_raw = getattr(tls, "handshake_extensions_supported_version", None)
        if version_raw and int(version_raw, 16) in TLS_VERSIONS:
            findings.append(Finding("network", asset, location, TLS_VERSIONS[int(version_raw, 16)],
                                    notes=f"{role}, versão oferecida"))

        suite_raw = getattr(tls, "handshake_ciphersuite", None)
        if suite_raw:
            add_suite(asset, location, int(suite_raw, 16), role, "oferecida")

        group_raw = getattr(tls, "handshake_extensions_key_share_group", None)
        if group_raw:
            group = KEY_EXCHANGE_GROUPS.get(int(group_raw, 16), group_raw)
            findings.append(Finding("network", asset, location, group,
                                    notes=f"{role}, grupo de troca de chaves oferecido"))

        sig_raw = getattr(tls, "handshake_sig_hash_alg", None)
        if sig_raw:
            scheme = SIGNATURE_SCHEMES.get(int(sig_raw, 16), sig_raw)
            findings.append(Finding("network", asset, location, scheme,
                                    notes=f"{role}, algoritmo de assinatura oferecido"))

    elif tls.handshake_type == "2":
        # ServerHello: o que foi negociado
        role = "ServerHello (negociado)"

        version = "TLS 1.2 ou anterior"
        version_raw = getattr(tls, "handshake_extensions_supported_version", None)
        if version_raw:
            version = TLS_VERSIONS.get(int(version_raw, 16), version)

        suite_name = ""
        suite_raw = getattr(tls, "handshake_ciphersuite", None)
        if suite_raw:
            suite_name = add_suite(asset, location, int(suite_raw, 16), role, version)

        group_raw = getattr(tls, "handshake_extensions_key_share_group", None)
        if group_raw:
            group = KEY_EXCHANGE_GROUPS.get(int(group_raw, 16), group_raw)
            findings.append(Finding("network", asset, location, group,
                                    notes=f"{role}, {version}, grupo de troca de chaves"))
        elif suite_name.startswith("TLS_RSA_"):
            findings.append(Finding("network", asset, location, "RSA",
                                    notes=f"{role}, {version}, troca RSA inferida da cifra"))

captures.close()