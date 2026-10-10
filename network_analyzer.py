import asyncio
import json
import pyshark

pcap_file = "data/network-capture/network.pcap"

asyncio.set_event_loop(asyncio.new_event_loop())
captures = pyshark.FileCapture(pcap_file, display_filter="tls or ssh or http", keep_packets=False)

for packet in captures:
    source_ip = packet.ip.src if hasattr(packet, "ip") else "Desconhecido"
    description_ip = packet.ip.dst if hasattr(packet, "ip") else "Desconhecido"
    location = f"Pakect {packet.number} ({source_ip} -> {description_ip})"
    print(location)
