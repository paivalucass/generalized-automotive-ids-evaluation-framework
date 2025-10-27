from scapy.all import rdpcap, wrpcap, Ether
from scapy.all import Dot1Q, Raw
import pandas as pd
import numpy as np
import os

# === CONFIG ===
pcap_path_1 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP/driving_01_injected.pcap"
pcap_path_2 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP/driving_02_injected.pcap"
pcap_path_3 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP/indoors_01_injected.pcap"
pcap_path_4 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP/indoors_02_injected.pcap"
pcap_path_5 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP/single-MPEG-frame.pcap"


output_dir = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/AVTP_masked"
os.makedirs(output_dir, exist_ok=True)
# ============================

filtered_paths = []  # Store the paths for later use

# EtherTypes
AVTP_ETHERTYPE = 0x8100
PTP_ETHERTYPE = 0x88F7
IPV4_ETHERTYPE = 0x0800

for pcap_path in [pcap_path_1,pcap_path_2,pcap_path_3,pcap_path_4,pcap_path_5]:
    print(f"\n=== Processing dataset: {os.path.basename(pcap_path)} ===")

    # Load packets
    raw_packets = rdpcap(pcap_path)
    print(f">> Loaded {len(raw_packets)} packets")

    filtered_packets = []

    for pkt in raw_packets:
        
        if not pkt.haslayer(Ether):
            continue

        pkt = pkt.copy()
        eth = pkt[Ether]      
        eth.src = "00:00:00:00:00:00"
        eth.dst = "00:00:00:00:00:00"


        if eth.type == AVTP_ETHERTYPE or pkt.haslayer(Dot1Q):
            # Mask VLAN priority if Dot1Q exists
            if pkt.haslayer(Dot1Q):
                pkt[Dot1Q].prio = 0  # VLAN priority = 0 (mask it)
            
        filtered_packets.append(pkt)

    print(f">> Remaining: {len(filtered_packets)} packets")

    # === Save masked PCAP ===
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    filtered_pcap_path = os.path.join(output_dir, f"{base_name}_masked.pcap")
    wrpcap(filtered_pcap_path, filtered_packets)
    print(f"✅ Saved filtered PCAP: {filtered_pcap_path}")

