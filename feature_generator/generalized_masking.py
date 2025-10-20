from scapy.all import rdpcap, wrpcap, Ether
from scapy.all import Dot1Q, Raw
import pandas as pd
import numpy as np
import os

# === CONFIG ===
pcap_path_1 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/Automotive_Ethernet_with_Attack_original_10_17_19_50_training.pcap"
pcap_path_2 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/Automotive_Ethernet_with_Attack_original_10_17_20_04_test.pcap"
csv_path_1 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/y_train.csv"
csv_path_2 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/y_test.csv"

output_dir = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW_masked"
os.makedirs(output_dir, exist_ok=True)
# ============================

filtered_paths = []  # Store the paths for later use

# EtherTypes
AVTP_ETHERTYPE = 0x8100
PTP_ETHERTYPE = 0x88F7
IPV4_ETHERTYPE = 0x0800

for (pcap_path, csv_path) in [(pcap_path_1, csv_path_1), (pcap_path_2, csv_path_2)]:
    print(f"\n=== Processing dataset: {os.path.basename(pcap_path)} ===")

    # Load packets
    raw_packets = rdpcap(pcap_path)
    print(f">> Loaded {len(raw_packets)} packets")

    # Load CSV
    labels = pd.read_csv(csv_path, header=None, names=["index", "Class", "Description"])
    labels = labels.drop(columns=["index"])
    print(f">> Loaded {len(labels)} labels")

    filtered_packets = []
    filtered_labels = []

    for pkt, label_row in zip(raw_packets, labels.itertuples(index=False)):
        if not pkt.haslayer(Ether):
            continue

        eth = pkt[Ether]
        
        pkt = pkt.copy()
        eth.src = "00:00:00:00:00:00"
        eth.dst = "00:00:00:00:00:00"

        # Mask source/destination MACs for PTP or AVTP packets
        if eth.type == PTP_ETHERTYPE:
            # Clone packet (avoid modifying original reference)
            filtered_packets.append(pkt)
            filtered_labels.append([label_row.Class, label_row.Description])

        elif eth.type == AVTP_ETHERTYPE or pkt.haslayer(Dot1Q):
            # Mask VLAN priority if Dot1Q exists
            if pkt.haslayer(Dot1Q):
                pkt[Dot1Q].prio = 0  # VLAN priority = 0 (mask it)

            filtered_packets.append(pkt)
            filtered_labels.append([label_row.Class, label_row.Description])

        else:
            # Keep others unchanged
            filtered_packets.append(pkt)
            filtered_labels.append([label_row.Class, label_row.Description])

    print(f">> Remaining: {len(filtered_packets)} packets")

    # === Save filtered PCAP ===
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    filtered_pcap_path = os.path.join(output_dir, f"{base_name}_masked.pcap")
    wrpcap(filtered_pcap_path, filtered_packets)
    print(f"✅ Saved filtered PCAP: {filtered_pcap_path}")

    # === Save filtered CSV ===
    filtered_csv_path = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(csv_path))[0]}_masked.csv")
    filtered_df = pd.DataFrame(filtered_labels, columns=["Class", "Description"])
    filtered_df.to_csv(filtered_csv_path, index=False)
    print(f"✅ Saved filtered CSV: {filtered_csv_path}")

    filtered_paths.append((filtered_pcap_path, filtered_csv_path))

print("\n=== All datasets processed successfully ===")
for pcap, csv in filtered_paths:
    print(f" - PCAP: {pcap}")
    print(f" - CSV : {csv}")
