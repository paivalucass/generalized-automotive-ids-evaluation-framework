from scapy.all import rdpcap, wrpcap, Ether
import pandas as pd
import numpy as np
import os

# === CONFIG ===
pcap_path_1 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/Automotive_Ethernet_with_Attack_original_10_17_19_50_training.pcap"
pcap_path_2 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/Automotive_Ethernet_with_Attack_original_10_17_20_04_test.pcap"
csv_path_1 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/y_train.csv"
csv_path_2 = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/y_test.csv"

output_dir = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW_filtered"
os.makedirs(output_dir, exist_ok=True)
# ============================

filtered_paths = []  # Store the paths for later use

for (pcap_path, csv_path) in [(pcap_path_2, csv_path_2)]:
    print(f"\n=== Processing dataset: {os.path.basename(pcap_path)} ===")

    # Load packets
    raw_packets = rdpcap(pcap_path)
    print(f">> Loaded {len(raw_packets)} packets")

    # Load CSV
    labels = pd.read_csv(csv_path, header=None, names=["index", "Class", "Description"])
    labels = labels.drop(columns=["index"])
    print(f">> Loaded {len(labels)} labels")

    # EtherTypes
    AVTP_ETHERTYPE = 0x8100
    PTP_ETHERTYPE = 0x88F7
    IPV4_ETHERTYPE = 0x0800

    # Separate packets and mark protocols
    filtered_packets = []
    filtered_labels = []
    dropped_count = 0

    for pkt, label_row in zip(raw_packets, labels.itertuples(index=False)):
        if not pkt.haslayer(Ether):
            continue

        eth = pkt[Ether]
        if eth.type == IPV4_ETHERTYPE:
            dropped_count += 1
            continue  # skip IPv4 (CAN/UDP)
        else:
            filtered_packets.append(pkt)
            filtered_labels.append(label_row)

    print(f">> Dropped {dropped_count} IPv4 packets")
    print(f">> Remaining: {len(filtered_packets)} packets")

    # === Save filtered PCAP ===
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    filtered_pcap_path = os.path.join(output_dir, f"{base_name}_filtered.pcap")
    wrpcap(filtered_pcap_path, filtered_packets)
    print(f"✅ Saved filtered PCAP: {filtered_pcap_path}")

    # === Save filtered CSV ===
    filtered_csv_path = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(csv_path))[0]}_filtered.csv")
    filtered_df = pd.DataFrame(filtered_labels, columns=["Class", "Description"])
    filtered_df.to_csv(filtered_csv_path, index=False)
    print(f"✅ Saved filtered CSV: {filtered_csv_path}")