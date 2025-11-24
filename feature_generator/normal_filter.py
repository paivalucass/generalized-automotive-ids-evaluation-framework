from scapy.all import rdpcap, wrpcap
import pandas as pd
import os

# === CONFIG ===
pcap_path_1 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/TOW_filtered/Automotive_Ethernet_with_Attack_original_10_17_19_50_training_filtered.pcap"
pcap_path_2 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/TOW_filtered/Automotive_Ethernet_with_Attack_original_10_17_20_04_test_filtered.pcap"
csv_path_1 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/TOW_filtered/y_train_filtered.csv"
csv_path_2 = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/TOW_filtered/y_test_filtered.csv"

output_dir = "/srv/nfs/shared/lacp/generalized-automotive-ids-evaluation-framework/dataset/TOW_normal"
os.makedirs(output_dir, exist_ok=True)
# ============================

for (pcap_path, csv_path) in [(pcap_path_1, csv_path_1)]:
    print(f"\n=== Processing dataset: {os.path.basename(pcap_path)} ===")

    # === Load packets ===
    raw_packets = rdpcap(pcap_path)
    print(f">> Loaded {len(raw_packets)} packets from PCAP")

    # === Load labels CSV ===
    labels = pd.read_csv(csv_path, header=None, names=["index", "Class", "Description"])
    if "index" in labels.columns:
        labels = labels.drop(columns=["index"])
    print(f">> Loaded {len(labels)} labels from CSV")

    # === Filter only 'Normal' packets ===
    filtered_packets = []
    filtered_labels = []
    dropped_count = 0

    for pkt, (_, row) in zip(raw_packets, labels.iterrows()):
        if row["Class"].strip().lower() == "normal":
            filtered_packets.append(pkt)
            filtered_labels.append(row.values.tolist())
        else:
            dropped_count += 1

    print(f">> Dropped {dropped_count} non-Normal packets")
    print(f">> Remaining Normal packets: {len(filtered_packets)}")

    # === Save filtered PCAP ===
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    filtered_pcap_path = os.path.join(output_dir, f"{base_name}_NormalOnly.pcap")
    wrpcap(filtered_pcap_path, filtered_packets)
    print(f"Saved filtered PCAP: {filtered_pcap_path}")

    # === Save filtered CSV ===
    filtered_csv_path = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(csv_path))[0]}_NormalOnly.csv")
    filtered_df = pd.DataFrame(filtered_labels, columns=["Class", "Description"])
    filtered_df.to_csv(filtered_csv_path, index=False)
    print(f"Saved filtered CSV: {filtered_csv_path}")