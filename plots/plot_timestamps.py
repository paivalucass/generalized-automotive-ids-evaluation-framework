from scapy.all import rdpcap, Ether, raw
import numpy as np
import matplotlib.pyplot as plt

# === CONFIG ===
pcap_path = "/home/lucas/generalized-ids-framework/generalized-automotive-ids-evaluation-framework/dataset/TOW/Automotive_Ethernet_with_Attack_original_10_17_19_50_training.pcap"
MAX_PACKETS = 50000  # limit to first N packets
# ===============

print(">> Loading packets...")
raw_packets = rdpcap(pcap_path)
print(f">> Loaded {len(raw_packets)} packets (showing first {MAX_PACKETS})")

# EtherTypes
AVTP_ETHERTYPE = 0x8100   # VLAN-tagged, actual AVTP might be inside (check below)
PTP_ETHERTYPE = 0x88F7
IPV4_ETHERTYPE = 0x0800

timestamps = []
protocols = []  # "CAN/UDP", "AVTP", "PTPv2", "Other"

for pkt in raw_packets[:MAX_PACKETS]:
    if not pkt.haslayer(Ether):
        continue

    ts = pkt.time
    eth = pkt[Ether]

    proto = "Other"
    if eth.type == PTP_ETHERTYPE:
        proto = "PTPv2"
    elif eth.type == IPV4_ETHERTYPE:
        proto = "CAN/UDP"
    elif eth.type == AVTP_ETHERTYPE:
        proto = "AVTP"

    timestamps.append(ts)
    protocols.append(proto)

timestamps = np.array(timestamps)
protocols = np.array(protocols)

# Compute inter-arrival times between all consecutive packets
delta_t = np.diff(timestamps)
protocol_next = protocols[1:]  # protocol of the second packet in each Δt pair

# Assign colors
color_map = {
    "CAN/UDP": "red",
    "AVTP": "blue",
    "PTPv2": "green",
    "Other": "gray"
}
colors = [color_map.get(p, "gray") for p in protocol_next]

# === Plot ===
plt.figure(figsize=(14, 6))
plt.scatter(range(len(delta_t)), delta_t, c=colors, s=8, alpha=0.7)
plt.xlabel("Packet index (up to 50k)")
plt.ylabel("Δt (seconds)")
plt.title("Inter-packet Time Δt per Protocol (First 50,000 packets)")
plt.grid(True, linestyle="--", alpha=0.3)

# Create legend manually
for name, color in color_map.items():
    plt.scatter([], [], c=color, label=name, s=20)
plt.legend(markerscale=2)
plt.tight_layout()
plt.savefig("inter_packet_timeline_colored.png", dpi=300, bbox_inches="tight")
plt.show()

print("✅ Saved plot as inter_packet_timeline_colored.png")
