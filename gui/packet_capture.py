from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

print("=" * 60)
print("  QNIDS — Network Packet Capture")
print("=" * 60)
print(f"  Started: {datetime.now().strftime('%H:%M:%S')}")
print("  Ctrl+C dabao rokne ke liye")
print("=" * 60)
print()

# Header print karo
print(
    f"{'TIME':<10} "
    f"{'SOURCE IP':<16} "
    f"{'DEST IP':<16} "
    f"{'PROTOCOL':<10} "
    f"{'SIZE':<8} "
    f"{'PORT':<8}"
)
print("-" * 70)

# Counter
packet_count = 0

def process_packet(packet):
    global packet_count

    # ── Sirf IP packets process karo
    if not packet.haslayer(IP):
        return

    # ── Basic info nikalo
    src_ip   = packet[IP].src        # Source IP
    dst_ip   = packet[IP].dst        # Destination IP
    size     = len(packet)           # Packet size bytes mein
    time_now = datetime.now().strftime("%H:%M:%S")

    # ── Protocol aur Port nikalo
    protocol = "OTHER"
    port     = "-"

    if packet.haslayer(TCP):
        protocol = "TCP"
        port = str(packet[TCP].dport)   # Destination port

    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = str(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        port = "-"

    # ── Console pe print karo
    print(
        f"{time_now:<10} "
        f"{src_ip:<16} "
        f"{dst_ip:<16} "
        f"{protocol:<10} "
        f"{size:<8} "
        f"{port:<8}"
    )

    packet_count += 1

    # ── Har 10 packets pe summary
    if packet_count % 10 == 0:
        print(f"\n  [{packet_count} packets captured so far...]\n")


# ── Capture shuru karo
try:
    sniff(
        prn=process_packet,  # Har packet pe yeh function call ho
        store=0,             # Memory mein save mat karo
        filter="ip"          # Sirf IP packets
    )
except KeyboardInterrupt:
    print(f"\n\nCapture stopped — Total: {packet_count} packets")