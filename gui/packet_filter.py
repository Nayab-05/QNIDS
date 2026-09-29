from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

print("QNIDS — Filtered Packet Monitor")
print("Common ports monitor kar raha hai...")
print("-" * 60)

# ── Common ports jo interesting hain
INTERESTING_PORTS = {
    80:   "HTTP",
    443:  "HTTPS",
    21:   "FTP",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    53:   "DNS",
    3306: "MySQL",
    8080: "HTTP-ALT",
}

stats = {
    "TCP": 0, "UDP": 0,
    "ICMP": 0, "OTHER": 0,
    "total": 0
}

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    size     = len(packet)
    time_now = datetime.now().strftime("%H:%M:%S")

    protocol = "OTHER"
    port     = 0
    service  = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        port     = packet[TCP].dport
        service  = INTERESTING_PORTS.get(port, "")
        stats["TCP"] += 1

    elif packet.haslayer(UDP):
        protocol = "UDP"
        port     = packet[UDP].dport
        service  = INTERESTING_PORTS.get(port, "")
        stats["UDP"] += 1

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        stats["ICMP"] += 1
    else:
        stats["OTHER"] += 1

    stats["total"] += 1

    # ── Service tag add karo
    service_tag = f"[{service}]" if service else ""

    print(
        f"{time_now}  "
        f"{src_ip:<16} → {dst_ip:<16}  "
        f"{protocol:<5}  "
        f"Port:{port:<6}  "
        f"Size:{size:<5}  "
        f"{service_tag}"
    )

    # ── Har 20 packets stats show karo
    if stats["total"] % 20 == 0:
        print(f"""
  ┌─ Stats ({stats['total']} total) ──────────────┐
  │  TCP:   {stats['TCP']}
  │  UDP:   {stats['UDP']}
  │  ICMP:  {stats['ICMP']}
  └──────────────────────────────────┘
        """)


try:
    sniff(prn=process_packet, store=0, filter="ip")
except KeyboardInterrupt:
    print(f"\nTotal captured: {stats['total']}")
    print(f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']}")