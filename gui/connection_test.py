from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime

# All active connections store
connections = defaultdict(dict)
completed   = 0

def track(pkt):
    global completed

    if IP not in pkt or TCP not in pkt:
        return

    src   = pkt[IP].src
    dst   = pkt[IP].dst
    sp    = pkt[TCP].sport
    dp    = pkt[TCP].dport
    key   = (src, dst, sp, dp)
    flags = int(pkt[TCP].flags)

    # SYN — new connection start
    if flags & 0x02 and not flags & 0x10:
        connections[key] = {
            'start':      datetime.now(),
            'src_bytes':  0,
            'src':        src,
            'dst':        dst,
            'dport':      dp,
            'flags_seen': ['SYN'],
        }

    # Existing connection
    elif key in connections:
        conn = connections[key]
        conn['src_bytes'] += len(pkt)

        # SYN-ACK
        if flags & 0x02 and flags & 0x10:
            conn['flags_seen'].append('SYN-ACK')

        # FIN — connection complete
        if flags & 0x01:
            conn['flags_seen'].append('FIN')
            duration = (
                datetime.now() - conn['start']
            ).total_seconds()
            completed += 1
            print(
                f"[{completed}] Connection COMPLETE\n"
                f"    {src}:{sp} → {dst}:{dp}\n"
                f"    Duration:  {duration:.3f}s\n"
                f"    Bytes:     {conn['src_bytes']}B\n"
                f"    Flags:     {conn['flags_seen']}\n"
            )
            del connections[key]

        # RST — connection reset
        elif flags & 0x04:
            conn['flags_seen'].append('RST')
            duration = (
                datetime.now() - conn['start']
            ).total_seconds()
            completed += 1
            print(
                f"[{completed}] Connection RESET\n"
                f"    {src}:{sp} → {dst}:{dp}\n"
                f"    Duration:  {duration:.3f}s\n"
                f"    Bytes:     {conn['src_bytes']}B\n"
            )
            del connections[key]


print("=" * 50)
print("  Connection Tracking Test")
print("=" * 50)
print("Browser mein koi website kholo")
print("Connections complete hone pe dikh'engi")
print("Ctrl+C se rokna\n")

try:
    sniff(
        prn=track,
        filter="tcp",
        store=False
    )
except KeyboardInterrupt:
    print(f"\nTotal completed: {completed}")
    print(
        f"Active (incomplete): {len(connections)}"
    )
    
    """Yeh code intrusion detection ke liye useful hai kyunki yeh network ki har TCP connection ko monitor karta
    hai aur unusual patterns (jaise zyada connections, scanning, incomplete connections, ya abnormal data transfer)
    ko identify karke attacks detect karne mein help karta hai."""