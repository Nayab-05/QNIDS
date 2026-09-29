import warnings
warnings.filterwarnings('ignore')

from scapy.all import sniff
from cic_flow_tracker import CICFlowTracker
from datetime import datetime

INTERFACE = r"\Device\NPF_{CFC52924-8468-4E87-AD39-5C6315E326A1}"

flow_count = 0

def on_flow(features):
    global flow_count
    flow_count += 1

    src      = features['_src_ip']
    dst      = features['_dst_ip']
    dur      = features['Flow Duration'] / 1e6
    fwd_pkts = features['Total Fwd Packets']
    bwd_pkts = features['Total Backward Packets']
    fwd_byt  = features['Total Length of Fwd Packets']
    bwd_byt  = features['Total Length of Bwd Packets']
    syn      = features['SYN Flag Count']
    ack      = features['ACK Flag Count']
    fin      = features['FIN Flag Count']
    bps      = features['Flow Bytes/s']
    pps      = features['Flow Packets/s']

    print(
        f"[{flow_count}] "
        f"{datetime.now().strftime('%H:%M:%S')} | "
        f"{src:<16} → {dst:<16} | "
        f"Dur:{dur:.3f}s | "
        f"Pkts:{fwd_pkts}↑{bwd_pkts}↓ | "
        f"Bytes:{fwd_byt}↑{bwd_byt}↓ | "
        f"Flags:SYN={syn}ACK={ack}FIN={fin} | "
        f"BPS:{bps:.0f}"
    )

tracker = CICFlowTracker(callback=on_flow)

print("=" * 60)
print("  CIC Flow Tracker Test")
print("=" * 60)
print("Browser mein koi website kholo")
print("Flows complete hone pe dikh'engi")
print("Ctrl+C se rokna\n")

try:
    sniff(
        iface   = INTERFACE,
        prn     = tracker.process_packet,
        store   = False,
        filter  = "ip"
    )
except KeyboardInterrupt:
    print(f"\nTotal flows: {flow_count}")