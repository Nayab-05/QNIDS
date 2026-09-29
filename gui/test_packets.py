from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

print("Test shuru — browser mein koi site kholo...")
print("Ctrl+C se rokna\n")

def show(pkt):
    if IP in pkt:
        print(f"{datetime.now().strftime('%H:%M:%S')} | "
              f"{pkt[IP].src} | {len(pkt)}B")

sniff(prn=show, filter="ip", store=False, count=20)
print("20 packets complete!")

