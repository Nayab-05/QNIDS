from scapy.all import sniff, IP, TCP, UDP, ICMP

print("Scapy import successful!")

def show_packet(packet):
    print("Packet found!")
    print(packet.summary())
    print("---")

# Sirf 5 packets capture karo — test ke liye
sniff(prn=show_packet, count=5)
