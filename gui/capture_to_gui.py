import threading
import time
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"Scapy load error: {e}")


class PacketCapture:

    def __init__(self, callback=None):
        self.callback     = callback
        self.is_running   = False
        self._thread      = None
        self.packet_count = 0

    def start(self):
        if self.is_running:
            return
        self.is_running   = True
        self._thread      = threading.Thread(
            target=self._run,
            daemon=True
        )
        self._thread.start()
        print("Capture thread started")

    def stop(self):
        self.is_running = False
        print("Capture stopped")

    def _run(self):
        if not SCAPY_AVAILABLE:
            print("Scapy not available")
            return
        try:
            print("Sniffing started...")
            sniff(
                prn=self._process_packet,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Sniff error: {e}")

    def _process_packet(self, pkt):
        if not self.is_running:
            return
        if IP not in pkt:
            return

        try:
            src_ip   = pkt[IP].src
            size     = len(pkt)
            ts       = datetime.now().strftime("%H:%M:%S")
            protocol = "OTHER"
            port     = "-"
            service  = ""

            if TCP in pkt:
                protocol = "TCP"
                dport    = pkt[TCP].dport
                port     = str(dport)
                service  = {
                    80:   "HTTP",
                    443:  "HTTPS",
                    22:   "SSH",
                    21:   "FTP",
                    53:   "DNS",
                    8080: "HTTP-ALT",
                    3306: "MySQL",
                    25:   "SMTP",
                }.get(dport, "")

            elif UDP in pkt:
                protocol = "UDP"
                dport    = pkt[UDP].dport
                port     = str(dport)
                service  = "DNS" if dport == 53 else ""

            elif ICMP in pkt:
                protocol = "ICMP"

            self.packet_count += 1

            if service:
                info = f"{protocol} | {service} | {size}B"
            else:
                info = f"{protocol} | Port:{port} | {size}B"

            # Console pe print karo — confirm ke liye
            print(f"[{self.packet_count}] {ts} | {src_ip} | {info}")

            # GUI callback
            if self.callback:
                self.callback(
                    ts,
                    src_ip,
                    info,
                    "MONITORING",
                    "#3b82f6",
                    100
                )

        except Exception as e:
            print(f"Packet error: {e}")