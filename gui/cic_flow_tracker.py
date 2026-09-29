import time
import threading
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
import numpy as np

class CICFlow:
    """
    Ek single network flow ka tracker
    CIC-IDS2017 style features extract karta hai
    """

    def __init__(self, src_ip, dst_ip,
                 src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = time.time()
        self.last_time  = self.start_time

        # Forward packets (src → dst)
        self.fwd_packets   = []
        self.fwd_bytes     = 0
        self.fwd_pkt_count = 0

        # Backward packets (dst → src)
        self.bwd_packets   = []
        self.bwd_bytes     = 0
        self.bwd_pkt_count = 0

        # TCP Flags count
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0

        # Inter-arrival times
        self.fwd_iat = []
        self.bwd_iat = []
        self.last_fwd_time = None
        self.last_bwd_time = None

        self.is_active = True

    def add_packet(self, pkt, direction='fwd'):
        """Packet add karo flow mein"""
        now  = time.time()
        size = len(pkt)
        self.last_time = now

        if direction == 'fwd':
            # IAT calculate karo
            if self.last_fwd_time:
                iat = (now - self.last_fwd_time) * 1e6
                self.fwd_iat.append(iat)
            self.last_fwd_time  = now
            self.fwd_bytes     += size
            self.fwd_pkt_count += 1
            self.fwd_packets.append(size)
        else:
            if self.last_bwd_time:
                iat = (now - self.last_bwd_time) * 1e6
                self.bwd_iat.append(iat)
            self.last_bwd_time  = now
            self.bwd_bytes     += size
            self.bwd_pkt_count += 1
            self.bwd_packets.append(size)

        # TCP flags
        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x01: self.fin_count += 1
            if flags & 0x02: self.syn_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x08: self.psh_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x20: self.urg_count += 1

    def get_features(self):
        """
        CIC-IDS2017 style features extract karo
        """
        now      = time.time()
        duration = (now - self.start_time) * 1e6
        if duration <= 0:
            duration = 1

        total_pkts  = self.fwd_pkt_count + \
                      self.bwd_pkt_count
        total_bytes = self.fwd_bytes + self.bwd_bytes

        # Packet length stats
        all_pkts = self.fwd_packets + self.bwd_packets
        pkt_len_mean = np.mean(all_pkts) \
            if all_pkts else 0
        pkt_len_std  = np.std(all_pkts) \
            if all_pkts else 0
        pkt_len_min  = min(all_pkts) if all_pkts else 0
        pkt_len_max  = max(all_pkts) if all_pkts else 0

        # Fwd packet stats
        fwd_pkt_mean = np.mean(self.fwd_packets) \
            if self.fwd_packets else 0
        fwd_pkt_std  = np.std(self.fwd_packets) \
            if self.fwd_packets else 0
        fwd_pkt_min  = min(self.fwd_packets) \
            if self.fwd_packets else 0
        fwd_pkt_max  = max(self.fwd_packets) \
            if self.fwd_packets else 0

        # Bwd packet stats
        bwd_pkt_mean = np.mean(self.bwd_packets) \
            if self.bwd_packets else 0
        bwd_pkt_std  = np.std(self.bwd_packets) \
            if self.bwd_packets else 0
        bwd_pkt_min  = min(self.bwd_packets) \
            if self.bwd_packets else 0
        bwd_pkt_max  = max(self.bwd_packets) \
            if self.bwd_packets else 0

        # IAT stats
        fwd_iat_mean = np.mean(self.fwd_iat) \
            if self.fwd_iat else 0
        fwd_iat_std  = np.std(self.fwd_iat) \
            if self.fwd_iat else 0
        fwd_iat_min  = min(self.fwd_iat) \
            if self.fwd_iat else 0
        fwd_iat_max  = max(self.fwd_iat) \
            if self.fwd_iat else 0

        bwd_iat_mean = np.mean(self.bwd_iat) \
            if self.bwd_iat else 0
        bwd_iat_std  = np.std(self.bwd_iat) \
            if self.bwd_iat else 0
        bwd_iat_min  = min(self.bwd_iat) \
            if self.bwd_iat else 0
        bwd_iat_max  = max(self.bwd_iat) \
            if self.bwd_iat else 0

        all_iat = self.fwd_iat + self.bwd_iat
        flow_iat_mean = np.mean(all_iat) \
            if all_iat else 0
        flow_iat_std  = np.std(all_iat) \
            if all_iat else 0
        flow_iat_min  = min(all_iat) \
            if all_iat else 0
        flow_iat_max  = max(all_iat) \
            if all_iat else 0

        # Flow rates
        dur_sec = duration / 1e6
        flow_bytes_per_sec = total_bytes / dur_sec \
            if dur_sec > 0 else 0
        flow_pkts_per_sec  = total_pkts / dur_sec \
            if dur_sec > 0 else 0

        return {
            # Basic flow info
            '_src_ip':   self.src_ip,
            '_dst_ip':   self.dst_ip,
            '_src_port': self.src_port,
            '_dst_port': self.dst_port,
            '_protocol': self.protocol,

            # CIC-IDS2017 features
            'Flow Duration':
                duration,
            'Total Fwd Packets':
                self.fwd_pkt_count,
            'Total Backward Packets':
                self.bwd_pkt_count,
            'Total Length of Fwd Packets':
                self.fwd_bytes,
            'Total Length of Bwd Packets':
                self.bwd_bytes,
            'Fwd Packet Length Max':
                fwd_pkt_max,
            'Fwd Packet Length Min':
                fwd_pkt_min,
            'Fwd Packet Length Mean':
                fwd_pkt_mean,
            'Fwd Packet Length Std':
                fwd_pkt_std,
            'Bwd Packet Length Max':
                bwd_pkt_max,
            'Bwd Packet Length Min':
                bwd_pkt_min,
            'Bwd Packet Length Mean':
                bwd_pkt_mean,
            'Bwd Packet Length Std':
                bwd_pkt_std,
            'Flow Bytes/s':
                flow_bytes_per_sec,
            'Flow Packets/s':
                flow_pkts_per_sec,
            'Flow IAT Mean':
                flow_iat_mean,
            'Flow IAT Std':
                flow_iat_std,
            'Flow IAT Max':
                flow_iat_max,
            'Flow IAT Min':
                flow_iat_min,
            'Fwd IAT Total':
                sum(self.fwd_iat),
            'Fwd IAT Mean':
                fwd_iat_mean,
            'Fwd IAT Std':
                fwd_iat_std,
            'Fwd IAT Max':
                fwd_iat_max,
            'Fwd IAT Min':
                fwd_iat_min,
            'Bwd IAT Total':
                sum(self.bwd_iat),
            'Bwd IAT Mean':
                bwd_iat_mean,
            'Bwd IAT Std':
                bwd_iat_std,
            'Bwd IAT Max':
                bwd_iat_max,
            'Bwd IAT Min':
                bwd_iat_min,
            'Fwd PSH Flags':
                self.psh_count,
            'Bwd PSH Flags':
                0,
            'Fwd URG Flags':
                self.urg_count,
            'Bwd URG Flags':
                0,
            'Fwd Header Length':
                self.fwd_pkt_count * 20,
            'Bwd Header Length':
                self.bwd_pkt_count * 20,
            'Fwd Packets/s':
                self.fwd_pkt_count / dur_sec
                if dur_sec > 0 else 0,
            'Bwd Packets/s':
                self.bwd_pkt_count / dur_sec
                if dur_sec > 0 else 0,
            'Packet Length Min':
                pkt_len_min,
            'Packet Length Max':
                pkt_len_max,
            'Packet Length Mean':
                pkt_len_mean,
            'Packet Length Std':
                pkt_len_std,
            'Packet Length Variance':
                pkt_len_std ** 2,
            'FIN Flag Count':
                self.fin_count,
            'SYN Flag Count':
                self.syn_count,
            'RST Flag Count':
                self.rst_count,
            'PSH Flag Count':
                self.psh_count,
            'ACK Flag Count':
                self.ack_count,
            'URG Flag Count':
                self.urg_count,
            'CWE Flag Count':
                0,
            'ECE Flag Count':
                0,
            'Down/Up Ratio':
                self.bwd_bytes / self.fwd_bytes
                if self.fwd_bytes > 0 else 0,
            'Average Packet Size':
                pkt_len_mean,
            'Avg Fwd Segment Size':
                fwd_pkt_mean,
            'Avg Bwd Segment Size':
                bwd_pkt_mean,
            'Fwd Avg Bytes/Bulk':
                0,
            'Fwd Avg Packets/Bulk':
                0,
            'Fwd Avg Bulk Rate':
                0,
            'Bwd Avg Bytes/Bulk':
                0,
            'Bwd Avg Packets/Bulk':
                0,
            'Bwd Avg Bulk Rate':
                0,
            'Subflow Fwd Packets':
                self.fwd_pkt_count,
            'Subflow Fwd Bytes':
                self.fwd_bytes,
            'Subflow Bwd Packets':
                self.bwd_pkt_count,
            'Subflow Bwd Bytes':
                self.bwd_bytes,
            'Init_Win_bytes_forward':
                0,
            'Init_Win_bytes_backward':
                0,
            'act_data_pkt_fwd':
                self.fwd_pkt_count,
            'min_seg_size_forward':
                fwd_pkt_min,
            'Active Mean':
                0,
            'Active Std':
                0,
            'Active Max':
                0,
            'Active Min':
                0,
            'Idle Mean':
                0,
            'Idle Std':
                0,
            'Idle Max':
                0,
            'Idle Min':
                0,
        }


class CICFlowTracker:
    """
    Live network traffic se CIC-style flows track karo
    """

    FLOW_TIMEOUT = 60  # seconds

    def __init__(self, callback=None):
        self.flows    = {}
        self.callback = callback
        self._lock    = threading.Lock()

        # Cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()

    def process_packet(self, pkt):
        """Har packet yahan aata hai"""
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = 6  # TCP
            flags    = int(pkt[TCP].flags)
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = 17  # UDP
            flags    = 0
        else:
            return

        # Flow key — 5 tuple
        fwd_key = (src_ip, dst_ip,
                   src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip,
                   dst_port, src_port, protocol)

        with self._lock:
            if fwd_key in self.flows:
                # Forward direction
                flow = self.flows[fwd_key]
                flow.add_packet(pkt, 'fwd')

                # TCP FIN/RST — flow complete
                if TCP in pkt and (
                    flags & 0x01 or flags & 0x04
                ):
                    self._complete_flow(fwd_key)

            elif bwd_key in self.flows:
                # Backward direction
                flow = self.flows[bwd_key]
                flow.add_packet(pkt, 'bwd')

            else:
                # New flow
                flow = CICFlow(
                    src_ip, dst_ip,
                    src_port, dst_port, protocol
                )
                flow.add_packet(pkt, 'fwd')
                self.flows[fwd_key] = flow

    def _complete_flow(self, key):
        """Flow complete — features extract karo"""
        if key not in self.flows:
            return

        flow = self.flows.pop(key)

        # Minimum packets filter
        total_pkts = flow.fwd_pkt_count + \
                     flow.bwd_pkt_count
        if total_pkts < 2:
            return

        features = flow.get_features()

        if self.callback:
            self.callback(features)

    def _cleanup_loop(self):
        """Timeout flows cleanup karo"""
        while True:
            time.sleep(10)
            now = time.time()

            with self._lock:
                timeout_keys = [
                    k for k, v in self.flows.items()
                    if now - v.last_time >
                    self.FLOW_TIMEOUT
                ]
                for key in timeout_keys:
                    self._complete_flow(key)