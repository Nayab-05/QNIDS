import time
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP

PORT_SERVICE = {
    80:   'http',     443:  'https',
    21:   'ftp',      22:   'ssh',
    23:   'telnet',   25:   'smtp',
    53:   'domain',   110:  'pop3',
    143:  'imap',     3306: 'mysql',
    8080: 'http_alt', 3389: 'rdp',
    445:  'microsoft_ds',
    139:  'netbios_ssn',
}

PROTOCOL_MAP = {'tcp': 0, 'udp': 1, 'icmp': 2}

SERVICE_MAP = {
    'http': 0,    'https': 1,   'ftp': 2,
    'ssh': 3,     'smtp': 4,    'domain': 5,
    'other': 6,   'telnet': 7,  'pop3': 8,
    'imap': 9,    'mysql': 10,  'rdp': 11,
    'http_alt': 12, 'microsoft_ds': 13,
    'netbios_ssn': 14,
}

FLAG_MAP = {
    'SF': 0, 'S0': 1, 'REJ': 2,
    'RSTO': 3, 'RSTR': 4,
    'SH': 5,  'OTH': 6,
}


class FeatureExtractor:

    def __init__(self):
        # Active TCP connections
        self.connections = {}
        # Last 100 completed connections
        self.history     = deque(maxlen=100)
        # Last 2 seconds connections
        self.recent_2s   = deque(maxlen=500)

    def process_packet(self, pkt):
        if IP not in pkt:
            return None

        if TCP in pkt:
            return self._handle_tcp(pkt)
        elif UDP in pkt:
            return self._handle_udp(pkt)
        elif ICMP in pkt:
            return self._handle_icmp(pkt)

        return None

    # ─────────────────────────────
    # TCP Handler
    # ─────────────────────────────
    def _handle_tcp(self, pkt):
        src   = pkt[IP].src
        dst   = pkt[IP].dst
        sp    = pkt[TCP].sport
        dp    = pkt[TCP].dport
        key   = (src, dst, sp, dp)
        flags = int(pkt[TCP].flags)
        now   = time.time()

        # SYN only — new connection
        if flags & 0x02 and not flags & 0x10:
            self.connections[key] = {
                'start':       now,
                'src':         src,
                'dst':         dst,
                'src_port':    sp,
                'dst_port':    dp,
                'protocol':    'tcp',
                'service':     PORT_SERVICE.get(
                    dp, 'other'
                ),
                'src_bytes':   0,
                'dst_bytes':   0,
                'land':        1 if src == dst else 0,
                'urgent':      0,
                'fragments':   0,
                'syn_errors':  0,
                'rej_errors':  0,
                'flags_list':  ['S'],
            }
            return None

        # Existing connection
        if key not in self.connections:
            return None

        conn = self.connections[key]
        conn['src_bytes'] += len(pkt)

        # Urgent flag check
        if hasattr(pkt[TCP], 'urgptr') and \
           pkt[TCP].urgptr > 0:
            conn['urgent'] += 1

        # SYN-ACK
        if flags & 0x02 and flags & 0x10:
            conn['flags_list'].append('SA')

        # SYN error
        if flags & 0x02 and not flags & 0x10:
            conn['syn_errors'] += 1

        # RST — connection reset
        if flags & 0x04:
            conn['flags_list'].append('R')
            conn['rej_errors'] += 1
            return self._finalize(key, now, 'RSTO')

        # FIN — connection complete
        if flags & 0x01:
            conn['flags_list'].append('F')
            return self._finalize(key, now, 'SF')

        return None

    # ─────────────────────────────
    # UDP Handler
    # ─────────────────────────────
    def _handle_udp(self, pkt):
        src = pkt[IP].src
        dst = pkt[IP].dst
        dp  = pkt[UDP].dport
        now = time.time()

        svc = PORT_SERVICE.get(dp, 'other')
        features = self._base_features()
        features.update({
            'duration':      0,
            'protocol_type': 1,
            'service':       SERVICE_MAP.get(svc, 6),
            'flag':          FLAG_MAP['SF'],
            'src_bytes':     len(pkt),
            'dst_bytes':     0,
            'land':          1 if src == dst else 0,
            '_src':          src,
            '_dst':          dst,
            '_time':         now,
            '_service_name': svc,
            '_protocol':     'UDP',
        })

        self._save_history(features)
        self._add_window_stats(features)
        return features

    # ─────────────────────────────
    # ICMP Handler
    # ─────────────────────────────
    def _handle_icmp(self, pkt):
        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()

        features = self._base_features()
        features.update({
            'duration':      0,
            'protocol_type': 2,
            'service':       SERVICE_MAP.get(
                'eco_i', 6
            ),
            'flag':          FLAG_MAP['SF'],
            'src_bytes':     len(pkt),
            'dst_bytes':     0,
            'land':          0,
            '_src':          src,
            '_dst':          dst,
            '_time':         now,
            '_service_name': 'icmp',
            '_protocol':     'ICMP',
        })

        self._save_history(features)
        self._add_window_stats(features)
        return features

    # ─────────────────────────────
    # Connection Finalize
    # ─────────────────────────────
    def _finalize(self, key, now, flag_str):
        if key not in self.connections:
            return None

        conn     = self.connections.pop(key)
        duration = now - conn['start']
        svc      = conn.get('service', 'other')
        svc_enc  = SERVICE_MAP.get(svc, 6)
        flag_enc = FLAG_MAP.get(flag_str, 0)

        features = self._base_features()
        features.update({
            'duration':          duration,
            'protocol_type':     0,
            'service':           svc_enc,
            'flag':              flag_enc,
            'src_bytes':         conn['src_bytes'],
            'dst_bytes':         conn['dst_bytes'],
            'land':              conn['land'],
            'wrong_fragment':    conn['fragments'],
            'urgent':            conn['urgent'],
            '_src':              conn['src'],
            '_dst':              conn['dst'],
            '_time':             now,
            '_service_name':     svc,
            '_protocol':         'TCP',
        })

        self._save_history(features)
        self._add_window_stats(features)
        return features

    # ─────────────────────────────
    # Window Statistics
    # ─────────────────────────────
    def _add_window_stats(self, features):
        dst  = features.get('_dst', '')
        svc  = features.get('service', 0)
        now  = features.get('_time', time.time())
        hist = list(self.history)

        # Last 2 seconds window
        window = [
            h for h in hist
            if now - h.get('_time', 0) <= 2.0
        ]

        count     = sum(
            1 for h in window
            if h.get('_dst') == dst
        )
        srv_count = sum(
            1 for h in window
            if h.get('service') == svc
        )

        if count > 0:
            same_srv  = sum(
                1 for h in window
                if h.get('_dst') == dst
                and h.get('service') == svc
            )
            diff_srv  = count - same_srv
            serror    = sum(
                1 for h in window
                if h.get('_dst') == dst
                and h.get('flag') == 1
            )
            rerror    = sum(
                1 for h in window
                if h.get('_dst') == dst
                and h.get('flag') == 2
            )
        else:
            same_srv = diff_srv = serror = rerror = 0

        # Last 100 connections host stats
        h100 = list(self.history)[-100:]
        dst_host_count = sum(
            1 for h in h100
            if h.get('_dst') == dst
        )
        dst_host_srv = sum(
            1 for h in h100
            if h.get('_dst') == dst
            and h.get('service') == svc
        )

        safe_div = lambda a, b: a/b if b > 0 else 0

        features.update({
            'count':
                count,
            'srv_count':
                srv_count,
            'serror_rate':
                safe_div(serror, count),
            'srv_serror_rate':
                safe_div(serror, srv_count),
            'rerror_rate':
                safe_div(rerror, count),
            'srv_rerror_rate':
                safe_div(rerror, srv_count),
            'same_srv_rate':
                safe_div(same_srv, count),
            'diff_srv_rate':
                safe_div(diff_srv, count),
            'srv_diff_host_rate':    0,
            'dst_host_count':
                dst_host_count,
            'dst_host_srv_count':
                dst_host_srv,
            'dst_host_same_srv_rate':
                safe_div(dst_host_srv, dst_host_count),
            'dst_host_diff_srv_rate':
                safe_div(
                    dst_host_count - dst_host_srv,
                    dst_host_count
                ),
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate':        0,
            'dst_host_srv_serror_rate':    0,
            'dst_host_rerror_rate':        0,
            'dst_host_srv_rerror_rate':    0,
        })

    def _save_history(self, features):
        self.history.append(features.copy())

    def _base_features(self):
        """41 features — sab zero se shuru"""
        return {
            'duration':                    0,
            'protocol_type':               0,
            'service':                     0,
            'flag':                        0,
            'src_bytes':                   0,
            'dst_bytes':                   0,
            'land':                        0,
            'wrong_fragment':              0,
            'urgent':                      0,
            'hot':                         0,
            'num_failed_logins':           0,
            'logged_in':                   0,
            'num_compromised':             0,
            'root_shell':                  0,
            'su_attempted':                0,
            'num_root':                    0,
            'num_file_creations':          0,
            'num_shells':                  0,
            'num_access_files':            0,
            'num_outbound_cmds':           0,
            'is_host_login':               0,
            'is_guest_login':              0,
            'count':                       0,
            'srv_count':                   0,
            'serror_rate':                 0,
            'srv_serror_rate':             0,
            'rerror_rate':                 0,
            'srv_rerror_rate':             0,
            'same_srv_rate':               0,
            'diff_srv_rate':               0,
            'srv_diff_host_rate':          0,
            'dst_host_count':              0,
            'dst_host_srv_count':          0,
            'dst_host_same_srv_rate':      0,
            'dst_host_diff_srv_rate':      0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate':        0,
            'dst_host_srv_serror_rate':    0,
            'dst_host_rerror_rate':        0,
            'dst_host_srv_rerror_rate':    0,
            '_src':                        '',
            '_dst':                        '',
            '_time':                       0,
            '_service_name':               'other',
            '_protocol':                   'TCP',
        }