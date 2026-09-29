import matplotlib
import numpy as np
matplotlib.use('Agg')
import sys
import os
import threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import predict
from PyQt5.QtCore import QThread, pyqtSignal as Signal
from PyQt5.QtWidgets import QProgressDialog
import random
from datetime import datetime
from csv_simulator import CSVSimulator
from export_manager import ExportManager
from loading_screen import LoadingScreen
from about_dialog import AboutDialog

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont

from capture_to_gui import PacketCapture
from alert_system import (
    play_attack_sound,
    play_unknown_sound,
    UnknownThreatPopup
)
from chart_widget import AttackPieChart


# ══════════════════════════════════════════════════════
# PCAP BACKGROUND PROCESSOR
# ══════════════════════════════════════════════════════
class PcapProcessor(QThread):
    """
    Reads a .pcap file in a background thread,
    extracts flows, classifies with predict.predict(),
    and emits results to the GUI one by one.
    """
    flow_ready    = Signal(str, str, str, str, str, int, float)
    progress      = Signal(int)
    finished_pcap = Signal(int)
    error         = Signal(str)

    def __init__(self, pcap_path: str):
        super().__init__()
        self.pcap_path  = pcap_path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            import numpy as np

            packets = rdpcap(self.pcap_path)
            if len(packets) == 0:
                self.error.emit("PCAP file is empty.")
                return

            # Group packets into flows by (src_ip, dst_ip, proto)
            flows = {}
            for pkt in packets:
                if not pkt.haslayer(IP):
                    continue
                proto = ("TCP" if pkt.haslayer(TCP) else
                         "UDP" if pkt.haslayer(UDP) else "OTHER")
                key = (pkt[IP].src, pkt[IP].dst, proto)
                flows.setdefault(key, []).append(pkt)

            flow_count = len(flows)
            processed = 0

            for (src_ip, dst_ip, proto), pkts in flows.items():
                if self._cancelled:
                    break

                # ── Feature extraction
                times = [float(p.time) for p in pkts]
                if len(times) > 1:
                    flow_dur = times[-1] - times[0]
                    iats = [times[i+1] - times[i] for i in range(len(times) - 1)]
                    iat_mean = sum(iats) / len(iats)
                    iat_std = (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5
                else:
                    flow_dur = iat_mean = iat_std = 0.0
                    iats = []

                pkt_sizes = [len(p) for p in pkts]
                total_bytes = sum(pkt_sizes)
                fwd_pkts = bwd_pkts = 0
                syn = ack = fin = rst = 0

                for p in pkts:
                    if p.haslayer(IP):
                        if p[IP].src == src_ip:
                            fwd_pkts += 1
                        else:
                            bwd_pkts += 1
                    if p.haslayer(TCP):
                        f = p[TCP].flags
                        if f & 0x02: syn += 1
                        if f & 0x10: ack += 1
                        if f & 0x01: fin += 1
                        if f & 0x04: rst += 1

                mean_len = total_bytes / len(pkts) if pkts else 0
                bytes_per_sec = total_bytes / flow_dur if flow_dur > 0 else 0
                pkts_per_sec = len(pkts) / flow_dur if flow_dur > 0 else 0

                # Compute extra stats needed by model
                fwd_sizes = [len(p) for p in pkts if p.haslayer(IP) and p[IP].src == src_ip]
                bwd_sizes = [len(p) for p in pkts if p.haslayer(IP) and p[IP].src != src_ip]
                all_sizes = [len(p) for p in pkts]

                fwd_iat_min = min(iats) if iats else 0.0
                pkt_var = float(np.var(all_sizes)) if all_sizes else 0.0
                avg_pkt = float(np.mean(all_sizes)) if all_sizes else 0.0
                fwd_min = float(min(fwd_sizes)) if fwd_sizes else 0.0
                fwd_mean = float(np.mean(fwd_sizes)) if fwd_sizes else 0.0
                bwd_total = float(sum(bwd_sizes))

                # Get destination port
                dst_port = 0
                for p in pkts:
                    if p.haslayer(TCP):
                        dst_port = p[TCP].dport
                        break
                    elif p.haslayer(UDP):
                        dst_port = p[UDP].dport
                        break

                # Get TCP window sizes
                init_win_fwd = 65535
                init_win_bwd = 65535
                for p in pkts:
                    if p.haslayer(TCP):
                        if p[IP].src == src_ip:
                            init_win_fwd = p[TCP].window
                        else:
                            init_win_bwd = p[TCP].window
                        break

                flow_dict = {
                    "Destination Port":            float(dst_port),
                    "Flow Duration":               flow_dur,
                    "Total Fwd Packets":           float(fwd_pkts),
                    "Total Backward Packets":      float(bwd_pkts),
                    "Total Length of Fwd Packets": float(sum(fwd_sizes)),
                    "Total Length of Bwd Packets": bwd_total,
                    "Fwd Packet Length Max":       float(max(fwd_sizes)) if fwd_sizes else 0.0,
                    "Fwd Packet Length Min":       fwd_min,
                    "Fwd Packet Length Mean":      fwd_mean,
                    "Fwd Packet Length Std":       float(np.std(fwd_sizes)) if fwd_sizes else 0.0,
                    "Bwd Packet Length Max":       float(max(bwd_sizes)) if bwd_sizes else 0.0,
                    "Bwd Packet Length Min":       float(min(bwd_sizes)) if bwd_sizes else 0.0,
                    "Bwd Packet Length Mean":      float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
                    "Bwd Packet Length Std":       float(np.std(bwd_sizes)) if bwd_sizes else 0.0,
                    "Flow Bytes/s":                bytes_per_sec,
                    "Flow Packets/s":              pkts_per_sec,
                    "Flow IAT Mean":               iat_mean,
                    "Flow IAT Std":                iat_std,
                    "Flow IAT Max":                float(max(iats)) if iats else 0.0,
                    "Flow IAT Min":                float(min(iats)) if iats else 0.0,
                    "Fwd IAT Total":               float(sum(iats)) if iats else 0.0,
                    "Fwd IAT Mean":                iat_mean,
                    "Fwd IAT Std":                 iat_std,
                    "Fwd IAT Max":                 float(max(iats)) if iats else 0.0,
                    "Fwd IAT Min":                 fwd_iat_min,
                    "Bwd IAT Total":               0.0,
                    "Bwd IAT Mean":                0.0,
                    "Bwd IAT Std":                 0.0,
                    "Bwd IAT Max":                 0.0,
                    "Bwd IAT Min":                 0.0,
                    "Fwd PSH Flags":               0.0,
                    "Fwd URG Flags":               0.0,
                    "Fwd Header Length":           float(fwd_pkts * 20),
                    "Bwd Header Length":           float(bwd_pkts * 20),
                    "Fwd Packets/s":               pkts_per_sec * 0.6,
                    "Bwd Packets/s":               pkts_per_sec * 0.4,
                    "Min Packet Length":           float(min(all_sizes)) if all_sizes else 0.0,
                    "Max Packet Length":           float(max(all_sizes)) if all_sizes else 0.0,
                    "Packet Length Mean":          avg_pkt,
                    "Packet Length Std":           float(np.std(all_sizes)) if all_sizes else 0.0,
                    "Packet Length Variance":      pkt_var,
                    "FIN Flag Count":              float(fin),
                    "SYN Flag Count":              float(syn),
                    "RST Flag Count":              float(rst),
                    "PSH Flag Count":              0.0,
                    "ACK Flag Count":              float(ack),
                    "URG Flag Count":              0.0,
                    "CWE Flag Count":              0.0,
                    "ECE Flag Count":              0.0,
                    "Down/Up Ratio":               float(bwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0.0,
                    "Average Packet Size":         avg_pkt,
                    "Avg Fwd Segment Size":        fwd_mean,
                    "Avg Bwd Segment Size":        float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
                    "Subflow Fwd Packets":         float(fwd_pkts),
                    "Subflow Fwd Bytes":           float(sum(fwd_sizes)),
                    "Subflow Bwd Packets":         float(bwd_pkts),
                    "Subflow Bwd Bytes":           bwd_total,
                    "Init_Win_bytes_forward":      float(init_win_fwd),
                    "Init_Win_bytes_backward":     float(init_win_bwd),
                    "act_data_pkt_fwd":            float(fwd_pkts),
                    "min_seg_size_forward":        fwd_min,
                    "Active Mean":                 flow_dur * 0.7,
                    "Active Std":                  0.0,
                    "Active Max":                  flow_dur * 0.9,
                    "Active Min":                  flow_dur * 0.5,
                    "Idle Mean":                   flow_dur * 0.3,
                    "Idle Std":                    0.0,
                    "Idle Max":                    flow_dur * 0.4,
                    "Idle Min":                    flow_dur * 0.1,
                }

                # ── Classify
                result = predict.predict(flow_dict)
                decision = result.get("decision", "SUSPICIOUS")
                label = result.get("display_name", "Unknown")
                conf = int(result.get("rf_confidence", 0) * 100)

                if decision == "Normal":
                    verdict = "NORMAL"
                    color = "#10b981"
                    label = "Normal Traffic"
                elif decision.startswith("Known Attack"):
                    verdict = "ATTACK"
                    color = "#ef4444"
                    label = decision.replace("Known Attack - ", "") + " Attack"
                else:
                    verdict = "UNKNOWN"
                    color = "#f59e0b"
                    label = "Suspicious / Zero-Day"

                ts = datetime.now().strftime("%H:%M:%S")
                if_score_val = result.get("if_score", 0.0)
                self.flow_ready.emit(ts, src_ip, label, verdict, color, conf, if_score_val)

                processed += 1
                self.progress.emit(int(processed / flow_count * 100))
                self.msleep(80)

            # Finished signal only after the loop
            self.finished_pcap.emit(processed)

        except ImportError:
            self.error.emit("Scapy not found.\nRun: pip install scapy")
        except Exception as e:
            self.error.emit(f"PCAP processing error: {str(e)}")


# ══════════════════════════════════════════════════════
# THREAD-SAFE SIGNAL
# ══════════════════════════════════════════════════════
class _Signaller(QObject):
    packet_received = pyqtSignal(str, str, str, str, str, int, float)


# ══════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
ACCENT = "#00d4ff"
GREEN  = "#10b981"
RED    = "#ef4444"
ORANGE = "#f59e0b"
PURPLE = "#8b5cf6"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"
PA     = "#3b82f6"

# ── Sample data for Demo Mode
SAMPLE_ATTACKS = [
    ("DoS Attack",     "ATTACK",  RED,    92),
    ("Normal Traffic", "NORMAL",  GREEN,  98),
    ("Probe",          "ATTACK",  RED,    87),
    ("DDoS",           "ATTACK",  RED,    95),
    ("Normal Traffic", "NORMAL",  GREEN,  99),
    ("Unknown Threat", "UNKNOWN", ORANGE, 74),
    ("R2L Attempt",    "ATTACK",  RED,    83),
    ("Normal Traffic", "NORMAL",  GREEN,  97),
    ("Port Scan",      "ATTACK",  RED,    91),
]
SAMPLE_IPS = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."]


def rnd_ip():
    return random.choice(SAMPLE_IPS) + str(random.randint(1, 254))


def rnd_event():
    return random.choice(SAMPLE_ATTACKS)


# ══════════════════════════════════════════════════════
# METRIC CARD
# ══════════════════════════════════════════════════════
class MetricCard(QFrame):
    def __init__(self, label, value, subtitle,
                 color, trend="", trend_up=True):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-top: 2px solid {color};
                border-radius: 10px;
            }}
        """)
        self.setMinimumHeight(105)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)

        lbl = QLabel(label.upper())
        lbl.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 1.5px;")

        self.val = QLabel(value)
        self.val.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")

        sub = QLabel(subtitle)
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        lay.addWidget(lbl)
        lay.addWidget(self.val)
        lay.addWidget(sub)

        if trend:
            tc = GREEN if trend_up else RED
            ts = "▲" if trend_up else "▼"
            tw = QLabel(f"{ts} {trend}")
            tw.setStyleSheet(f"color: {tc}; font-size: 10px; font-weight: bold;")
            lay.addWidget(tw)

    def update_value(self, new_val):
        self.val.setText(new_val)


# ══════════════════════════════════════════════════════
# MAIN WINDOW
# ══════════════════════════════════════════════════════
class QNIDSMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "QNIDS — Quantum-Inspired Network Intrusion Detection System"
        )
        icon_path = os.path.join(os.path.dirname(__file__), "qnids_icon.ico")
        if os.path.exists(icon_path):
            from PyQt5.QtGui import QIcon
            self.setWindowIcon(QIcon(icon_path))

        self.setMinimumSize(1200, 720)
        self.setStyleSheet(f"background-color: {BG}; color: {TEXT};")

        # State
        self.is_paused    = False
        self.is_demo_mode = False
        self.row_count    = 0
        self.attack_count = 0
        self.packet_count = 0
        self._last_unknown_time = 0
        self._popup_open        = False

        # Thread-safe signal
        self._sig = _Signaller()
        self._sig.packet_received.connect(self.add_row)

        # Capture + simulator
        self.capturer  = PacketCapture(callback=self._on_packet)
        self.simulator = CSVSimulator(callback=self._on_packet)

        # Build UI
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_header())

        mid_widget = QWidget()
        mid = QHBoxLayout(mid_widget)
        mid.setContentsMargins(0, 0, 0, 0)
        mid.setSpacing(0)
        mid.addWidget(self._make_sidebar())
        mid.addWidget(self._make_content(), stretch=1)
        mid.addWidget(self._make_right_panel())
        root.addWidget(mid_widget, stretch=1)

        root.addWidget(self._make_statusbar())

        # Timers
        self.feed_timer  = QTimer()
        self.feed_timer.timeout.connect(self._auto_add_row)
        self.pkt_timer   = QTimer()
        self.pkt_timer.timeout.connect(self._update_packets)
        self.clock_timer = QTimer()
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start(1000)

    # ══════════════════════════════════════
    # HEADER
    # ══════════════════════════════════════
    def _make_header(self):
        hdr = QFrame()
        hdr.setFixedHeight(54)
        hdr.setStyleSheet(f"QFrame {{ background-color: {PANEL}; border-bottom: 1px solid {BORDER}; }}")
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(20, 0, 20, 0)

        logo  = QLabel("⬡")
        logo.setStyleSheet(f"color: {ACCENT}; font-size: 22px;")
        title = QLabel("QNIDS")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 18px; font-weight: bold; letter-spacing: 2px;")
        sub   = QLabel("Quantum-Inspired Network Intrusion Detection System")
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        self.status_badge = QLabel("● SYSTEM ACTIVE")
        self.status_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 11px; font-weight: bold;
            background: rgba(16,185,129,0.1);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 10px; padding: 3px 12px;
        """)
        self.clock_lbl = QLabel("00:00:00")
        self.clock_lbl.setStyleSheet(f"color: {MUTED}; font-size: 12px; font-family: monospace;")

        lay.addWidget(logo)
        lay.addSpacing(6)
        lay.addWidget(title)
        lay.addSpacing(10)
        lay.addWidget(sub)
        lay.addStretch()
        lay.addWidget(self.status_badge)
        lay.addSpacing(16)
        lay.addWidget(self.clock_lbl)
        return hdr

    # ══════════════════════════════════════
    # SIDEBAR
    # ══════════════════════════════════════
    def _make_sidebar(self):
        sb = QFrame()
        sb.setFixedWidth(200)
        sb.setStyleSheet(f"QFrame {{ background-color: {PANEL}; border-right: 1px solid {BORDER}; }}")
        lay = QVBoxLayout(sb)
        lay.setContentsMargins(0, 12, 0, 12)
        lay.setSpacing(2)

        def sec_lbl(txt):
            l = QLabel(f"  {txt}")
            l.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 2px; padding: 8px 0 3px 12px;")
            return l

        def nav(icon, txt, active=False):
            b = QPushButton(f"  {icon}  {txt}")
            b.setStyleSheet(f"""
                QPushButton {{
                    text-align: left; padding: 8px 12px; border: none;
                    border-left: 2px solid {'%s' % ACCENT if active else 'transparent'};
                    background: {'rgba(0,212,255,0.1)' if active else 'transparent'};
                    color: {'%s' % ACCENT if active else MUTED}; font-size: 13px;
                }}
                QPushButton:hover {{ background: rgba(0,212,255,0.06); color: {TEXT}; }}
            """)
            return b

        lay.addWidget(sec_lbl("NAVIGATION"))
        lay.addWidget(nav("⬡", "Dashboard", True))
        live_btn = nav("⚡", "Live Detection")
        live_btn.clicked.connect(lambda: self._switch_mode(demo=False))
        lay.addWidget(live_btn)

        qpso_btn = nav("◈", "QPSO Analysis")
        qpso_btn.clicked.connect(self._show_qpso)
        lay.addWidget(qpso_btn)

        reports_btn = nav("↓", "Reports")
        reports_btn.clicked.connect(self._show_results)
        lay.addWidget(reports_btn)
        reports_btn.clicked.connect(self._show_results)
        lay.addWidget(reports_btn)
        lay.addWidget(sec_lbl("DATASETS"))

        cic_btn = nav("▣", "CIC-IDS2017  ✓", True)
        cic_btn.clicked.connect(self._on_cic_click)
        lay.addWidget(cic_btn)

        custom_btn = nav("+", "Load Custom CSV")
        custom_btn.clicked.connect(self._load_custom_csv)
        lay.addWidget(custom_btn)
        lay.addWidget(sec_lbl("HELP"))
        about_btn = nav("ℹ", "About QNIDS")
        about_btn.clicked.connect(self._show_about)
        lay.addWidget(about_btn)
        lay.addStretch()

        box = QFrame()
        box.setStyleSheet(f"QFrame {{ background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 8px; margin: 8px; }}")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(12, 10, 12, 10)
        bl.setSpacing(3)
        t = QLabel("QPSO STATUS")
        t.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 1px;")
        v = QLabel("78 → 15 Features")
        v.setStyleSheet(f"color: {ACCENT}; font-size: 16px; font-weight: bold;")
        s = QLabel("80.8% dimensionality reduction")
        s.setStyleSheet(f"color: {MUTED}; font-size: 9px;")
        s.setWordWrap(True)
        bl.addWidget(t)
        bl.addWidget(v)
        bl.addWidget(s)
        lay.addWidget(box)
        return sb

    def _show_about(self):
        dialog = AboutDialog(parent=self)
        dialog.exec_()
        
    def _show_qpso(self):
        from qpso_analysis_dialog import QPSOAnalysisDialog
        dialog = QPSOAnalysisDialog(parent=self)
        dialog.exec_()
        
    def _on_cic_click(self):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(
        self,
        "Dataset Info",
        "CIC-IDS2017 — Active Dataset\n\n"
        "• Type: Modern Flow-Based Dataset\n"
        "• Features: 78 CIC-IDS2017 style features\n"
        "• Attack Types: DoS, DDoS, PortScan, "
        "BruteForce, WebAttack, Botnet\n"
        "• Model trained on: 377,390 flows\n"
        "• RF Accuracy: 99.93%\n"
        "• Macro F1: 99.63%\n\n"
        "This dataset is currently active and loaded."
    )

    def _load_custom_csv(self):
        """Load any custom CIC-IDS2017 format CSV in Demo mode."""
        filepath, _ = QFileDialog.getOpenFileName(
        self,
        "Load Custom CSV Dataset",
        "D:\\QNIDS-Project\\data",
        "CSV Files (*.csv);;All Files (*)"
    )
        if not filepath:
            return

        # Switch to demo mode first
        self._set_toggle_styles(active="demo")
        self.mode_lbl.setText("Mode: Custom CSV")
        self.mode_lbl.setStyleSheet(f"color: {PURPLE}; font-size: 11px;")
        self.status_badge.setText("● CUSTOM CSV")
        self.status_badge.setStyleSheet(f"""
        color: {PURPLE}; font-size: 11px; font-weight: bold;
        background: rgba(139,92,246,0.1);
        border: 1px solid rgba(139,92,246,0.3);
        border-radius: 10px; padding: 3px 12px;
    """)

        # Stop any running mode
        self.capturer.stop()
        self.simulator.stop()

    # Load and start
        if self.simulator.load_csv(filepath):
            self.simulator.start()
            self.live_badge.setText("● CUSTOM CSV")
            self.live_badge.setStyleSheet(f"""
            color: {PURPLE}; font-size: 10px; font-weight: bold;
            background: rgba(139,92,246,0.12);
            border: 1px solid rgba(139,92,246,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.information(
                self, "CSV Loaded",
                f"Custom CSV loaded successfully!\n\n"
                f"File: {filepath.split('/')[-1]}\n"
                f"Simulation started automatically."
        )
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "Load Failed",
               "CSV file could not be loaded.\n"
                "Make sure it is a valid CIC-IDS2017 format CSV."
        )
        
    def _show_results(self):
        from results_tab import ResultsDialog
        dialog = ResultsDialog(parent=self)
        dialog.exec_()

    # ══════════════════════════════════════
    # MAIN CONTENT
    # ══════════════════════════════════════
    def _make_content(self):
        frame = QFrame()
        frame.setStyleSheet(f"background: {BG};")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)
        lay.addWidget(self._make_input_bar())
        lay.addWidget(self._make_toggle_bar())
        lay.addLayout(self._make_metric_cards())
        lay.addWidget(self._make_feed_panel(), stretch=1)
        return frame

    def _make_input_bar(self):
        bar = QFrame()
        bar.setFixedHeight(48)
        bar.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px; }}")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)

        self.dataset_label = QLabel("Dataset:")
        self.dataset_label.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        self.dataset_selector = QPushButton("CIC-IDS2017 ▾")
        self.dataset_selector.setFixedWidth(140)
        self.dataset_selector.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 6px;
                color: {ACCENT}; font-size: 11px; font-weight: bold;
                padding: 5px 10px; text-align: left;
            }}
            QPushButton:hover {{ border-color: {ACCENT}; }}
        """)
        self.current_dataset = "CIC-IDS2017"

        self.speed_label = QLabel("Speed:")
        self.speed_label.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        self.speed_btn = QPushButton("Normal ▾")
        self.speed_btn.setFixedWidth(100)
        self.speed_btn.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 6px;
                color: {TEXT}; font-size: 11px; padding: 5px 10px; text-align: left;
            }}
            QPushButton:hover {{ border-color: {ACCENT}; }}
        """)
        self.speed_btn.clicked.connect(self._toggle_speed)
        self.current_speed = "Normal"
        self.speed_values  = {"Slow": 1.5, "Normal": 0.5, "Fast": 0.15}

        run_btn = QPushButton("▶  RUN DETECTION")
        run_btn.setFixedWidth(155)
        run_btn.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT}; color: #000; font-size: 12px;
                font-weight: bold; border-radius: 6px; padding: 7px; letter-spacing: 1px;
            }}
            QPushButton:hover {{ background: #33ddff; }}
        """)
        run_btn.clicked.connect(self._on_run)

        lay.addWidget(self.dataset_label)
        lay.addSpacing(4)
        lay.addWidget(self.dataset_selector)
        lay.addSpacing(16)
        lay.addWidget(self.speed_label)
        lay.addSpacing(4)
        lay.addWidget(self.speed_btn)
        lay.addStretch()
        lay.addWidget(run_btn)
        return bar

    def _make_toggle_bar(self):
        bar = QFrame()
        bar.setFixedHeight(44)
        bar.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        self.live_btn = QPushButton("🔵  LIVE MODE  —  Real Network Packets")
        self.demo_btn = QPushButton("🔴  DEMO MODE  —  CSV Attack Simulation")
        self.pcap_btn = QPushButton("📁  PCAP MODE  —  Upload & Analyze File")

        self._set_toggle_styles(active="live")

        self.live_btn.clicked.connect(lambda: self._switch_mode(demo=False))
        self.demo_btn.clicked.connect(lambda: self._switch_mode(demo=True))
        self.pcap_btn.clicked.connect(self._switch_to_pcap)

        lay.addWidget(self.live_btn)
        lay.addWidget(self.demo_btn)
        lay.addWidget(self.pcap_btn)
        return bar

    def _set_toggle_styles(self, active: str = "live"):
        """Highlight the active mode button. active: 'live' | 'demo' | 'pcap'"""
        configs = {
            "live": (self.live_btn, "#3b82f6", "rgba(59,130,246,0.2)"),
            "demo": (self.demo_btn, "#ef4444", "rgba(239,68,68,0.2)"),
            "pcap": (self.pcap_btn, "#8b5cf6", "rgba(139,92,246,0.2)"),
        }
        for btn in [self.live_btn, self.demo_btn, self.pcap_btn]:
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; border: 1.5px solid {BORDER};
                    border-radius: 8px; color: {MUTED}; font-size: 12px; padding: 8px;
                }}
                QPushButton:hover {{ background: rgba(255,255,255,0.04); color: {TEXT}; }}
            """)
        active_btn, color, bg = configs.get(active, configs["live"])
        active_btn.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; border: 1.5px solid {color};
                border-radius: 8px; color: {color};
                font-size: 12px; font-weight: bold; padding: 8px;
            }}
            QPushButton:hover {{ background: {bg}; color: {color}; }}
        """)

    def _switch_mode(self, demo: bool):
        self.is_demo_mode = demo
        self._set_toggle_styles(active="demo" if demo else "live")

        if demo:
            self.capturer.stop()
            self.feed_timer.stop()
            self.mode_lbl.setText("Mode: Demo/Simulation")
            self.mode_lbl.setStyleSheet(f"color: {RED}; font-size: 11px;")
            self.status_badge.setText("● DEMO MODE")
            self.status_badge.setStyleSheet(f"""
                color: {RED}; font-size: 11px; font-weight: bold;
                background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3);
                border-radius: 10px; padding: 3px 12px;
            """)
            self.live_badge.setText("⏺ DEMO")
            self.live_badge.setStyleSheet(f"""
                color: {RED}; font-size: 10px; font-weight: bold;
                background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
            self._load_and_start_csv()
        else:
            self.simulator.stop()
            self.feed_timer.stop()
            self.mode_lbl.setText("Mode: Live Network")
            self.mode_lbl.setStyleSheet(f"color: {PA}; font-size: 11px;")
            self.status_badge.setText("● LIVE CAPTURE")
            self.status_badge.setStyleSheet(f"""
                color: {PA}; font-size: 11px; font-weight: bold;
                background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.3);
                border-radius: 10px; padding: 3px 12px;
            """)
            self.live_badge.setText("● MONITORING")
            self.live_badge.setStyleSheet(f"""
                color: {PA}; font-size: 10px; font-weight: bold;
                background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
            self._add_monitoring_row()
            self.capturer = PacketCapture(callback=self._on_packet)
            self.capturer.start()

    def _switch_to_pcap(self):
        """Switch to PCAP Upload mode."""
        self.capturer.stop()
        self.simulator.stop()
        self._set_toggle_styles(active="pcap")
        self.mode_lbl.setText("Mode: PCAP Analysis")
        self.mode_lbl.setStyleSheet(f"color: {PURPLE}; font-size: 11px;")
        self.status_badge.setText("● PCAP MODE")
        self.status_badge.setStyleSheet(f"""
            color: {PURPLE}; font-size: 11px; font-weight: bold;
            background: rgba(139,92,246,0.1); border: 1px solid rgba(139,92,246,0.3);
            border-radius: 10px; padding: 3px 12px;
        """)
        self.live_badge.setText("📁 PCAP")
        self.live_badge.setStyleSheet(f"""
            color: {PURPLE}; font-size: 10px; font-weight: bold;
            background: rgba(139,92,246,0.12); border: 1px solid rgba(139,92,246,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)
        self._load_pcap_file()

    def _load_pcap_file(self):
        """Open file dialog and start PCAP processing in background."""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File",
            os.path.expanduser("~"),
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if not filepath:
            return

        self._progress_dlg = QProgressDialog(
            "Processing PCAP file...", "Cancel", 0, 100, self
        )
        self._progress_dlg.setWindowTitle("PCAP Analysis")
        self._progress_dlg.setMinimumWidth(360)
        self._progress_dlg.setAutoClose(True)
        self._progress_dlg.show()

        predict.load_models()
        self._pcap_thread = PcapProcessor(filepath)
        self._pcap_thread.flow_ready.connect(self.add_row)
        self._pcap_thread.progress.connect(self._progress_dlg.setValue)
        self._pcap_thread.finished_pcap.connect(self._on_pcap_done)
        self._pcap_thread.error.connect(self._on_pcap_error)
        self._progress_dlg.canceled.connect(self._pcap_thread.cancel)
        self._pcap_thread.start()

    def _on_pcap_done(self, flow_count: int):
        """Called when PCAP processing completes successfully."""
        self.live_badge.setText("✓ PCAP DONE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 10px; font-weight: bold;
            background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)
        QMessageBox.information(
            self, "PCAP Analysis Complete",
            f"Processing complete.\n{flow_count} network flows analyzed."
        )

    def _on_pcap_error(self, msg: str):
        """Called when PCAP processing encounters an error."""
        QMessageBox.warning(self, "PCAP Error", msg)

    def _add_monitoring_row(self):
        """Add a status row when live monitoring starts."""
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            "---", "Network Monitoring Active...",
            "● MONITORING", PA, 100
        )

    def _make_metric_cards(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        self.card_acc = MetricCard("Detection Accuracy", "99.93%", "RF Macro F1: 99.63%",ACCENT, "+11.83% vs baseline", True)
        self.card_fpr = MetricCard("False Positive Rate", "5.05%", "Isolation Forest Layer 2", RED, "Heartbleed: 100% detected", True)
        self.card_attacks = MetricCard("Attacks Detected",    "0",     "Current session",        GREEN,  "Live counting",     True)
        self.card_packets = MetricCard("Packets Analyzed",    "0",     "Processing speed",       PURPLE, "Active",            True)
        for c in [self.card_acc, self.card_fpr, self.card_attacks, self.card_packets]:
            row.addWidget(c)
        return row

    def _make_feed_panel(self):
        wrapper = QFrame()
        wrapper.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px; }}")
        lay = QVBoxLayout(wrapper)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        hdr = QFrame()
        hdr.setFixedHeight(40)
        hdr.setStyleSheet(f"background: {PANEL2}; border-bottom: 1px solid {BORDER}; border-radius: 10px 10px 0 0;")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(14, 0, 14, 0)

        feed_title = QLabel("LIVE DETECTION FEED")
        feed_title.setStyleSheet(f"color: {TEXT}; font-size: 12px; font-weight: bold; letter-spacing: 1px;")

        self.live_badge = QLabel("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 10px; font-weight: bold;
            background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)

        self.event_count_lbl = QLabel("0 events")
        self.event_count_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.setFixedWidth(80)
        self.pause_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER}; border-radius: 5px;
                color: {MUTED}; font-size: 11px; padding: 3px 8px; }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        self.pause_btn.clicked.connect(self._toggle_pause)

        clear_btn = QPushButton("✕ Clear")
        clear_btn.setFixedWidth(65)
        clear_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER}; border-radius: 5px;
                color: {MUTED}; font-size: 11px; padding: 3px 8px; }}
            QPushButton:hover {{ border-color: {RED}; color: {RED}; }}
        """)
        clear_btn.clicked.connect(self._clear_table)

        hl.addWidget(feed_title)
        hl.addSpacing(8)
        hl.addWidget(self.live_badge)
        hl.addStretch()
        hl.addWidget(self.event_count_lbl)
        hl.addSpacing(8)
        hl.addWidget(self.pause_btn)
        hl.addSpacing(4)
        hl.addWidget(clear_btn)
        lay.addWidget(hdr)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
    "Time", "Source IP", "Attack Type", "Decision", "RF Conf %", "IF Score"])
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 110)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(3, 105)
        self.table.setColumnWidth(4, 85)
        self.table.setColumnWidth(5, 80)
        self.table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background: {BG}; border: none; color: {TEXT}; font-size: 12px;
                gridline-color: rgba(30,48,72,0.5); outline: none; }}
            QHeaderView::section {{ background: {PANEL2}; color: {MUTED}; font-size: 9px;
                font-weight: bold; letter-spacing: 1px; padding: 7px 8px; border: none;
                border-right: 1px solid {BORDER}; border-bottom: 1px solid {BORDER}; }}
            QTableWidget::item {{ padding: 5px 8px; border-bottom: 1px solid rgba(30,48,72,0.4); }}
            QTableWidget::item:selected {{ background: rgba(0,212,255,0.08); color: {TEXT}; }}
            QScrollBar:vertical {{ background: {BG}; width: 5px; border-radius: 3px; }}
            QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 3px; }}
        """)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setDefaultSectionSize(34)
        lay.addWidget(self.table)
        return wrapper

    # ══════════════════════════════════════
    # RIGHT PANEL
    # ══════════════════════════════════════
    def _make_right_panel(self):
        rp = QFrame()
        rp.setFixedWidth(265)
        rp.setStyleSheet(f"QFrame {{ background: {PANEL}; border-left: 1px solid {BORDER}; }}")
        lay = QVBoxLayout(rp)
        lay.setContentsMargins(12, 14, 12, 14)
        lay.setSpacing(12)

        def sec(txt):
            l = QLabel(txt)
            l.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 1.5px;")
            return l

        lay.addWidget(sec("ACTIVE MODELS"))
        for name, acc, color, active in [
            ("Hybrid RF+QPSO", "94.2%", ACCENT, True),
            ("Isolation Forest", "—",   PURPLE, True),
            ("Decision Tree",  "85.7%", MUTED,  False),
        ]:
            row = QFrame()
            row.setStyleSheet(f"background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 6px;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 5, 8, 5)
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; font-size: 10px;")
            nm = QLabel(name)
            nm.setStyleSheet(f"color: {'%s' % TEXT if active else MUTED}; font-size: 11px;")
            ac = QLabel(acc)
            ac.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
            rl.addWidget(dot)
            rl.addWidget(nm, stretch=1)
            rl.addWidget(ac)
            lay.addWidget(row)

        lay.addWidget(sec("ATTACK DISTRIBUTION"))
        self.pie_chart = AttackPieChart()
        self.pie_chart.setFixedHeight(320)
        self.pie_chart.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;")
        lay.addWidget(self.pie_chart)

        lay.addStretch()
        lay.addWidget(sec("EXPORT"))

        pdf_btn = QPushButton("↓  Export PDF")
        pdf_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER}; border-radius: 6px;
                color: {MUTED}; font-size: 11px; padding: 6px; }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        pdf_btn.clicked.connect(self._export_pdf)

        csv_btn = QPushButton("↓  Export CSV")
        csv_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER}; border-radius: 6px;
                color: {MUTED}; font-size: 11px; padding: 6px; }}
            QPushButton:hover {{ border-color: {GREEN}; color: {GREEN}; }}
        """)
        csv_btn.clicked.connect(self._export_csv)

        lay.addWidget(pdf_btn)
        lay.addWidget(csv_btn)
        return rp

    # ══════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════
    def _get_exporter(self):
        return ExportManager(
            table_widget=self.table,
            accuracy=self.card_acc.val.text(),
            fpr=self.card_fpr.val.text(),
            attacks=self.attack_count,
            packets=self.packet_count,
            pie_counts=self.pie_chart.counts
        )

    def _export_pdf(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report",
            os.path.join(os.path.expanduser("~"), "Desktop",
                         f"QNIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"),
            "PDF Files (*.pdf)"
        )
        if not filepath:
            return
        result = self._get_exporter().export_pdf(filepath)
        if result:
            QMessageBox.information(self, "Export Complete", f"PDF saved!\n\n{filepath}")
        else:
            QMessageBox.warning(self, "Export Failed", "PDF export failed. Check console.")

    def _export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save CSV Report",
            os.path.join(os.path.expanduser("~"), "Desktop",
                         f"QNIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"),
            "CSV Files (*.csv)"
        )
        if not filepath:
            return
        result = self._get_exporter().export_csv(filepath)
        if result:
            QMessageBox.information(self, "Export Complete", f"CSV saved!\n\n{filepath}")
        else:
            QMessageBox.warning(self, "Export Failed", "CSV export failed. Check console.")

    # ══════════════════════════════════════
    # STATUS BAR
    # ══════════════════════════════════════
    def _make_statusbar(self):
        bar = QFrame()
        bar.setFixedHeight(28)
        bar.setStyleSheet(f"QFrame {{ background: {PANEL}; border-top: 1px solid {BORDER}; }}")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(20)

        self.sys_lbl  = QLabel("● System Ready")
        self.sys_lbl.setStyleSheet(f"color: {GREEN}; font-size: 11px;")
        self.mode_lbl = QLabel("Mode: Live Network")
        self.mode_lbl.setStyleSheet(f"color: {PA}; font-size: 11px;")
        self.pkt_lbl  = QLabel("Packets: 0")
        self.pkt_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        dataset_lbl   = QLabel("CIC-IDS2017 Loaded")
        dataset_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px;")
        ver = QLabel("QNIDS v1.0  ·  CIC-IDS2017  ·  QPSO+RF+IF")
        ver.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        lay.addWidget(self.sys_lbl)
        lay.addWidget(self.mode_lbl)
        lay.addWidget(self.pkt_lbl)
        lay.addWidget(dataset_lbl)
        lay.addStretch()
        lay.addWidget(ver)
        return bar

    # ══════════════════════════════════════
    # PACKET CALLBACK
    # ══════════════════════════════════════
    def _on_packet(self, ts, ip, info, verdict, color, conf, if_score=0.0):
        if self.is_paused:
            return
        self.packet_count += 1
        display = (f"{self.packet_count/1000:.1f}K"
               if self.packet_count >= 1000
               else str(self.packet_count))
        self.card_packets.update_value(display)
        self.pkt_lbl.setText(f"Packets: {display}")
        self._sig.packet_received.emit(ts, ip, info, verdict, color, conf, if_score)

    # ══════════════════════════════════════
    # TABLE
    # ══════════════════════════════════════
    def add_row(self, timestamp, ip, attack_type,
            verdict, verdict_color, confidence, if_score=0.0):
      self.table.insertRow(0)

    # Col 0 — Time
      t = QTableWidgetItem(timestamp)
      t.setForeground(QColor(MUTED))
      t.setFont(QFont("Courier New", 10))
      t.setTextAlignment(Qt.AlignCenter)
      self.table.setItem(0, 0, t)

    # Col 1 — Source IP
      ip_i = QTableWidgetItem(ip)
      ip_i.setForeground(QColor(TEXT))
      ip_i.setFont(QFont("Courier New", 10))
      ip_i.setTextAlignment(Qt.AlignCenter)
      self.table.setItem(0, 1, ip_i)

    # Col 2 — Attack Type
      at = QTableWidgetItem(f"  {attack_type}")
      if "Normal" in attack_type or "NORMAL" in attack_type:
        at.setForeground(QColor(GREEN))
      elif "Unknown" in attack_type or "UNKNOWN" in attack_type:
        at.setForeground(QColor(ORANGE))
      elif "MONITORING" in attack_type:
        at.setForeground(QColor(PA))
      else:
        at.setForeground(QColor(RED))
      self.table.setItem(0, 2, at)

    # Col 3 — Decision badge
      if "NORMAL" in verdict:
        decision_text  = "● NORMAL"
        decision_color = GREEN
      elif "ATTACK" in verdict:
        decision_text  = "▲ ATTACK"
        decision_color = RED
      elif "MONITORING" in verdict:
        decision_text  = "● MONITOR"
        decision_color = PA
      else:
        decision_text  = "◆ SUSPICIOUS"
        decision_color = ORANGE

      vd = QTableWidgetItem(decision_text)
      vd.setForeground(QColor(decision_color))
      vd.setFont(QFont("Arial", 10, QFont.Bold))
      vd.setTextAlignment(Qt.AlignCenter)
      self.table.setItem(0, 3, vd)

    # Col 4 — RF Confidence %
      cf = QTableWidgetItem(f"{confidence}%")
      cf_color = (GREEN  if confidence >= 85
                else ORANGE if confidence >= 70
                else RED)
      cf.setForeground(QColor(cf_color))
      cf.setFont(QFont("Courier New", 10, QFont.Bold))
      cf.setTextAlignment(Qt.AlignCenter)
      self.table.setItem(0, 4, cf)

    # Col 5 — IF Score
      if if_score < -0.20:
        if_color = RED        # anomalous — zero-day risk
      elif if_score < 0:
        if_color = ORANGE     # borderline
      else:
        if_color = GREEN      # normal range

      if_item = QTableWidgetItem(f"{if_score:+.3f}")
      if_item.setForeground(QColor(if_color))
      if_item.setFont(QFont("Courier New", 10))
      if_item.setTextAlignment(Qt.AlignCenter)
      self.table.setItem(0, 5, if_item)

    # Row background alternate
      row_bg = QColor("#0d1520" if self.row_count % 2 == 0 else "#0a0f1a")
      for col in range(6):
        item = self.table.item(0, col)
        if item:
            item.setBackground(row_bg)

    # Max 100 rows
      if self.table.rowCount() > 100:
        self.table.removeRow(self.table.rowCount() - 1)

    # Counters
      self.row_count += 1
      if verdict_color in (RED, ORANGE):
        self.attack_count += 1
        self.card_attacks.update_value(str(self.attack_count))

      self.event_count_lbl.setText(f"{self.row_count} events")
      self._trigger_alert(attack_type, verdict, verdict_color,
                        confidence, timestamp, ip)
      self.pie_chart.update_counts(attack_type, verdict)

    def _trigger_alert(self, attack_type, verdict, color,
                   confidence, ts, ip, if_score=0.0):
     import time
     if "NORMAL" in verdict:
        return

     decision = ("KNOWN_ATTACK" if "ATTACK" in verdict
                else "SUSPICIOUS")

     if "UNKNOWN" in verdict or "ATTACK" in verdict:
        now = time.time()
        if not self._popup_open and \
           (now - self._last_unknown_time) > 30:
            self._last_unknown_time = now
            self._popup_open        = True
            if "UNKNOWN" in verdict:
                play_unknown_sound()
            else:
                play_attack_sound()
            self._show_unknown_popup(
                attack_type, ip, ts,
                confidence, if_score, decision
            )
        elif "ATTACK" in verdict and confidence >= 85:
            play_attack_sound()

    def _show_unknown_popup(self, attack_info, ip, ts,
                        confidence=0, if_score=0.0,
                        decision="SUSPICIOUS"):
     popup = UnknownThreatPopup(
        parent=self, attack_info=attack_info,
        ip=ip, ts=ts, confidence=confidence,
        protocol="TCP", if_score=if_score,
        decision=decision
                         )
     popup.finished.connect(lambda: setattr(self, '_popup_open', False))
     popup.move(
            self.x() + (self.width()  - popup.width())  // 2,
            self.y() + (self.height() - popup.height()) // 2
         )
     popup.show()

    def _auto_add_row(self):
        if self.is_paused:
            return
        attack_type, verdict, color, conf = rnd_event()
        conf = max(60, min(99, conf + random.randint(-4, 4)))
        self.add_row(datetime.now().strftime("%H:%M:%S"),
                     rnd_ip(), attack_type, verdict, color, conf)

    def _clear_table(self):
        self.table.setRowCount(0)
        self.row_count    = 0
        self.attack_count = 0
        self.event_count_lbl.setText("0 events")
        self.card_attacks.update_value("0")

    # ══════════════════════════════════════
    # TIMERS + CONTROLS
    # ══════════════════════════════════════
    def _update_packets(self):
        self.packet_count += random.randint(6, 14)
        display = (f"{self.packet_count/1000:.1f}K"
                   if self.packet_count >= 1000
                   else str(self.packet_count))
        self.card_packets.update_value(display)
        self.pkt_lbl.setText(f"Packets: {display}")

    def _update_clock(self):
        self.clock_lbl.setText(datetime.now().strftime("%H:%M:%S"))

    def _on_run(self):
        self.is_paused = False
        self.pause_btn.setText("⏸ Pause")
        self.live_badge.setText("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 10px; font-weight: bold;
            background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)

    def _toggle_speed(self):
        speeds = ["Slow", "Normal", "Fast"]
        self.current_speed = speeds[(speeds.index(self.current_speed) + 1) % 3]
        colors = {"Slow": MUTED, "Normal": TEXT, "Fast": GREEN}
        color  = colors[self.current_speed]
        self.speed_btn.setText(f"{self.current_speed} ▾")
        self.speed_btn.setStyleSheet(f"""
            QPushButton {{ background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 6px;
                color: {color}; font-size: 11px; font-weight: bold;
                padding: 5px 10px; text-align: left; }}
            QPushButton:hover {{ border-color: {ACCENT}; }}
        """)
        self.simulator.set_speed(self.speed_values[self.current_speed])

    def _load_and_start_csv(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select CSV File",
            "D:\\QNIDS-Project\\data",
            "CSV/Text Files (*.csv *.txt);;All Files (*)"
        )
        if not filepath:
            print("No file selected")
            return
        if self.simulator.load_csv(filepath):
            self.simulator.start()
            self.live_badge.setText("● SIMULATING")
            self.live_badge.setStyleSheet(f"""
                color: {RED}; font-size: 10px; font-weight: bold;
                background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
            print("Simulation started!")
        else:
            print("CSV load failed")

    def _toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_btn.setText("▶ Resume")
            self.live_badge.setText("⏸ PAUSED")
            self.live_badge.setStyleSheet(f"""
                color: {ORANGE}; font-size: 10px; font-weight: bold;
                background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
            self.simulator.pause()
        else:
            self.pause_btn.setText("⏸ Pause")
            self.live_badge.setText("● LIVE")
            self.live_badge.setStyleSheet(f"""
                color: {GREEN}; font-size: 10px; font-weight: bold;
                background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
            self.simulator.resume()

    def _load_unsw_model(self):
        try:
            self.simulator.predictor.load_unsw_model()
            self.sys_lbl.setText("● UNSW-NB15 Active")
            self.sys_lbl.setStyleSheet(f"color: {PURPLE}; font-size: 11px;")
        except Exception as e:
            print(f"Model load error: {e}")

    def _load_nslkdd_model(self):
        try:
            self.simulator.predictor.load_nslkdd_model()
            self.sys_lbl.setText("● System Ready")
            self.sys_lbl.setStyleSheet(f"color: {GREEN}; font-size: 11px;")
        except Exception as e:
            print(f"Model load error: {e}")

    def closeEvent(self, event):
        self.capturer.stop()
        self.simulator.stop()
        event.accept()


# ══════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    splash = LoadingScreen()
    splash.show()
    app.processEvents()

    window = QNIDSMainWindow()
    splash.finish(window)
    window.show()

    sys.exit(app.exec_())