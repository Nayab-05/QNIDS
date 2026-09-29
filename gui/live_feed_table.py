import sys
import random
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QFrame, QHeaderView
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont

# ── Colors
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

# ── Sample data — jab CSV nahi hai toh yeh use hoga test ke liye
SAMPLE_ATTACKS = [
    ("DoS Attack",      "🔴 ATTACK",   RED,    92),
    ("Normal Traffic",  "🟢 NORMAL",   GREEN,  98),
    ("Probe",           "🔴 ATTACK",   RED,    87),
    ("DDoS",            "🔴 ATTACK",   RED,    95),
    ("Normal Traffic",  "🟢 NORMAL",   GREEN,  99),
    ("⚠ Unknown Threat","🟠 UNKNOWN",  ORANGE, 74),
    ("R2L Attempt",     "🔴 ATTACK",   RED,    83),
    ("Normal Traffic",  "🟢 NORMAL",   GREEN,  97),
    ("Port Scan",       "🔴 ATTACK",   RED,    91),
    ("U2R Attempt",     "🔴 ATTACK",   RED,    88),
]

SAMPLE_IPS = [
    "192.168.1.", "10.0.0.",
    "172.16.0.", "203.0.113."
]

def random_ip():
    return random.choice(SAMPLE_IPS) + str(random.randint(1, 254))

def random_event():
    return random.choice(SAMPLE_ATTACKS)


class LiveFeedTable(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QNIDS — Live Feed Table Test")
        self.setMinimumSize(900, 600)
        self.setStyleSheet(f"background-color: {BG}; color: {TEXT};")

        self.is_paused = False
        self.row_count = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Table panel
        layout.addWidget(self.make_table_panel())

        # Test buttons — sirf testing ke liye
        layout.addWidget(self.make_test_buttons())

        # Auto-add rows timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.add_random_row)
        self.timer.start(1500)  # har 1.5 second mein ek row

    # ─────────────────────────────────────
    # TABLE PANEL BANANA
    # ─────────────────────────────────────
    def make_table_panel(self):
        wrapper = QFrame()
        wrapper.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
        """)
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header bar
        layout.addWidget(self.make_table_header())

        # ── Actual table
        layout.addWidget(self.make_table())

        return wrapper

    def make_table_header(self):
        hdr = QFrame()
        hdr.setFixedHeight(42)
        hdr.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL2};
                border-bottom: 1px solid {BORDER};
                border-radius: 10px 10px 0 0;
            }}
        """)
        layout = QHBoxLayout(hdr)
        layout.setContentsMargins(16, 0, 16, 0)

        # Title
        title = QLabel("LIVE DETECTION FEED")
        title.setStyleSheet(f"""
            color: {TEXT};
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 1px;
        """)

        # Live badge
        self.live_badge = QLabel("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN};
            font-size: 10px;
            font-weight: bold;
            background: rgba(16,185,129,0.12);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px;
            padding: 2px 10px;
        """)

        # Event counter
        self.counter_label = QLabel("0 events")
        self.counter_label.setStyleSheet(f"""
            color: {MUTED};
            font-size: 11px;
        """)

        # Pause button
        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.setFixedWidth(80)
        self.pause_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 5px;
                color: {MUTED};
                font-size: 11px;
                padding: 3px 8px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
                color: {ACCENT};
            }}
        """)
        self.pause_btn.clicked.connect(self.toggle_pause)

        # Clear button
        clear_btn = QPushButton("✕ Clear")
        clear_btn.setFixedWidth(70)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 5px;
                color: {MUTED};
                font-size: 11px;
                padding: 3px 8px;
            }}
            QPushButton:hover {{
                border-color: {RED};
                color: {RED};
            }}
        """)
        clear_btn.clicked.connect(self.clear_table)

        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(self.live_badge)
        layout.addStretch()
        layout.addWidget(self.counter_label)
        layout.addSpacing(8)
        layout.addWidget(self.pause_btn)
        layout.addSpacing(4)
        layout.addWidget(clear_btn)

        return hdr

    def make_table(self):
        self.table = QTableWidget()

        # ── 5 columns set karo
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Time",
            "Source IP",
            "Attack Type",
            "Verdict",
            "Confidence"
        ])

        # ── Column widths
        self.table.setColumnWidth(0, 90)   # Time
        self.table.setColumnWidth(1, 130)  # Source IP
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.Stretch          # Attack Type — stretch
        )
        self.table.setColumnWidth(3, 100)  # Verdict
        self.table.setColumnWidth(4, 100)  # Confidence

        # ── Styling
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {BG};
                border: none;
                color: {TEXT};
                font-size: 12px;
                gridline-color: rgba(30,48,72,0.5);
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {PANEL2};
                color: {MUTED};
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 1px;
                padding: 7px 8px;
                border: none;
                border-right: 1px solid {BORDER};
                border-bottom: 1px solid {BORDER};
                text-transform: uppercase;
            }}
            QTableWidget::item {{
                padding: 5px 8px;
                border-bottom: 1px solid rgba(30,48,72,0.4);
            }}
            QTableWidget::item:selected {{
                background-color: rgba(0,212,255,0.08);
                color: {TEXT};
            }}
            QScrollBar:vertical {{
                background: {BG};
                width: 5px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 3px;
            }}
        """)

        # ── Settings
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setDefaultSectionSize(36)

        return self.table

    # ─────────────────────────────────────
    # ROW ADD KARNA — Yeh main function hai
    # ─────────────────────────────────────
    def add_row(self, timestamp, ip, attack_type,
                verdict, verdict_color, confidence):
        """
        Ek naya row table mein add karta hai — top pe
        """
        # Table mein new row insert karo — position 0 (top pe)
        self.table.insertRow(0)

        # ── Column 0: Time
        time_item = QTableWidgetItem(timestamp)
        time_item.setForeground(QColor(MUTED))
        time_item.setFont(QFont("Courier New", 10))
        time_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 0, time_item)

        # ── Column 1: Source IP
        ip_item = QTableWidgetItem(ip)
        ip_item.setForeground(QColor(TEXT))
        ip_item.setFont(QFont("Courier New", 10))
        ip_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 1, ip_item)

        # ── Column 2: Attack Type
        attack_item = QTableWidgetItem(f"  {attack_type}")
        if "Normal" in attack_type:
            attack_item.setForeground(QColor(GREEN))
        elif "Unknown" in attack_type:
            attack_item.setForeground(QColor(ORANGE))
        else:
            attack_item.setForeground(QColor(RED))
        self.table.setItem(0, 2, attack_item)

        # ── Column 3: Verdict
        verdict_item = QTableWidgetItem(verdict)
        verdict_item.setForeground(QColor(verdict_color))
        verdict_item.setFont(QFont("Arial", 11, QFont.Bold))
        verdict_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 3, verdict_item)

        # ── Column 4: Confidence
        conf_item = QTableWidgetItem(f"{confidence}%")
        if confidence >= 90:
            conf_item.setForeground(QColor(GREEN))
        elif confidence >= 75:
            conf_item.setForeground(QColor(ORANGE))
        else:
            conf_item.setForeground(QColor(RED))
        conf_item.setFont(QFont("Courier New", 10, QFont.Bold))
        conf_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 4, conf_item)

        # ── Row color — background
        row_bg = QColor("#0d1520") if self.row_count % 2 == 0 else QColor("#0a0f1a")
        for col in range(5):
            item = self.table.item(0, col)
            if item:
                item.setBackground(row_bg)

        # ── Max 100 rows rakho — purane delete karo
        if self.table.rowCount() > 100:
            self.table.removeRow(self.table.rowCount() - 1)

        # ── Counter update karo
        self.row_count += 1
        self.counter_label.setText(f"{self.row_count} events")

    def add_random_row(self):
        """Timer se call hota hai — random test data add karta hai"""
        if self.is_paused:
            return

        attack_type, verdict, color, conf = random_event()
        timestamp = datetime.now().strftime("%H:%M:%S")
        ip = random_ip()

        # Confidence thoda vary karo
        conf_vary = conf + random.randint(-5, 5)
        conf_vary = max(60, min(99, conf_vary))

        self.add_row(timestamp, ip, attack_type,
                     verdict, color, conf_vary)

    # ─────────────────────────────────────
    # BUTTONS
    # ─────────────────────────────────────
    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_btn.setText("▶ Resume")
            self.live_badge.setText("⏸ PAUSED")
            self.live_badge.setStyleSheet(f"""
                color: {ORANGE};
                font-size: 10px;
                font-weight: bold;
                background: rgba(245,158,11,0.12);
                border: 1px solid rgba(245,158,11,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)
        else:
            self.pause_btn.setText("⏸ Pause")
            self.live_badge.setText("● LIVE")
            self.live_badge.setStyleSheet(f"""
                color: {GREEN};
                font-size: 10px;
                font-weight: bold;
                background: rgba(16,185,129,0.12);
                border: 1px solid rgba(16,185,129,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)

    def clear_table(self):
        self.table.setRowCount(0)
        self.row_count = 0
        self.counter_label.setText("0 events")

    def make_test_buttons(self):
        """Sirf testing ke liye — baad mein hata dena"""
        bar = QFrame()
        bar.setFixedHeight(40)
        bar.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)

        info = QLabel(
            "Pause/Resume/Clear test."
        )
        info.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        layout.addWidget(info)

        # Manual attack inject button
        attack_btn = QPushButton("🔴 Inject Attack")
        attack_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(239,68,68,0.15);
                border: 1px solid {RED};
                border-radius: 6px;
                color: {RED};
                font-size: 11px;
                padding: 5px 14px;
            }}
            QPushButton:hover {{ background: rgba(239,68,68,0.25); }}
        """)
        attack_btn.clicked.connect(self.inject_attack)

        # Manual unknown inject
        unknown_btn = QPushButton("🟠 Inject Unknown")
        unknown_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(245,158,11,0.15);
                border: 1px solid {ORANGE};
                border-radius: 6px;
                color: {ORANGE};
                font-size: 11px;
                padding: 5px 14px;
            }}
            QPushButton:hover {{ background: rgba(245,158,11,0.25); }}
        """)
        unknown_btn.clicked.connect(self.inject_unknown)

        layout.addStretch()
        layout.addWidget(attack_btn)
        layout.addSpacing(6)
        layout.addWidget(unknown_btn)

        return bar

    def inject_attack(self):
        """Manual attack inject karo — button se"""
        attacks = [
            ("DoS Attack",   "🔴 ATTACK", RED,    94),
            ("DDoS",         "🔴 ATTACK", RED,    91),
            ("Port Scan",    "🔴 ATTACK", RED,    88),
            ("R2L Attempt",  "🔴 ATTACK", RED,    85),
        ]
        attack_type, verdict, color, conf = random.choice(attacks)
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            random_ip(), attack_type, verdict, color, conf
        )

    def inject_unknown(self):
        """Unknown threat inject karo"""
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            random_ip(),
            "⚠ Unknown Threat",
            "🟠 UNKNOWN",
            ORANGE, 73
        )


# ── Run
app = QApplication(sys.argv)
window = LiveFeedTable()
window.show()
sys.exit(app.exec_())