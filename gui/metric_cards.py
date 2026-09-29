import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QFrame, QPushButton
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QFont
import random

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


class MetricCard(QFrame):
    """
    Ek single metric card — reusable component hai
    """
    def __init__(self, label, value, subtitle,
                 color, trend="", trend_up=True):
        super().__init__()

        self.color = color
        self._current_value = value

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-top: 2px solid {color};
                border-radius: 10px;
            }}
        """)
        self.setMinimumHeight(110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        # ── Label (upar chhota)
        self.label_widget = QLabel(label.upper())
        self.label_widget.setStyleSheet(f"""
            color: {MUTED};
            font-size: 9px;
            font-weight: bold;
            letter-spacing: 1.5px;
        """)

        # ── Main value (bada number)
        self.value_widget = QLabel(value)
        self.value_widget.setStyleSheet(f"""
            color: {color};
            font-size: 30px;
            font-weight: bold;
        """)

        # ── Subtitle (neeche chhota)
        self.sub_widget = QLabel(subtitle)
        self.sub_widget.setStyleSheet(f"""
            color: {MUTED};
            font-size: 10px;
        """)

        # ── Trend (corner mein)
        if trend:
            trend_color = GREEN if trend_up else RED
            trend_symbol = "▲" if trend_up else "▼"
            self.trend_widget = QLabel(
                f"{trend_symbol} {trend}"
            )
            self.trend_widget.setStyleSheet(f"""
                color: {trend_color};
                font-size: 10px;
                font-weight: bold;
            """)
            self.trend_widget.setAlignment(Qt.AlignRight)
        else:
            self.trend_widget = None

        layout.addWidget(self.label_widget)
        layout.addWidget(self.value_widget)
        layout.addWidget(self.sub_widget)
        if self.trend_widget:
            layout.addWidget(self.trend_widget)

    def update_value(self, new_value):
        """Card ka value update karo"""
        self.value_widget.setText(new_value)


class MetricCardsRow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QNIDS — Metric Cards Test")
        self.setMinimumSize(900, 300)
        self.setStyleSheet(f"background-color: {BG};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # ── Title
        title = QLabel("Dashboard Metrics — Live Update Test")
        title.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 14px;
            font-weight: bold;
        """)
        layout.addWidget(title)

        # ── 4 Cards row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        # Card 1 — Accuracy
        self.card_accuracy = MetricCard(
            label    = "Detection Accuracy",
            value    = "94.2%",
            subtitle = "Hybrid QPSO+RF Model",
            color    = ACCENT,
            trend    = "+6.1% vs baseline",
            trend_up = True
        )

        # Card 2 — False Positive Rate
        self.card_fpr = MetricCard(
            label    = "False Positive Rate",
            value    = "4.8%",
            subtitle = "vs 12.3% Classical RF",
            color    = RED,
            trend    = "−7.5% improvement",
            trend_up = True
        )

        # Card 3 — Attacks Detected
        self.card_attacks = MetricCard(
            label    = "Attacks Detected",
            value    = "0",
            subtitle = "Current session",
            color    = GREEN,
            trend    = "Live counting",
            trend_up = True
        )

        # Card 4 — Packets Analyzed
        self.card_packets = MetricCard(
            label    = "Packets Analyzed",
            value    = "0",
            subtitle = "Processing speed",
            color    = PURPLE,
            trend    = "Active",
            trend_up = True
        )

        cards_row.addWidget(self.card_accuracy)
        cards_row.addWidget(self.card_fpr)
        cards_row.addWidget(self.card_attacks)
        cards_row.addWidget(self.card_packets)

        layout.addLayout(cards_row)

        # ── Test buttons
        layout.addWidget(self.make_test_buttons())
        layout.addStretch()

        # ── Counters for live update
        self.attack_count  = 0
        self.packet_count  = 0

        # ── Timer — packets counter update karo
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_counters)
        self.timer.start(800)

    def update_counters(self):
        """
        Har 0.8 second mein counters update karo
        Jab real model connect hoga — yeh values
        model se aayengi
        """
        # Packets always barh rahe hain
        self.packet_count += random.randint(5, 15)

        # Kabhi kabhi attack aa jaata hai
        if random.random() < 0.3:
            self.attack_count += 1

        # Format karo
        if self.packet_count >= 1000:
            pkt_display = f"{self.packet_count/1000:.1f}K"
        else:
            pkt_display = str(self.packet_count)

        # Cards update karo
        self.card_attacks.update_value(
            str(self.attack_count)
        )
        self.card_packets.update_value(pkt_display)

    def make_test_buttons(self):
        bar = QFrame()
        bar.setFixedHeight(44)
        bar.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)

        info = QLabel(
            "Cards automatically update "
            "— packets aur attacks live count ho rahe hain"
        )
        info.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        # Simulate attack button
        atk_btn = QPushButton("+ Simulate Attack")
        atk_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(239,68,68,0.15);
                border: 1px solid {RED};
                border-radius: 6px;
                color: {RED};
                font-size: 11px;
                padding: 6px 14px;
            }}
            QPushButton:hover {{
                background: rgba(239,68,68,0.25);
            }}
        """)
        atk_btn.clicked.connect(self.simulate_attack)

        # Reset button
        reset_btn = QPushButton("↺ Reset")
        reset_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {MUTED};
                font-size: 11px;
                padding: 6px 14px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
                color: {ACCENT};
            }}
        """)
        reset_btn.clicked.connect(self.reset_counters)

        layout.addWidget(info)
        layout.addStretch()
        layout.addWidget(atk_btn)
        layout.addSpacing(6)
        layout.addWidget(reset_btn)

        return bar

    def simulate_attack(self):
        self.attack_count += 1
        self.card_attacks.update_value(
            str(self.attack_count)
        )

    def reset_counters(self):
        self.attack_count = 0
        self.packet_count = 0
        self.card_attacks.update_value("0")
        self.card_packets.update_value("0")


# ── Run
app = QApplication(sys.argv)
window = MetricCardsRow()
window.show()
sys.exit(app.exec_())

