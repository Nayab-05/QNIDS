from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame
)
from PyQt5.QtCore import Qt

BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
ACCENT = "#00d4ff"
GREEN  = "#10b981"
PURPLE = "#8b5cf6"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"


class AboutDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About QNIDS")
        self.setFixedSize(460, 420)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG};
                border: 1px solid {BORDER};
            }}
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header
        header = QFrame()
        header.setFixedHeight(110)
        header.setStyleSheet(f"""
            background: {PANEL};
            border-bottom: 2px solid {ACCENT};
        """)
        hl = QVBoxLayout(header)
        hl.setAlignment(Qt.AlignCenter)
        hl.setSpacing(6)

        logo = QLabel("⬡  QNIDS")
        logo.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 28px;
            font-weight: bold;
            letter-spacing: 4px;
        """)
        logo.setAlignment(Qt.AlignCenter)

        sub = QLabel(
            "Quantum-Inspired Network Intrusion Detection System"
        )
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        sub.setAlignment(Qt.AlignCenter)

        badge_row = QHBoxLayout()
        badge_row.setAlignment(Qt.AlignCenter)
        badge_row.setSpacing(8)

        for txt, color in [
            ("QPSO", ACCENT),
            ("Random Forest", GREEN),
            ("Isolation Forest", PURPLE),
        ]:
            b = QLabel(txt)
            b.setStyleSheet(f"""
                color: {color};
                font-size: 9px;
                font-weight: bold;
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 4px;
                padding: 2px 8px;
            """)
            badge_row.addWidget(b)

        badge_widget = QFrame()
        badge_widget.setStyleSheet("background: transparent;")
        QHBoxLayout(badge_widget).addLayout(badge_row)

        hl.addWidget(logo)
        hl.addWidget(sub)
        hl.addWidget(badge_widget)
        layout.addWidget(header)

        # ── Info section
        info = QFrame()
        info.setStyleSheet(f"background: {PANEL};")
        il = QVBoxLayout(info)
        il.setContentsMargins(30, 18, 30, 18)
        il.setSpacing(10)

        fields = [
            ("Version",    "1.0.0",                          TEXT),
            ("Project",    "Final Year Project — BSCS",      TEXT),
            ("University", "University of Azad Jammu & Kashmir", ACCENT),
            ("Session",    "2022 – 2026",                    TEXT),
            ("Supervisor", "________________",               TEXT),
            ("Team",       "Anita  |  Nayab",               GREEN),
            ("Algorithm",  "QPSO + Random Forest (Layer 1)", TEXT),
            ("Layer 2",    "Isolation Forest (Zero-Day)",    TEXT),
            ("Dataset",    "CIC-IDS2017 (Modern Flow-Based)",ACCENT),
            ("Accuracy",   "99.93%  |  Macro F1: 99.63%",   GREEN),
        ]

        for label, value, color in fields:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(95)
            lbl.setStyleSheet(
                f"color: {MUTED}; font-size: 11px; font-weight: bold;"
            )
            val = QLabel(value)
            val.setStyleSheet(f"color: {color}; font-size: 11px;")
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            il.addLayout(row)

        layout.addWidget(info, stretch=1)

        # ── Footer
        footer = QFrame()
        footer.setFixedHeight(50)
        footer.setStyleSheet(f"""
            background: {PANEL2};
            border-top: 1px solid {BORDER};
        """)
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(20, 0, 20, 0)

        copy_lbl = QLabel("© 2026 QNIDS Team — UAJK BSCS")
        copy_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(80)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT}; color: #000;
                font-weight: bold; border-radius: 6px;
                padding: 6px; font-size: 11px;
            }}
            QPushButton:hover {{ background: #33ddff; }}
        """)
        close_btn.clicked.connect(self.close)

        fl.addWidget(copy_lbl)
        fl.addStretch()
        fl.addWidget(close_btn)
        layout.addWidget(footer)