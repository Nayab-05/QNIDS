"""
qpso_analysis_dialog.py — QPSO Feature Selection Visual Analysis
Shows selected features, importance bars, algorithm overview,
and convergence simulation for FYP demonstration.
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QScrollArea, QWidget, QGridLayout
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QImage, QFont

# ── Theme
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

# ── QPSO Selected Features (RF Layer 1 — from Partner A)
RF_FEATURES = [
    ("Flow Bytes/s",             0.187, ACCENT),
    ("Fwd Packet Length Mean",   0.156, GREEN),
    ("Average Packet Size",      0.142, GREEN),
    ("Packet Length Variance",   0.128, ORANGE),
    ("Total Length of Bwd Pkts", 0.103, ORANGE),
    ("Avg Fwd Segment Size",     0.091, PURPLE),
    ("Flow Duration",            0.074, PURPLE),
    ("Fwd Packet Length Min",    0.062, ACCENT),
    ("Fwd IAT Min",              0.051, GREEN),
    ("Destination Port",         0.043, ORANGE),
    ("RST Flag Count",           0.038, RED),
    ("Init_Win_bytes_forward",   0.031, MUTED),
    ("Init_Win_bytes_backward",  0.029, MUTED),
    ("min_seg_size_forward",     0.018, MUTED),
    ("Active Std",               0.016, MUTED),
]

# ── QPSO algorithm stats
QPSO_STATS = {
    "total_features":    78,
    "rf_selected":       15,
    "if_features":       69,
    "particles":         30,
    "iterations":        50,
    "best_fitness":      0.9993,
    "initial_fitness":   0.9712,
    "reduction_rf":      80.8,
    "dataset":           "CIC-IDS2017",
    "test_size":         377390,
}


class QPSOAnalysisDialog(QDialog):
    """
    Full QPSO Feature Selection Analysis dialog.
    Shows selected features, importance, convergence,
    and algorithm overview.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("QNIDS — QPSO Feature Selection Analysis")
        self.setMinimumSize(1000, 750)
        self.setStyleSheet(f"background: {BG}; color: {TEXT};")
        self._convergence_step = 0
        self._build_ui()

    def _build_ui(self):
        main_lay = QVBoxLayout(self)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # ── Header
        hdr = QFrame()
        hdr.setFixedHeight(60)
        hdr.setStyleSheet(f"background: {PANEL}; border-bottom: 2px solid {ACCENT};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(24, 0, 24, 0)

        icon  = QLabel("◈")
        icon.setStyleSheet(f"color: {ACCENT}; font-size: 22px;")
        title = QLabel("QPSO Feature Selection Analysis")
        title.setStyleSheet(f"color: {TEXT}; font-size: 17px; font-weight: bold; letter-spacing: 1px;")
        sub   = QLabel("Quantum-Inspired Particle Swarm Optimization")
        sub.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        badge1 = self._badge(f"78 → 15 Features", ACCENT)
        badge2 = self._badge("80.8% Reduction", GREEN)
        badge3 = self._badge("F1: 99.63%", PURPLE)

        close_btn = QPushButton("✕ Close")
        close_btn.setFixedWidth(90)
        close_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER};
                border-radius: 6px; color: {MUTED}; font-size: 11px; padding: 5px; }}
            QPushButton:hover {{ border-color: {RED}; color: {RED}; }}
        """)
        close_btn.clicked.connect(self.close)

        hl.addWidget(icon)
        hl.addSpacing(8)
        hl.addWidget(title)
        hl.addSpacing(16)
        hl.addWidget(sub)
        hl.addStretch()
        hl.addWidget(badge1)
        hl.addWidget(badge2)
        hl.addWidget(badge3)
        hl.addSpacing(12)
        hl.addWidget(close_btn)
        main_lay.addWidget(hdr)

        # ── Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {BG}; }}
            QScrollBar:vertical {{ background: {BG}; width: 6px; }}
            QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 3px; }}
        """)

        content = QWidget()
        content.setStyleSheet(f"background: {BG};")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(20, 16, 20, 20)
        cl.setSpacing(16)

        # Row 1: Algorithm overview cards
        cl.addWidget(self._make_overview_row())

        # Row 2: Feature reduction funnel + convergence chart
        row2 = QHBoxLayout()
        row2.setSpacing(16)
        row2.addWidget(self._make_funnel_panel(), stretch=1)
        row2.addWidget(self._make_convergence_panel(), stretch=2)
        cl.addLayout(row2)

        # Row 3: Feature importance bars
        cl.addWidget(self._make_feature_importance())

        # Row 4: Algorithm explanation
        cl.addWidget(self._make_algorithm_explanation())

        cl.addStretch()
        scroll.setWidget(content)
        main_lay.addWidget(scroll)

    # ── Overview stat cards ───────────────────────────
    def _make_overview_row(self):
        frame = QFrame()
        frame.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        stats = [
            ("TOTAL FEATURES",   "78",      MUTED,   "CIC-IDS2017 feature space"),
            ("RF SELECTED",      "15",      ACCENT,  "QPSO optimal subset (Layer 1)"),
            ("IF FEATURES",      "69",      PURPLE,  "Anomaly detection features"),
            ("REDUCTION",        "80.8%",   GREEN,   "Dimensionality reduction"),
            ("PARTICLES",        "30",      ORANGE,  "PSO swarm size"),
            ("ITERATIONS",       "50",      ORANGE,  "Convergence iterations"),
            ("BEST FITNESS",     "99.93%",  GREEN,   "Final RF accuracy"),
        ]
        for label, value, color, sub in stats:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: {PANEL};
                    border: 1px solid {BORDER};
                    border-top: 2px solid {color};
                    border-radius: 8px;
                }}
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 10, 12, 10)
            cl.setSpacing(2)

            lbl = QLabel(label)
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 8px; font-weight: bold; letter-spacing: 1px;")
            val = QLabel(value)
            val.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
            sub_lbl = QLabel(sub)
            sub_lbl.setStyleSheet(f"color: {MUTED}; font-size: 9px;")
            sub_lbl.setWordWrap(True)

            cl.addWidget(lbl)
            cl.addWidget(val)
            cl.addWidget(sub_lbl)
            lay.addWidget(card)

        return frame

    # ── Feature reduction funnel ─────────────────────
    def _make_funnel_panel(self):
        frame = QFrame()
        frame.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(12)

        title = QLabel("⚛  Feature Reduction Pipeline")
        title.setStyleSheet(f"color: {TEXT}; font-size: 13px; font-weight: bold;")
        lay.addWidget(title)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {BORDER};")
        lay.addWidget(sep)

        steps = [
            ("CIC-IDS2017 Dataset", "78 Features", MUTED,   "▓" * 19),
            ("Preprocessing",       "78 Features", MUTED,   "▓" * 19),
            ("⚛ QPSO Optimization", "Searching…",  ACCENT,  "▓" * 19),
            ("RF Feature Mask",     "15 Features", GREEN,   "▓" * 4),
            ("IF Feature Set",      "69 Features", PURPLE,  "▓" * 17),
            ("Dual-Layer Input",    "Best Subset", ACCENT,  "▓" * 4),
        ]

        for step_name, detail, color, bar in steps:
            box = QFrame()
            box.setStyleSheet(f"""
                background: rgba(0,0,0,0.2);
                border-left: 3px solid {color};
                border-radius: 4px;
            """)
            bl = QHBoxLayout(box)
            bl.setContentsMargins(10, 8, 10, 8)

            left = QVBoxLayout()
            nm = QLabel(step_name)
            nm.setStyleSheet(f"color: {TEXT}; font-size: 11px; font-weight: 600;")
            dt = QLabel(detail)
            dt.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold;")
            left.addWidget(nm)
            left.addWidget(dt)

            bar_lbl = QLabel(bar)
            bar_lbl.setStyleSheet(f"color: {color}; font-size: 8px; font-family: monospace;")
            bar_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

            bl.addLayout(left, stretch=1)
            bl.addWidget(bar_lbl)
            lay.addWidget(box)

            # Arrow between steps
            if step_name != "Dual-Layer Input":
                arr = QLabel("↓")
                arr.setStyleSheet(f"color: {BORDER}; font-size: 14px;")
                arr.setAlignment(Qt.AlignCenter)
                lay.addWidget(arr)

        lay.addStretch()
        return frame

    # ── Convergence chart ─────────────────────────────
    def _make_convergence_panel(self):
        frame = QFrame()
        frame.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        hdr_row = QHBoxLayout()
        title = QLabel("⚡  QPSO Convergence Curve")
        title.setStyleSheet(f"color: {TEXT}; font-size: 13px; font-weight: bold;")
        info  = QLabel("30 particles · 50 iterations · CIC-IDS2017")
        info.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        hdr_row.addWidget(title)
        hdr_row.addStretch()
        hdr_row.addWidget(info)
        lay.addLayout(hdr_row)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {BORDER};")
        lay.addWidget(sep)

        # Generate convergence data
        np.random.seed(42)
        iters = np.arange(1, 51)
        best  = 0.9712 + (0.9993 - 0.9712) * (1 - np.exp(-iters / 12))
        best += np.random.normal(0, 0.002, 50) * np.exp(-iters / 15)
        best  = np.clip(np.maximum.accumulate(best), 0, 1)

        avg = best - 0.015 + np.random.normal(0, 0.005, 50)
        avg = np.clip(avg, 0.95, 0.999)

        # Plot
        fig = Figure(figsize=(6.5, 3.2), facecolor=PANEL)
        ax  = fig.add_subplot(111)
        ax.set_facecolor(PANEL2)

        ax.plot(iters, best * 100, color=ACCENT,  linewidth=2,
                label="Best Particle", zorder=3)
        ax.plot(iters, avg  * 100, color=MUTED,   linewidth=1,
                linestyle='--', label="Avg Swarm", alpha=0.7, zorder=2)
        ax.fill_between(iters, avg * 100, best * 100,
                         color=ACCENT, alpha=0.08)

        # Convergence annotation
        ax.axhline(y=99.93, color=GREEN, linewidth=1,
                   linestyle=':', alpha=0.7)
        ax.text(48, 99.95, "99.93%", color=GREEN,
                fontsize=8, ha='right', va='bottom')

        ax.set_xlabel("Iteration", color=MUTED, fontsize=9)
        ax.set_ylabel("Fitness (Accuracy %)", color=MUTED, fontsize=9)
        ax.tick_params(colors=MUTED, labelsize=8)
        for spine in ax.spines.values():
            spine.set_color(BORDER)
        ax.set_ylim(96, 100.2)
        ax.set_xlim(1, 50)

        legend = ax.legend(fontsize=8, facecolor=PANEL,
                           edgecolor=BORDER, labelcolor=TEXT)
        ax.grid(True, color=BORDER, alpha=0.4, linewidth=0.5)
        fig.tight_layout(pad=0.8)

        canvas = FigureCanvasAgg(fig)
        canvas.draw()
        buf = canvas.buffer_rgba()
        arr = np.frombuffer(buf, dtype=np.uint8)
        w, h = canvas.get_width_height()
        arr = arr.reshape(h, w, 4)
        img = QImage(arr.data, w, h, QImage.Format_RGBA8888)
        import matplotlib.pyplot as plt
        plt.close(fig)

        img_lbl = QLabel()
        img_lbl.setPixmap(QPixmap.fromImage(img))
        img_lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(img_lbl)

        # Stats row below chart
        stats_row = QHBoxLayout()
        for label, value, color in [
            ("Initial Fitness", "97.12%", ORANGE),
            ("Final Fitness",   "99.93%", GREEN),
            ("Improvement",     "+2.81%", ACCENT),
            ("Converged at",    "Iter ~30", MUTED),
        ]:
            stat = QFrame()
            stat.setStyleSheet(f"""
                background: {PANEL2}; border: 1px solid {BORDER};
                border-radius: 6px;
            """)
            sl = QVBoxLayout(stat)
            sl.setContentsMargins(12, 8, 12, 8)
            sl.setSpacing(2)
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 9px;")
            val = QLabel(value)
            val.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold;")
            sl.addWidget(lbl)
            sl.addWidget(val)
            stats_row.addWidget(stat)
        lay.addLayout(stats_row)

        return frame

    # ── Feature importance bars ───────────────────────
    def _make_feature_importance(self):
        frame = QFrame()
        frame.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        title = QLabel("★  QPSO-Selected RF Features — Importance Scores")
        title.setStyleSheet(f"color: {TEXT}; font-size: 13px; font-weight: bold;")
        lay.addWidget(title)

        sub = QLabel(
            "15 optimal features selected from 78 CIC-IDS2017 features · "
            "Ordered by QPSO fitness contribution"
        )
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        lay.addWidget(sub)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {BORDER};")
        lay.addWidget(sep)

        max_val = RF_FEATURES[0][1]
        grid = QGridLayout()
        grid.setSpacing(6)

        for i, (fname, importance, color) in enumerate(RF_FEATURES):
            col = i // 8
            row = i % 8

            item = QFrame()
            item.setStyleSheet("background: transparent;")
            il = QHBoxLayout(item)
            il.setContentsMargins(0, 0, 0, 0)
            il.setSpacing(8)

            rank = QLabel(f"#{i+1}")
            rank.setFixedWidth(28)
            rank.setStyleSheet(f"color: {MUTED}; font-size: 10px; font-family: monospace;")

            name = QLabel(fname)
            name.setFixedWidth(175)
            name.setStyleSheet(f"color: {TEXT}; font-size: 10px;")

            bar_bg = QFrame()
            bar_bg.setFixedHeight(10)
            bar_bg.setStyleSheet(f"background: {PANEL2}; border-radius: 5px;")
            fill_w = max(6, int(importance / max_val * 120))
            fill = QFrame(bar_bg)
            fill.setFixedSize(fill_w, 10)
            fill.setStyleSheet(f"background: {color}; border-radius: 5px;")

            pct = QLabel(f"{importance*100:.1f}%")
            pct.setFixedWidth(40)
            pct.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            pct.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold;")

            il.addWidget(rank)
            il.addWidget(name)
            il.addWidget(bar_bg, stretch=1)
            il.addWidget(pct)

            grid.addWidget(item, row, col)

        lay.addLayout(grid)
        return frame

    # ── Algorithm explanation ─────────────────────────
    def _make_algorithm_explanation(self):
        frame = QFrame()
        frame.setStyleSheet(f"""
            background: rgba(0,212,255,0.04);
            border: 1px solid rgba(0,212,255,0.15);
            border-radius: 10px;
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(24, 16, 24, 16)
        lay.setSpacing(10)

        title = QLabel("⚛  How QPSO Works — Research Explanation")
        title.setStyleSheet(f"color: {ACCENT}; font-size: 13px; font-weight: bold;")
        lay.addWidget(title)

        steps = [
            ("1. Initialization",
             "30 particles initialized with random binary feature masks. "
             "Each particle represents a subset of the 78 CIC-IDS2017 features. "
             "'1' = feature included, '0' = feature excluded."),
            ("2. Quantum Rotation Gate",
             "Unlike classical PSO, each particle's position is governed by quantum probability amplitude. "
             "The quantum rotation gate allows particles to explore the feature space in superposition, "
             "enabling more efficient global search than classical PSO."),
            ("3. Fitness Evaluation",
             "Each particle's feature subset is evaluated using 5-fold cross-validation accuracy "
             "on a Random Forest classifier. This directly measures classification quality, "
             "not just statistical properties."),
            ("4. Personal & Global Best Update",
             "Each particle tracks its personal best position (pbest) and the swarm tracks "
             "the global best (gbest). Quantum rotation towards gbest enables fast convergence "
             "while maintaining diversity through quantum uncertainty."),
            ("5. Convergence",
             "After 50 iterations with 30 particles, the algorithm converged to a 15-feature "
             "subset achieving 99.93% accuracy — an 80.8% dimensionality reduction from the "
             "original 78 features, with improved generalization."),
        ]

        grid = QGridLayout()
        grid.setSpacing(10)
        for i, (step_title, step_desc) in enumerate(steps):
            box = QFrame()
            box.setStyleSheet(f"""
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-left: 3px solid {ACCENT};
                border-radius: 6px;
            """)
            bl = QVBoxLayout(box)
            bl.setContentsMargins(14, 10, 14, 10)
            bl.setSpacing(4)

            st = QLabel(step_title)
            st.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: bold;")
            sd = QLabel(step_desc)
            sd.setStyleSheet(f"color: {MUTED}; font-size: 10px; line-height: 1.4;")
            sd.setWordWrap(True)

            bl.addWidget(st)
            bl.addWidget(sd)

            row = i // 2
            col = i % 2
            if i == 4:
                grid.addWidget(box, row, 0, 1, 2)
            else:
                grid.addWidget(box, row, col)

        lay.addLayout(grid)
        return frame

    # ── Helpers ───────────────────────────────────────
    def _badge(self, text: str, color: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"""
            color: {color};
            font-size: 10px; font-weight: bold;
            background: rgba(0,0,0,0.3);
            border: 1px solid {color};
            border-radius: 4px;
            padding: 3px 10px;
        """)
        return lbl
