import numpy as np
import matplotlib
matplotlib.use('Agg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.patches import Circle

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout
from PyQt5.QtCore    import Qt, QTimer
from PyQt5.QtGui     import QPixmap, QImage, QFont

# ── Theme
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"

# ── CIC-IDS2017 categories + colors
CATEGORIES = {
    "Normal":    "#10b981",   # green
    "DoS":       "#ef4444",   # red
    "DDoS":      "#f97316",   # orange
    "PortScan":  "#8b5cf6",   # purple
    "BruteForce":"#3b82f6",   # blue
    "WebAttack": "#eab308",   # yellow
    "Suspicious":"#f59e0b",   # amber
}


class AttackPieChart(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)

        # Count store
        self.counts = {k: 0 for k in CATEGORIES}
        self._update_counter = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Chart image label
        self.chart_label = QLabel()
        self.chart_label.setStyleSheet(f"background: {PANEL};")
        self.chart_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.chart_label, stretch=1)

        # Legend area below chart
        self.legend_frame = QFrame()
        self.legend_frame.setStyleSheet(
            f"background: {PANEL}; border-top: 1px solid {PANEL2};"
        )
        self.legend_layout = QVBoxLayout(self.legend_frame)
        self.legend_layout.setContentsMargins(10, 6, 10, 8)
        self.legend_layout.setSpacing(3)
        layout.addWidget(self.legend_frame)

        self._draw_chart()

        # Redraw every 5 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._draw_chart)
        self._timer.start(5000)

    # ── Draw donut chart ──────────────────────────────────────────
    def _draw_chart(self):
        try:
            active   = {k: v for k, v in self.counts.items() if v > 0}
            total    = sum(active.values())
            has_data = bool(active)

            # Figure — taller for more visual impact
            fig = Figure(figsize=(2.6, 2.6), facecolor=PANEL)
            ax  = fig.add_axes([0.05, 0.05, 0.9, 0.9])
            ax.set_facecolor(PANEL)

            if not has_data:
                # Empty state — decorative ring
                ax.pie(
                    [1],
                    colors=["#1e3048"],
                    startangle=90,
                    wedgeprops={"linewidth": 0, "width": 0.45}
                )
                ax.text(
                    0, 0, "Waiting\nfor data",
                    ha="center", va="center",
                    color=MUTED, fontsize=8,
                    fontfamily="monospace"
                )
            else:
                labels  = list(active.keys())
                sizes   = list(active.values())
                colors  = [CATEGORIES[k] for k in labels]

                wedges, _ = ax.pie(
                    sizes,
                    colors=colors,
                    startangle=90,
                    wedgeprops={
                        "linewidth":  2.0,
                        "edgecolor":  PANEL,
                        "width":      0.48,   # donut hole
                    },
                    counterclock=False,
                )

                # Subtle glow — slightly wider transparent ring behind
                ax.pie(
                    sizes,
                    colors=[c + "22" for c in colors],
                    startangle=90,
                    wedgeprops={
                        "linewidth": 0,
                        "width":     0.56,
                        "alpha":     0.4,
                    },
                    counterclock=False,
                )

                # Center text — total count
                ax.text(
                    0, 0.06, str(total),
                    ha="center", va="center",
                    color=TEXT, fontsize=15,
                    fontweight="bold"
                )
                ax.text(
                    0, -0.18, "TOTAL",
                    ha="center", va="center",
                    color=MUTED, fontsize=7,
                    fontfamily="monospace"
                )

            ax.axis("equal")

            # Render to QPixmap
            canvas = FigureCanvasAgg(fig)
            canvas.draw()
            buf = canvas.buffer_rgba()
            arr = np.frombuffer(buf, dtype=np.uint8)
            w, h = canvas.get_width_height()
            arr = arr.reshape(h, w, 4)
            img = QImage(arr.data, w, h, QImage.Format_RGBA8888)
            self.chart_label.setPixmap(
                QPixmap.fromImage(img).scaled(
                    self.chart_label.width() or 220,
                    220,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
            )
            import matplotlib.pyplot as plt
            plt.close(fig)

            # Rebuild legend
            self._rebuild_legend(active, total)

        except Exception as e:
            print(f"[chart_widget] Draw error: {e}")

    # ── Legend rows ───────────────────────────────────────────────
    def _rebuild_legend(self, active: dict, total: int):
        # Clear old widgets
        while self.legend_layout.count():
            child = self.legend_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        for label, count in active.items():
            color = CATEGORIES.get(label, MUTED)
            pct   = int(count / total * 100) if total else 0

            row = QFrame()
            row.setStyleSheet("background: transparent;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(6)

            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; font-size: 10px;")
            dot.setFixedWidth(14)

            name_lbl = QLabel(label)
            name_lbl.setStyleSheet(f"color: {TEXT}; font-size: 11px;")

            pct_lbl = QLabel(f"{pct}%")
            pct_lbl.setStyleSheet(
                f"color: {color}; font-size: 11px; font-weight: bold;"
            )
            pct_lbl.setAlignment(Qt.AlignRight)

            count_lbl = QLabel(f"({count})")
            count_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
            count_lbl.setAlignment(Qt.AlignRight)

            rl.addWidget(dot)
            rl.addWidget(name_lbl, stretch=1)
            rl.addWidget(pct_lbl)
            rl.addWidget(count_lbl)
            self.legend_layout.addWidget(row)

    # ── Count updater ─────────────────────────────────────────────
    def update_counts(self, attack_type: str, verdict: str):
        v  = verdict.lower()
        at = attack_type.lower()

        if "normal" in v:
            self.counts["Normal"] += 1
        elif "unknown" in v or "suspicious" in v:
            self.counts["Suspicious"] += 1
        elif "ddos" in at:
            self.counts["DDoS"] += 1
        elif "dos" in at:
            self.counts["DoS"] += 1
        elif "portscan" in at or "port scan" in at or "scan" in at:
            self.counts["PortScan"] += 1
        elif "brute" in at:
            self.counts["BruteForce"] += 1
        elif "web" in at or "sql" in at or "xss" in at:
            self.counts["WebAttack"] += 1
        else:
            if "attack" in v:
                self.counts["DoS"] += 1
            else:
                self.counts["Normal"] += 1

        self._update_counter += 1
        if self._update_counter % 10 == 0:
            self._draw_chart()

    def reset(self):
        self.counts = {k: 0 for k in CATEGORIES}
        self._update_counter = 0
        self._draw_chart()