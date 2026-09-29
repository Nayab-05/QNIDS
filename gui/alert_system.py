import winsound
import threading
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QTextEdit, QApplication, QProgressBar
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont

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


# ══════════════════════════════════════════════════════
# SOUNDS
# ══════════════════════════════════════════════════════
def play_attack_sound():
    """Two-tone beep for known attacks."""
    def _play():
        try:
            winsound.Beep(1000, 200)
            winsound.Beep(800,  200)
        except Exception as e:
            print(f"[alert] Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


def play_unknown_sound():
    """Triple pulse beep for unknown/suspicious threats."""
    def _play():
        try:
            for _ in range(3):
                winsound.Beep(1500, 150)
                winsound.Beep(500,  150)
        except Exception as e:
            print(f"[alert] Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


# ══════════════════════════════════════════════════════
# THREAD-SAFE AI SIGNAL
# ══════════════════════════════════════════════════════
class _AISignal(QObject):
    result_ready = pyqtSignal(str)


# ══════════════════════════════════════════════════════
# DUAL-LAYER INFO ROW WIDGET
# ══════════════════════════════════════════════════════
class _DualLayerPanel(QFrame):
    """
    Compact panel showing RF Confidence + IF Score
    with visual indicators.
    """
    def __init__(self, rf_confidence: int,
                 if_score: float, decision: str,
                 parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(8)

        # ── Decision badge (top)
        if decision == "KNOWN_ATTACK":
            d_color = RED
            d_text  = "▲  KNOWN ATTACK DETECTED"
        elif decision == "SUSPICIOUS":
            d_color = ORANGE
            d_text  = "◆  SUSPICIOUS / ZERO-DAY RISK"
        else:
            d_color = GREEN
            d_text  = "●  NORMAL TRAFFIC"

        badge = QLabel(d_text)
        badge.setStyleSheet(f"""
            color: {d_color};
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 1px;
            padding: 4px 0;
        """)
        badge.setAlignment(Qt.AlignCenter)
        lay.addWidget(badge)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {BORDER};")
        lay.addWidget(sep)

        # ── Layer 1 — RF Confidence
        l1_lbl = QLabel("Layer 1 — Random Forest Confidence")
        l1_lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold;"
        )
        lay.addWidget(l1_lbl)

        rf_row = QHBoxLayout()
        rf_bar = QProgressBar()
        rf_bar.setFixedHeight(10)
        rf_bar.setRange(0, 100)
        rf_bar.setValue(rf_confidence)
        rf_bar.setTextVisible(False)
        bar_color = (GREEN  if rf_confidence >= 85
                     else ORANGE if rf_confidence >= 70
                     else RED)
        rf_bar.setStyleSheet(f"""
            QProgressBar {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 5px;
            }}
            QProgressBar::chunk {{
                background: {bar_color};
                border-radius: 5px;
            }}
        """)
        rf_val = QLabel(f"{rf_confidence}%")
        rf_val.setFixedWidth(38)
        rf_val.setStyleSheet(
            f"color: {bar_color}; font-size: 12px; font-weight: bold;"
        )
        rf_val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        rf_row.addWidget(rf_bar, stretch=1)
        rf_row.addSpacing(8)
        rf_row.addWidget(rf_val)
        lay.addLayout(rf_row)

        # ── Layer 2 — IF Score
        l2_lbl = QLabel("Layer 2 — Isolation Forest Anomaly Score")
        l2_lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold;"
        )
        lay.addWidget(l2_lbl)

        if_row = QHBoxLayout()

        if if_score < -0.20:
            if_color = RED
            if_desc  = "High Anomaly — Zero-Day Risk"
        elif if_score < 0:
            if_color = ORANGE
            if_desc  = "Borderline — Monitor Closely"
        else:
            if_color = GREEN
            if_desc  = "Normal Range"

        if_score_lbl = QLabel(f"{if_score:+.4f}")
        if_score_lbl.setStyleSheet(
            f"color: {if_color}; font-size: 14px; "
            f"font-weight: bold; font-family: monospace;"
        )
        if_desc_lbl = QLabel(if_desc)
        if_desc_lbl.setStyleSheet(
            f"color: {if_color}; font-size: 10px;"
        )

        if_row.addWidget(if_score_lbl)
        if_row.addSpacing(10)
        if_row.addWidget(if_desc_lbl)
        if_row.addStretch()
        lay.addLayout(if_row)


# ══════════════════════════════════════════════════════
# MAIN THREAT POPUP
# ══════════════════════════════════════════════════════
class UnknownThreatPopup(QDialog):
    """
    Alert popup for SUSPICIOUS and KNOWN_ATTACK verdicts.
    Shows dual-layer scores + AI threat analysis.
    """

    def __init__(self, parent=None,
                 attack_info="", ip="",
                 ts="", confidence=0,
                 protocol="TCP",
                 if_score=0.0,
                 decision="SUSPICIOUS"):
        super().__init__(parent)

        self.attack_info = attack_info
        self.ip          = ip
        self.ts          = ts
        self.confidence  = confidence
        self.protocol    = protocol
        self.if_score    = if_score
        self.decision    = decision
        self._ai_sig     = _AISignal()
        self._ai_sig.result_ready.connect(self._show_ai_result)

        # Title + border color based on verdict
        if decision == "KNOWN_ATTACK":
            border_color = RED
            title_text   = "⚠  Known Attack Detected!"
        else:
            border_color = ORANGE
            title_text   = "⚠  Unknown Threat Detected!"

        self.setWindowTitle(title_text)
        self.setFixedSize(500, 520)
        self.setModal(False)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG};
                border: 2px solid {border_color};
                border-radius: 12px;
            }}
        """)
        self._build_ui(border_color, title_text)

    def _build_ui(self, border_color, title_text):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header
        header = QFrame()
        header.setFixedHeight(52)
        header.setStyleSheet(f"""
            background: rgba(239,68,68,0.12)
                if '{border_color}' == '{RED}'
                else rgba(245,158,11,0.12);
            border-bottom: 1px solid {border_color};
            border-radius: 10px 10px 0 0;
        """)
        # Simplified header style
        header.setStyleSheet(f"""
            background: rgba(30,48,72,0.8);
            border-bottom: 1px solid {border_color};
            border-radius: 10px 10px 0 0;
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("⚠")
        icon.setStyleSheet(f"color: {border_color}; font-size: 22px;")

        title = QLabel(title_text.replace("⚠  ", "").upper())
        title.setStyleSheet(f"""
            color: {border_color};
            font-size: 13px;
            font-weight: bold;
            letter-spacing: 1px;
        """)

        hl.addWidget(icon)
        hl.addSpacing(8)
        hl.addWidget(title)
        hl.addStretch()
        layout.addWidget(header)

        # ── Basic Info
        info_frame = QFrame()
        info_frame.setStyleSheet(f"background: {PANEL}; padding: 2px;")
        il = QVBoxLayout(info_frame)
        il.setContentsMargins(18, 10, 18, 10)
        il.setSpacing(5)

        for label, value, color in [
            ("Time:",      self.ts,          TEXT),
            ("Source IP:", self.ip,          ACCENT),
            ("Pattern:",   self.attack_info, border_color),
            ("Protocol:",  self.protocol,    TEXT),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(85)
            lbl.setStyleSheet(
                f"color: {MUTED}; font-size: 11px; font-weight: bold;"
            )
            val = QLabel(str(value))
            val.setStyleSheet(f"color: {color}; font-size: 11px;")
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            il.addLayout(row)

        layout.addWidget(info_frame)

        # ── Dual-Layer Panel
        dl_wrapper = QFrame()
        dl_wrapper.setStyleSheet(f"background: {BG}; padding: 0;")
        dw = QVBoxLayout(dl_wrapper)
        dw.setContentsMargins(14, 10, 14, 6)

        dl_panel = _DualLayerPanel(
            rf_confidence=self.confidence,
            if_score=self.if_score,
            decision=self.decision
        )
        dw.addWidget(dl_panel)
        layout.addWidget(dl_wrapper)

        # ── AI Analysis
        ai_frame = QFrame()
        ai_frame.setStyleSheet(f"""
            background: rgba(0,212,255,0.04);
            border-top: 1px solid {BORDER};
        """)
        al = QVBoxLayout(ai_frame)
        al.setContentsMargins(16, 8, 16, 8)
        al.setSpacing(6)

        ai_hdr = QHBoxLayout()
        ai_lbl = QLabel("🤖 AI THREAT ANALYSIS")
        ai_lbl.setStyleSheet(
            f"color: {ACCENT}; font-size: 11px; "
            f"font-weight: bold; letter-spacing: 1px;"
        )
        self.analyze_btn = QPushButton("⚡ Analyze")
        self.analyze_btn.setFixedWidth(95)
        self.analyze_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(0,212,255,0.15);
                border: 1px solid {ACCENT};
                border-radius: 5px; color: {ACCENT};
                font-size: 10px; font-weight: bold; padding: 4px 8px;
            }}
            QPushButton:hover {{ background: rgba(0,212,255,0.25); }}
            QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; background: transparent; }}
        """)
        self.analyze_btn.clicked.connect(self._start_analysis)

        ai_hdr.addWidget(ai_lbl)
        ai_hdr.addStretch()
        ai_hdr.addWidget(self.analyze_btn)
        al.addLayout(ai_hdr)

        self.ai_result = QTextEdit()
        self.ai_result.setFixedHeight(90)
        self.ai_result.setReadOnly(True)
        self.ai_result.setPlaceholderText(
            "Click '⚡ Analyze' for AI threat analysis..."
        )
        self.ai_result.setStyleSheet(f"""
            QTextEdit {{
                background: {PANEL2}; border: 1px solid {BORDER};
                border-radius: 6px; color: {TEXT};
                font-size: 10px; padding: 6px;
            }}
        """)
        al.addWidget(self.ai_result)
        layout.addWidget(ai_frame)

        # ── Footer
        btn_frame = QFrame()
        btn_frame.setFixedHeight(48)
        btn_frame.setStyleSheet(f"""
            background: {BG}; border-top: 1px solid {BORDER};
            border-radius: 0 0 10px 10px;
        """)
        bl = QHBoxLayout(btn_frame)
        bl.setContentsMargins(16, 0, 16, 0)
        bl.setSpacing(8)

        self._countdown = 30
        self.timer_lbl  = QLabel(f"Auto-close in {self._countdown}s")
        self.timer_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        copy_btn = QPushButton("📋 Copy")
        copy_btn.setFixedWidth(75)
        copy_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER};
                border-radius: 5px; color: {MUTED}; font-size: 11px; padding: 5px; }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        copy_btn.clicked.connect(self._copy_details)

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setFixedWidth(80)
        dismiss_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER};
                border-radius: 5px; color: {MUTED}; font-size: 11px; padding: 5px; }}
            QPushButton:hover {{ border-color: {RED}; color: {RED}; }}
        """)
        dismiss_btn.clicked.connect(self.close)

        bl.addWidget(self.timer_lbl)
        bl.addStretch()
        bl.addWidget(copy_btn)
        bl.addWidget(dismiss_btn)
        layout.addWidget(btn_frame)

        # Auto-close timer
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._tick)
        self._auto_timer.start(1000)

    # ── AI Analysis
    def _start_analysis(self):
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setText("Analyzing...")
        self.ai_result.setPlainText(
            "🤖 Analyzing threat pattern...\nPlease wait..."
        )
        try:
            from ai_analyzer import AIAnalyzer
            analyzer = AIAnalyzer()
            analyzer.analyze(
                attack_info=self.attack_info,
                ip=self.ip,
                confidence=self.confidence,
                protocol=self.protocol,
                callback=self._on_ai_result
            )
        except Exception as e:
            self.ai_result.setPlainText(f"Error: {str(e)}")
            self.analyze_btn.setEnabled(True)
            self.analyze_btn.setText("⚡ Analyze")

    def _on_ai_result(self, result):
        self._ai_sig.result_ready.emit(result)

    def _show_ai_result(self, result):
        self.ai_result.setPlainText(result)
        self.analyze_btn.setEnabled(True)
        self.analyze_btn.setText("🔄 Re-analyze")

    def _copy_details(self):
        details = (
            f"QNIDS Threat Report\n"
            f"{'=' * 40}\n"
            f"Time:        {self.ts}\n"
            f"Source IP:   {self.ip}\n"
            f"Pattern:     {self.attack_info}\n"
            f"Decision:    {self.decision}\n"
            f"RF Conf:     {self.confidence}%\n"
            f"IF Score:    {self.if_score:+.4f}\n\n"
            f"AI Analysis:\n"
            f"{self.ai_result.toPlainText()}"
        )
        QApplication.clipboard().setText(details)
        sender = self.sender()
        if sender:
            sender.setText("✓ Copied!")
            QTimer.singleShot(1500, lambda: sender.setText("📋 Copy"))

    def _tick(self):
        self._countdown -= 1
        self.timer_lbl.setText(f"Auto-close in {self._countdown}s")
        if self._countdown <= 0:
            self._auto_timer.stop()
            self.close()